package safety

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"time"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
)

// maxTracePackets bounds the hop-limited probes one trace or MTR lease may
// send (sufficient for 30 hops × 10 cycles plus discovery).
const maxTracePackets = 320

// Linux cmsg / sock_extended_err wire constants (64-bit little-endian ABI on
// amd64 and arm64). Kept in platform-independent code so unit tests exercise
// exact kernel control-message parsing on every development OS.
const (
	linuxSOL_IP              = 0
	linuxSOL_IPV6            = 41
	linuxIP_RECVERR          = 11
	linuxIPV6_RECVERR        = 25
	linuxAF_INET             = 2
	linuxAF_INET6            = 10
	linuxSO_EE_ORIGIN_ICMP   = 2
	linuxSO_EE_ORIGIN_ICMP6  = 3
	linuxICMP_DEST_UNREACH   = 3
	linuxICMP_TIME_EXCEEDED  = 11
	linuxICMP6_DEST_UNREACH  = 1
	linuxICMP6_TIME_EXCEEDED = 3
)

// rawHopSample is the unredacted result of one OS-level trace probe before
// Guard applies operator privacy redaction.
type rawHopSample struct {
	addr     netip.Addr
	reached  bool
	rtt      time.Duration
	protocol string
}

// TraceHop sends one TTL-limited probe toward the lease's validated target
// address under the shared 50 pps ICMP token bucket and the lease's trace
// packet cap, redacting any private, CGNAT or own-network responder IP.
func (l *guardLease) TraceHop(ctx context.Context, proto string, ttl int, seq int, timeout time.Duration) (module.HopSample, error) {
	if l.transport != module.TransportICMP {
		return module.HopSample{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "lease is not an ICMP/trace lease")
	}
	if l.isClosed() {
		return module.HopSample{}, errLeaseClosed
	}
	normProto := strings.ToLower(strings.TrimSpace(proto))
	if normProto == "" {
		normProto = "udp"
	}
	if normProto != "udp" && normProto != "icmp" {
		return module.HopSample{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS, "trace protocol %q must be udp or icmp", proto)
	}
	if ttl < 1 || ttl > 64 {
		return module.HopSample{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS, "trace TTL %d is outside 1..64", ttl)
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	if l.traces != nil && !l.traces.take() {
		return module.HopSample{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "trace packet cap %d reached", l.traces.max)
	}

	if err := l.g.icmp.take(ctx); err != nil {
		if l.traces != nil {
			l.traces.refund()
		}
		return module.HopSample{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED, "no send slot under the ICMP rate cap: %v", err)
	}
	if err := l.g.recheckDial(l.addr); err != nil {
		if l.traces != nil {
			l.traces.refund()
		}
		return module.HopSample{}, err
	}

	fn := l.g.traceHop
	if fn == nil {
		fn = defaultTraceHop
	}
	raw, err := fn(ctx, l.g, l.addr, normProto, ttl, seq, timeout)
	effProto := raw.protocol
	if effProto == "" {
		effProto = normProto
	}
	if err != nil {
		var te interface{ Timeout() bool }
		if !(errors.As(err, &te) && te.Timeout()) {
			if l.traces != nil {
				l.traces.refund()
			}
		}
		return module.HopSample{Protocol: effProto}, err
	}

	dst := l.addr.Unmap()
	hopAddr := raw.addr.Unmap()
	reached := raw.reached || (hopAddr.IsValid() && hopAddr == dst)
	if l.g.shouldRedactHop(hopAddr, dst) {
		return module.HopSample{
			Addr:     netip.Addr{},
			Redacted: true,
			Reached:  reached,
			RTT:      raw.rtt,
			Protocol: effProto,
		}, nil
	}
	return module.HopSample{
		Addr:     hopAddr,
		Redacted: false,
		Reached:  reached,
		RTT:      raw.rtt,
		Protocol: effProto,
	}, nil
}

// shouldRedactHop enforces residential operator privacy on intermediate router
// hops: any responder other than dstAddr that falls in Denied (RFC 1918,
// loopback, link-local, CGNAT 100.64.0.0/10, multicast, documentation) OR in
// the node's own network (/24 IPv4, /48 IPv6, interface prefixes) is stripped
// while preserving its round-trip timing.
func (g *Guard) shouldRedactHop(hopAddr, dstAddr netip.Addr) bool {
	hopAddr = hopAddr.Unmap()
	dstAddr = dstAddr.Unmap()
	if !hopAddr.IsValid() || hopAddr == dstAddr {
		return false
	}
	if denied, _ := Denied(hopAddr); denied {
		return true
	}
	g.mu.Lock()
	p := g.policyLocked()
	g.mu.Unlock()
	for _, n := range p.ownNet {
		if n.Contains(hopAddr) {
			return true
		}
	}
	for _, d := range p.addDeny {
		if d.Contains(hopAddr) {
			return true
		}
	}
	if v4, ok := nat64Destination(hopAddr, p.local.nat64); ok {
		if denied, _ := Denied(v4); denied {
			return true
		}
		for _, n := range p.ownNet {
			if n.Contains(v4) {
				return true
			}
		}
	}
	return false
}

// parseErrQueueControl parses 64-bit Linux MSG_ERRQUEUE control messages
// (IP_RECVERR / IPV6_RECVERR) carrying sock_extended_err + SO_EE_OFFENDER.
func parseErrQueueControl(oob []byte, dst netip.Addr) (offender netip.Addr, reached bool, ok bool) {
	dst = dst.Unmap()
	for len(oob) >= 16 {
		cmsgLen := binary.LittleEndian.Uint64(oob[0:8])
		level := int32(binary.LittleEndian.Uint32(oob[8:12]))
		typ := int32(binary.LittleEndian.Uint32(oob[12:16]))
		if cmsgLen < 16 || cmsgLen > uint64(len(oob)) {
			break
		}
		data := oob[16:cmsgLen]
		step := (int(cmsgLen) + 7) &^ 7
		if step <= 0 || step > len(oob) {
			oob = nil
		} else {
			oob = oob[step:]
		}

		isV4Err := level == linuxSOL_IP && typ == linuxIP_RECVERR
		isV6Err := level == linuxSOL_IPV6 && typ == linuxIPV6_RECVERR
		if !isV4Err && !isV6Err {
			continue
		}
		// struct sock_extended_err is 16 bytes, followed by SO_EE_OFFENDER sockaddr.
		if len(data) < 16+8 {
			continue
		}
		eeOrigin := data[4]
		eeType := data[5]
		sa := data[16:]
		addr, aok := parseLinuxSockaddr(sa)
		if !aok {
			continue
		}
		switch eeOrigin {
		case linuxSO_EE_ORIGIN_ICMP:
			if eeType == linuxICMP_TIME_EXCEEDED || eeType == linuxICMP_DEST_UNREACH {
				return addr, addr == dst, true
			}
		case linuxSO_EE_ORIGIN_ICMP6:
			if eeType == linuxICMP6_TIME_EXCEEDED || eeType == linuxICMP6_DEST_UNREACH {
				return addr, addr == dst, true
			}
		}
	}
	return netip.Addr{}, false, false
}

func parseLinuxSockaddr(sa []byte) (netip.Addr, bool) {
	if len(sa) < 2 {
		return netip.Addr{}, false
	}
	fam := binary.LittleEndian.Uint16(sa[0:2])
	switch fam {
	case linuxAF_INET:
		if len(sa) < 8 {
			return netip.Addr{}, false
		}
		var b [4]byte
		copy(b[:], sa[4:8])
		a := netip.AddrFrom4(b)
		if !a.IsValid() || a.IsUnspecified() {
			return netip.Addr{}, false
		}
		return a, true
	case linuxAF_INET6:
		if len(sa) < 24 {
			return netip.Addr{}, false
		}
		var b [16]byte
		copy(b[:], sa[8:24])
		a := netip.AddrFrom16(b).Unmap()
		if !a.IsValid() || a.IsUnspecified() {
			return netip.Addr{}, false
		}
		return a, true
	default:
		return netip.Addr{}, false
	}
}
