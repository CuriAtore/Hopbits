//go:build linux

package safety

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	traceBasePort = 33434
	tracePortSpan = 60
	tracePollStep = 25 * time.Millisecond
)

var errICMPFallback = errors.New("unprivileged ICMP socket unavailable")

func defaultTraceHop(ctx context.Context, g *Guard, dst netip.Addr, proto string, ttl, seq int, timeout time.Duration) (rawHopSample, error) {
	dst = dst.Unmap()
	if proto == "icmp" {
		s, err := sendTraceICMP(ctx, g, dst, ttl, seq, timeout)
		if !errors.Is(err, errICMPFallback) {
			return s, err
		}
	}
	return sendTraceUDP(ctx, g, dst, ttl, seq, timeout)
}

func sendTraceUDP(ctx context.Context, g *Guard, dst netip.Addr, ttl, seq int, timeout time.Duration) (rawHopSample, error) {
	isV6 := dst.Is6() && !dst.Is4()
	domain := syscall.AF_INET
	if isV6 {
		domain = syscall.AF_INET6
	}
	fd, err := syscall.Socket(domain, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.IPPROTO_UDP)
	if err != nil {
		return rawHopSample{protocol: "udp"}, fmt.Errorf("safety: open UDP trace socket: %w", os.NewSyscallError("socket", err))
	}
	if err := configureTraceSocket(fd, isV6, ttl); err != nil {
		_ = syscall.Close(fd)
		return rawHopSample{protocol: "udp"}, err
	}

	port := traceBasePort + ((seq%tracePortSpan + tracePortSpan) % tracePortSpan)
	var bindSA, remoteSA syscall.Sockaddr
	if isV6 {
		bindSA = &syscall.SockaddrInet6{}
		remoteSA = &syscall.SockaddrInet6{Port: port, Addr: dst.As16()}
	} else {
		bindSA = &syscall.SockaddrInet4{}
		remoteSA = &syscall.SockaddrInet4{Port: port, Addr: dst.As4()}
	}
	if err := syscall.Bind(fd, bindSA); err != nil {
		_ = syscall.Close(fd)
		return rawHopSample{protocol: "udp"}, fmt.Errorf("safety: bind UDP trace socket: %w", os.NewSyscallError("bind", err))
	}
	if err := syscall.Connect(fd, remoteSA); err != nil {
		_ = syscall.Close(fd)
		return rawHopSample{protocol: "udp"}, fmt.Errorf("safety: connect UDP trace socket: %w", os.NewSyscallError("connect", err))
	}

	f := os.NewFile(uintptr(fd), "hopbits-trace-udp")
	if f == nil {
		_ = syscall.Close(fd)
		return rawHopSample{protocol: "udp"}, errors.New("safety: wrap UDP trace socket failed")
	}
	defer f.Close()

	raw, err := f.SyscallConn()
	if err != nil {
		return rawHopSample{protocol: "udp"}, fmt.Errorf("safety: trace rawconn: %w", err)
	}

	nonce := make([]byte, echoNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return rawHopSample{protocol: "udp"}, fmt.Errorf("safety: draw trace nonce: %w", err)
	}
	payload := echoPayload(nonce)

	var sendErr error
	var start time.Time
	if cerr := raw.Control(func(sfd uintptr) {
		start = time.Now()
		_, sendErr = syscall.Write(int(sfd), payload)
	}); cerr != nil {
		return rawHopSample{protocol: "udp"}, cerr
	}
	if sendErr != nil {
		return rawHopSample{protocol: "udp"}, fmt.Errorf("safety: send UDP trace probe: %w", os.NewSyscallError("write", sendErr))
	}
	g.addTraffic(int64(len(payload)))

	return waitTraceSocket(ctx, g, f, raw, dst, "udp", 0, 0, nil, start, timeout)
}

func sendTraceICMP(ctx context.Context, g *Guard, dst netip.Addr, ttl, seq int, timeout time.Duration) (rawHopSample, error) {
	isV6 := dst.Is6() && !dst.Is4()
	domain := syscall.AF_INET
	icmpProto := protoICMP4
	var echoType icmp.Type = ipv4.ICMPTypeEcho
	if isV6 {
		domain = syscall.AF_INET6
		icmpProto = protoICMP6
		echoType = ipv6.ICMPTypeEchoRequest
	}
	fd, err := syscall.Socket(domain, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, icmpProto)
	if err != nil {
		return rawHopSample{protocol: "udp"}, errICMPFallback
	}
	if err := configureTraceSocket(fd, isV6, ttl); err != nil {
		_ = syscall.Close(fd)
		return rawHopSample{protocol: "udp"}, errICMPFallback
	}

	var bindSA, remoteSA syscall.Sockaddr
	if isV6 {
		bindSA = &syscall.SockaddrInet6{}
		remoteSA = &syscall.SockaddrInet6{Addr: dst.As16()}
	} else {
		bindSA = &syscall.SockaddrInet4{}
		remoteSA = &syscall.SockaddrInet4{Addr: dst.As4()}
	}
	if err := syscall.Bind(fd, bindSA); err != nil {
		_ = syscall.Close(fd)
		return rawHopSample{protocol: "udp"}, errICMPFallback
	}

	f := os.NewFile(uintptr(fd), "hopbits-trace-icmp")
	if f == nil {
		_ = syscall.Close(fd)
		return rawHopSample{protocol: "udp"}, errICMPFallback
	}
	defer f.Close()

	raw, err := f.SyscallConn()
	if err != nil {
		return rawHopSample{protocol: "udp"}, errICMPFallback
	}

	nonce := make([]byte, echoNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return rawHopSample{protocol: "icmp"}, fmt.Errorf("safety: draw ICMP trace nonce: %w", err)
	}
	payload := echoPayload(nonce)
	wantSeq := seq & 0xffff
	msg := icmp.Message{
		Type: echoType,
		Code: 0,
		Body: &icmp.Echo{ID: 0, Seq: wantSeq, Data: payload},
	}
	pkt, err := msg.Marshal(nil)
	if err != nil {
		return rawHopSample{protocol: "icmp"}, fmt.Errorf("safety: marshal ICMP trace probe: %w", err)
	}

	var sendErr error
	var start time.Time
	if cerr := raw.Control(func(sfd uintptr) {
		start = time.Now()
		sendErr = syscall.Sendto(int(sfd), pkt, 0, remoteSA)
	}); cerr != nil {
		return rawHopSample{protocol: "icmp"}, cerr
	}
	if sendErr != nil {
		if errors.Is(sendErr, syscall.EACCES) || errors.Is(sendErr, syscall.EPERM) || errors.Is(sendErr, syscall.EAFNOSUPPORT) || errors.Is(sendErr, syscall.EPROTONOSUPPORT) {
			return rawHopSample{protocol: "udp"}, errICMPFallback
		}
		return rawHopSample{protocol: "icmp"}, fmt.Errorf("safety: send ICMP trace probe: %w", os.NewSyscallError("sendto", sendErr))
	}
	g.addTraffic(int64(len(pkt)))

	return waitTraceSocket(ctx, g, f, raw, dst, "icmp", icmpProto, wantSeq, nonce, start, timeout)
}

func configureTraceSocket(fd int, isV6 bool, ttl int) error {
	if isV6 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_IPV6, syscall.IPV6_UNICAST_HOPS, ttl); err != nil {
			return fmt.Errorf("safety: set IPV6_UNICAST_HOPS: %w", os.NewSyscallError("setsockopt", err))
		}
		if err := syscall.SetsockoptInt(fd, syscall.SOL_IPV6, linuxIPV6_RECVERR, 1); err != nil {
			return fmt.Errorf("safety: set IPV6_RECVERR: %w", os.NewSyscallError("setsockopt", err))
		}
		return nil
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TTL, ttl); err != nil {
		return fmt.Errorf("safety: set IP_TTL: %w", os.NewSyscallError("setsockopt", err))
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_RECVERR, 1); err != nil {
		return fmt.Errorf("safety: set IP_RECVERR: %w", os.NewSyscallError("setsockopt", err))
	}
	return nil
}

func waitTraceSocket(
	ctx context.Context,
	g *Guard,
	f *os.File,
	raw syscall.RawConn,
	dst netip.Addr,
	proto string,
	icmpProto int,
	wantSeq int,
	nonce []byte,
	start time.Time,
	timeout time.Duration,
) (rawHopSample, error) {
	deadline := start.Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	buf := make([]byte, 1500)
	oob := make([]byte, 512)

	for {
		if err := ctx.Err(); err != nil {
			return rawHopSample{protocol: proto}, &lostEcho{cause: err}
		}
		now := time.Now()
		if !now.Before(deadline) {
			return rawHopSample{protocol: proto}, ErrEchoTimeout
		}
		sliceEnd := now.Add(tracePollStep)
		if deadline.Before(sliceEnd) {
			sliceEnd = deadline
		}
		_ = f.SetReadDeadline(sliceEnd)

		var (
			got      bool
			offender netip.Addr
			reached  bool
			at       time.Time
		)
		_ = raw.Read(func(fd uintptr) bool {
			// 1. Drain MSG_ERRQUEUE for ICMP Time Exceeded / Dest Unreachable.
			for {
				n, oobn, _, _, rerr := syscall.Recvmsg(int(fd), buf, oob, syscall.MSG_ERRQUEUE|syscall.MSG_DONTWAIT)
				if rerr != nil {
					break
				}
				at = time.Now()
				if n+oobn > 0 {
					g.addTraffic(int64(n + oobn))
				}
				if addr, rch, ok := parseErrQueueControl(oob[:oobn], dst); ok {
					offender = addr
					reached = rch
					got = true
					return true
				}
			}
			// 2. Check normal receive queue (ICMP Echo Reply or direct UDP reply).
			for {
				n, from, rerr := syscall.Recvfrom(int(fd), buf, syscall.MSG_DONTWAIT)
				if rerr != nil {
					break
				}
				at = time.Now()
				if n > 0 {
					g.addTraffic(int64(n))
				}
				if proto == "icmp" {
					m, perr := icmp.ParseMessage(icmpProto, buf[:n])
					if perr != nil || (m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply) {
						continue
					}
					echo, ok := m.Body.(*icmp.Echo)
					if !ok || echo.Seq != wantSeq || len(echo.Data) < echoNonceOffset+echoNonceLen {
						continue
					}
					if !bytes.Equal(echo.Data[echoNonceOffset:echoNonceOffset+echoNonceLen], nonce) {
						continue
					}
					offender = dst
					reached = true
					got = true
					return true
				}
				if saAddr, ok := sockaddrToAddr(from); ok && saAddr == dst {
					offender = dst
					reached = true
					got = true
					return true
				}
			}
			return false
		})

		if got {
			return rawHopSample{
				addr:     offender,
				reached:  reached,
				rtt:      at.Sub(start),
				protocol: proto,
			}, nil
		}
	}
}

func sockaddrToAddr(sa syscall.Sockaddr) (netip.Addr, bool) {
	switch s := sa.(type) {
	case *syscall.SockaddrInet4:
		return netip.AddrFrom4(s.Addr), true
	case *syscall.SockaddrInet6:
		return netip.AddrFrom16(s.Addr).Unmap(), true
	default:
		return netip.Addr{}, false
	}
}

// traceAvailable opens and closes an unprivileged UDP+IP_RECVERR socket to
// verify hop-limited path tracing works without sending any packet.
func traceAvailable(isV6 bool) (bool, string) {
	domain := syscall.AF_INET
	if isV6 {
		domain = syscall.AF_INET6
	}
	fd, err := syscall.Socket(domain, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.IPPROTO_UDP)
	if err != nil {
		return false, err.Error()
	}
	err = configureTraceSocket(fd, isV6, 1)
	_ = syscall.Close(fd)
	if err != nil {
		return false, err.Error()
	}
	return true, "unprivileged UDP+IP_RECVERR socket"
}
