//go:build linux || darwin

package safety

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// icmpEndpoint is an open ICMP socket on Linux or Darwin.
type icmpEndpoint struct {
	pc     *icmp.PacketConn
	isV6   bool
	useUDP bool
	proto  int
}

type icmpNetwork struct {
	network string
	address string
	udp     bool
}

func icmpNetworks(isV6 bool) [2]icmpNetwork {
	if isV6 {
		return [2]icmpNetwork{
			{"udp6", "::", true},
			{"ip6:ipv6-icmp", "::", false},
		}
	}
	return [2]icmpNetwork{
		{"udp4", "0.0.0.0", true},
		{"ip4:icmp", "0.0.0.0", false},
	}
}

// dialICMP opens an ICMP socket for dst's family, trying the unprivileged
// datagram socket first and the raw socket second.
func dialICMP(dst netip.Addr) (icmpConn, error) {
	dst = dst.Unmap()
	isV6 := dst.Is6() && !dst.Is4()
	proto := protoICMP4
	if isV6 {
		proto = protoICMP6
	}
	var firstErr error
	for _, n := range icmpNetworks(isV6) {
		pc, err := icmp.ListenPacket(n.network, n.address)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		e := &icmpEndpoint{pc: pc, isV6: isV6, useUDP: n.udp, proto: proto}
		if isV6 {
			if p6 := pc.IPv6PacketConn(); p6 != nil {
				_ = p6.SetControlMessage(ipv6.FlagHopLimit, true)
			}
		} else {
			if p4 := pc.IPv4PacketConn(); p4 != nil {
				_ = p4.SetControlMessage(ipv4.FlagTTL, true)
			}
		}
		return e, nil
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("no ICMP socket available")
	}
	return nil, firstErr
}

func (e *icmpEndpoint) writeEcho(dst netip.Addr, id, seq int, payload []byte) error {
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if e.isV6 {
		typ = ipv6.ICMPTypeEchoRequest
	}
	msg := icmp.Message{Type: typ, Code: 0, Body: &icmp.Echo{ID: id, Seq: seq, Data: payload}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	var addr net.Addr
	if e.useUDP {
		addr = &net.UDPAddr{IP: dst.AsSlice(), Zone: dst.Zone()}
	} else {
		addr = &net.IPAddr{IP: dst.AsSlice(), Zone: dst.Zone()}
	}
	_, err = e.pc.WriteTo(b, addr)
	return err
}

func (e *icmpEndpoint) readEcho(deadline time.Time) (int, []byte, int, error) {
	buf := make([]byte, 1500)
	var (
		n   int
		ttl int
		err error
	)
	if e.isV6 {
		p6 := e.pc.IPv6PacketConn()
		_ = p6.SetReadDeadline(deadline)
		var cm *ipv6.ControlMessage
		n, cm, _, err = p6.ReadFrom(buf)
		if cm != nil {
			ttl = cm.HopLimit
		}
	} else {
		p4 := e.pc.IPv4PacketConn()
		_ = p4.SetReadDeadline(deadline)
		var cm *ipv4.ControlMessage
		n, cm, _, err = p4.ReadFrom(buf)
		if cm != nil {
			ttl = cm.TTL
		}
	}
	if err != nil {
		return 0, nil, 0, err
	}
	m, perr := icmp.ParseMessage(e.proto, buf[:n])
	if perr != nil {
		return -1, nil, 0, nil
	}
	// A raw socket also sees echo requests, its own included when the
	// destination is local; only replies count.
	if m.Type != ipv4.ICMPTypeEchoReply && m.Type != ipv6.ICMPTypeEchoReply {
		return -1, nil, 0, nil
	}
	echo, ok := m.Body.(*icmp.Echo)
	if !ok {
		return -1, nil, 0, nil
	}
	return echo.Seq, echo.Data, ttl, nil
}

func (e *icmpEndpoint) close() error {
	return e.pc.Close()
}

// icmpAvailable opens and closes an ICMP socket to report availability
// without sending.
func icmpAvailable(isV6 bool) (bool, string) {
	var firstErr error
	for _, n := range icmpNetworks(isV6) {
		pc, err := icmp.ListenPacket(n.network, n.address)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		_ = pc.Close()
		if n.udp {
			return true, "unprivileged datagram ICMP socket"
		}
		return true, "raw ICMP socket"
	}
	if firstErr == nil {
		return false, "no ICMP socket available"
	}
	return false, firstErr.Error()
}
