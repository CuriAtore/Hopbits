//go:build linux

package anchor

import (
	"context"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// listenICMP starts best-effort raw ICMP echo listeners (v4 and v6) that
// extract arriving TTL/hop-limit and Echo payloads as observations. Inbound
// ICMP_ECHO / ICMPv6_ECHO_REQUEST capture requires raw ICMP sockets
// (CAP_NET_RAW); if the container lacks permissions, it logs a warning and
// returns cleanly without error.
func (s *Server) listenICMP(ctx context.Context) {
	s.startICMPLoop(ctx, "ip4:icmp", false)
	s.startICMPLoop(ctx, "ip6:ipv6-icmp", true)
}

func (s *Server) startICMPLoop(ctx context.Context, rawNet string, v6 bool) {
	c, err := icmp.ListenPacket(rawNet, "")
	if err != nil {
		s.log.Warn("anchor ICMP listener unavailable; relying on kernel echo responses",
			"network", rawNet, "err", err)
		return
	}

	if v6 {
		if p6 := c.IPv6PacketConn(); p6 != nil {
			_ = p6.SetControlMessage(ipv6.FlagHopLimit, true)
		}
	} else {
		if p4 := c.IPv4PacketConn(); p4 != nil {
			_ = p4.SetControlMessage(ipv4.FlagTTL, true)
		}
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer c.Close()
		go func() {
			<-ctx.Done()
			_ = c.Close()
		}()
		buf := make([]byte, 2048)
		for {
			n, ttl, src, err := readICMPPacket(c, buf, v6)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			s.handleICMPPacket(buf[:n], ttl, src, v6)
		}
	}()
}

func readICMPPacket(c *icmp.PacketConn, buf []byte, v6 bool) (n int, ttl uint32, src net.Addr, err error) {
	if v6 {
		if p6 := c.IPv6PacketConn(); p6 != nil {
			n, cm, a, rerr := p6.ReadFrom(buf)
			if cm != nil && cm.HopLimit > 0 {
				ttl = uint32(cm.HopLimit)
			}
			return n, ttl, a, rerr
		}
	} else {
		if p4 := c.IPv4PacketConn(); p4 != nil {
			n, cm, a, rerr := p4.ReadFrom(buf)
			if cm != nil && cm.TTL > 0 {
				ttl = uint32(cm.TTL)
			}
			return n, ttl, a, rerr
		}
	}
	n, a, rerr := c.ReadFrom(buf)
	return n, 0, a, rerr
}

func (s *Server) handleICMPPacket(pkt []byte, ttl uint32, src net.Addr, v6 bool) {
	protoNum := unix.IPPROTO_ICMP
	wantType := icmp.Type(ipv4.ICMPTypeEcho)
	if v6 {
		protoNum = unix.IPPROTO_ICMPV6
		wantType = ipv6.ICMPTypeEchoRequest
	}
	msg, err := icmp.ParseMessage(protoNum, pkt)
	if err != nil || msg.Type != wantType {
		return
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok || len(echo.Data) == 0 {
		return
	}
	addr := addrFromNetAddr(src)
	if !addr.IsValid() {
		return
	}
	nonce := append([]byte(nil), echo.Data...)
	if len(nonce) > maxNonceBytes {
		nonce = nonce[:maxNonceBytes]
	}
	s.RecordICMP(addr, nonce, ttl, true)
}
