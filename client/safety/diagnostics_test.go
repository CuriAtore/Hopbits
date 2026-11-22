package safety

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
)

var dnsN = module.Needs{Transport: module.TransportDNS}

func buildLinuxErrQueueCmsg(isV6 bool, origin, icmpType, icmpCode uint8, offender netip.Addr) []byte {
	var sa []byte
	level := int32(linuxSOL_IP)
	cmsgType := int32(linuxIP_RECVERR)
	if isV6 {
		level = linuxSOL_IPV6
		cmsgType = linuxIPV6_RECVERR
		sa = make([]byte, 28) // sizeof(sockaddr_in6)
		binary.LittleEndian.PutUint16(sa[0:2], linuxAF_INET6)
		b16 := offender.As16()
		copy(sa[8:24], b16[:])
	} else {
		sa = make([]byte, 16) // sizeof(sockaddr_in)
		binary.LittleEndian.PutUint16(sa[0:2], linuxAF_INET)
		b4 := offender.As4()
		copy(sa[4:8], b4[:])
	}
	cmsgLen := 16 + 16 + len(sa)
	aligned := (cmsgLen + 7) &^ 7
	buf := make([]byte, aligned)
	binary.LittleEndian.PutUint64(buf[0:8], uint64(cmsgLen))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(level))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(cmsgType))
	// sock_extended_err at offset 16..32
	binary.LittleEndian.PutUint32(buf[16:20], 113) // EHOSTUNREACH / ETIMEDOUT
	buf[20] = origin
	buf[21] = icmpType
	buf[22] = icmpCode
	copy(buf[32:], sa)
	return buf
}

func TestParseErrQueueControlV4AndV6(t *testing.T) {
	dst4 := netip.MustParseAddr("1.1.1.1")
	hop4 := netip.MustParseAddr("62.155.240.1")

	oob := buildLinuxErrQueueCmsg(false, linuxSO_EE_ORIGIN_ICMP, linuxICMP_TIME_EXCEEDED, 0, hop4)
	addr, reached, ok := parseErrQueueControl(oob, dst4)
	if !ok || addr != hop4 || reached {
		t.Fatalf("v4 time exceeded: got addr=%v reached=%v ok=%v", addr, reached, ok)
	}

	oobReach := buildLinuxErrQueueCmsg(false, linuxSO_EE_ORIGIN_ICMP, linuxICMP_DEST_UNREACH, 3, dst4)
	addr, reached, ok = parseErrQueueControl(oobReach, dst4)
	if !ok || addr != dst4 || !reached {
		t.Fatalf("v4 port unreachable from dst: got addr=%v reached=%v ok=%v", addr, reached, ok)
	}

	// Intermediate router sending ICMP_DEST_UNREACH is NOT destination reached.
	oobMidUnreach := buildLinuxErrQueueCmsg(false, linuxSO_EE_ORIGIN_ICMP, linuxICMP_DEST_UNREACH, 1, hop4)
	addr, reached, ok = parseErrQueueControl(oobMidUnreach, dst4)
	if !ok || addr != hop4 || reached {
		t.Fatalf("v4 unreach from router: got addr=%v reached=%v ok=%v", addr, reached, ok)
	}

	dst6 := netip.MustParseAddr("2606:4700:4700::1111")
	hop6 := netip.MustParseAddr("2001:4860:0:1::1")
	oob6 := buildLinuxErrQueueCmsg(true, linuxSO_EE_ORIGIN_ICMP6, linuxICMP6_TIME_EXCEEDED, 0, hop6)
	addr, reached, ok = parseErrQueueControl(oob6, dst6)
	if !ok || addr != hop6 || reached {
		t.Fatalf("v6 time exceeded: got addr=%v reached=%v ok=%v", addr, reached, ok)
	}

	oob6Reach := buildLinuxErrQueueCmsg(true, linuxSO_EE_ORIGIN_ICMP6, linuxICMP6_DEST_UNREACH, 4, dst6)
	addr, reached, ok = parseErrQueueControl(oob6Reach, dst6)
	if !ok || addr != dst6 || !reached {
		t.Fatalf("v6 port unreachable from dst: got addr=%v reached=%v ok=%v", addr, reached, ok)
	}
}

func TestTraceHopPrivacyRedactionAndBudget(t *testing.T) {
	caps := AgentCaps()
	caps.ICMPPacketsPerSecond = 1000
	g, _ := newGuard(t, caps, nil, nil)
	g.SetOwnNetwork(
		[]netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		[]netip.Addr{netip.MustParseAddr("84.15.200.42"), netip.MustParseAddr("2a01:4f8:10a:20b::5")},
	)

	var scripted rawHopSample
	var scriptedErr error
	g.traceHop = func(_ context.Context, _ *Guard, _ netip.Addr, proto string, _, _ int, _ time.Duration) (rawHopSample, error) {
		out := scripted
		if out.protocol == "" {
			out.protocol = proto
		}
		return out, scriptedErr
	}

	l, err := g.Admit(context.Background(), mkJob("1.1.1.1", 0, v4, pinned("1.1.1.1")), icmpN)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	cases := []struct {
		name         string
		hopIP        string
		reached      bool
		wantIP       string
		wantRedacted bool
		wantReached  bool
	}{
		{"Hop-1 RFC1918 router", "192.168.1.1", false, "", true, false},
		{"ISP CGNAT hop", "100.64.12.1", false, "", true, false},
		{"Loopback hop", "127.0.0.1", false, "", true, false},
		{"Operator own /24 BNG", "84.15.200.1", false, "", true, false},
		{"Operator own /48 IPv6 router", "2a01:4f8:10a::1", false, "", true, false},
		{"Public backbone router", "62.155.240.1", false, "62.155.240.1", false, false},
		{"Validated destination itself", "1.1.1.1", true, "1.1.1.1", false, true},
	}
	for i, tc := range cases {
		scripted = rawHopSample{
			addr:     netip.MustParseAddr(tc.hopIP),
			reached:  tc.reached,
			rtt:      4200 * time.Microsecond,
			protocol: "udp",
		}
		scriptedErr = nil
		got, err := l.TraceHop(context.Background(), "udp", i+1, i+1, 500*time.Millisecond)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		gotIP := ""
		if got.Addr.IsValid() {
			gotIP = got.Addr.String()
		}
		if gotIP != tc.wantIP || got.Redacted != tc.wantRedacted || got.Reached != tc.wantReached || got.RTT != 4200*time.Microsecond {
			t.Fatalf("%s: got ip=%q redacted=%v reached=%v rtt=%v", tc.name, gotIP, got.Redacted, got.Reached, got.RTT)
		}
	}

	// Exhaust remaining budget up to maxTracePackets (320 total).
	scriptedErr = ErrEchoTimeout
	for i := len(cases); i < maxTracePackets; i++ {
		if _, err := l.TraceHop(context.Background(), "udp", 1, i+1, 10*time.Millisecond); !errors.Is(err, ErrEchoTimeout) {
			t.Fatalf("probe %d: got %v, want ErrEchoTimeout", i+1, err)
		}
	}
	_, err = l.TraceHop(context.Background(), "udp", 1, 999, 10*time.Millisecond)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY)
}

// serveFakeDNS creates an in-memory net.Pipe responder simulating UDP or
// length-prefixed TCP DNS servers.
func serveFakeDNS(t *testing.T, build func(q dnsmessage.Question, id uint16, network string) []byte) func(context.Context, string, string, time.Duration) (net.Conn, error) {
	t.Helper()
	return func(_ context.Context, network, _ string, _ time.Duration) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			if network == "tcp" {
				var lb [2]byte
				if _, err := server.Read(lb[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(lb[:]))
				qbuf := make([]byte, n)
				if _, err := server.Read(qbuf); err != nil {
					return
				}
				var p dnsmessage.Parser
				hdr, err := p.Start(qbuf)
				if err != nil {
					return
				}
				q, err := p.Question()
				if err != nil {
					return
				}
				resp := build(q, hdr.ID, "tcp")
				frame := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(frame[:2], uint16(len(resp)))
				copy(frame[2:], resp)
				_, _ = server.Write(frame)
				return
			}
			qbuf := make([]byte, 2048)
			rn, err := server.Read(qbuf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			hdr, err := p.Start(qbuf[:rn])
			if err != nil {
				return
			}
			q, err := p.Question()
			if err != nil {
				return
			}
			resp := build(q, hdr.ID, "udp")
			_, _ = server.Write(resp)
		}()
		return client, nil
	}
}

func TestQueryDNSParsingTCFallbackAndPrivacy(t *testing.T) {
	g, clk := newGuard(t, AgentCaps(), nil, nil)
	resolvPath := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(resolvPath, []byte("# comment\nnameserver 192.168.178.1\nnameserver 127.0.0.53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g.resolvConf = resolvPath

	var dialedAddrs []string
	baseDial := serveFakeDNS(t, func(q dnsmessage.Question, id uint16, network string) []byte {
		if q.Name.String() == "nx.example.com." {
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
				ID:       id,
				Response: true,
				RCode:    dnsmessage.RCodeNameError,
			})
			_ = b.StartQuestions()
			_ = b.Question(q)
			out, _ := b.Finish()
			return out
		}
		if q.Type == dnsTypeCAA && network == "udp" {
			// Force TC=1 over UDP to test automatic TCP retry!
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
				ID:        id,
				Response:  true,
				Truncated: true,
			})
			_ = b.StartQuestions()
			_ = b.Question(q)
			out, _ := b.Finish()
			return out
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
			ID:            id,
			Response:      true,
			Authoritative: true,
		})
		_ = b.StartQuestions()
		_ = b.Question(q)
		_ = b.StartAnswers()
		hdr := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 300}
		switch q.Type {
		case dnsmessage.TypeA:
			_ = b.AResource(hdr, dnsmessage.AResource{A: [4]byte{104, 21, 48, 12}})
		case dnsmessage.TypeMX:
			_ = b.MXResource(hdr, dnsmessage.MXResource{Pref: 10, MX: dnsmessage.MustNewName("mx1.hopbits.io.")})
		case dnsmessage.TypeTXT:
			_ = b.TXTResource(hdr, dnsmessage.TXTResource{TXT: []string{"v=DMARC1; ", "p=reject"}})
		case dnsmessage.TypePTR:
			_ = b.PTRResource(hdr, dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("dns.google.")})
		case dnsTypeCAA:
			rdata := append([]byte{0, 5}, []byte("issueletsencrypt.org")...)
			_ = b.UnknownResource(hdr, dnsmessage.UnknownResource{Type: dnsTypeCAA, Data: rdata})
		}
		out, _ := b.Finish()
		return out
	})
	g.dialDNS = func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
		dialedAddrs = append(dialedAddrs, network+"/"+addr)
		return baseDial(ctx, network, addr, timeout)
	}

	// 1. ISP resolver queries /etc/resolv.conf IP internally but NEVER leaks it in Resolver.
	l1, err := g.Admit(context.Background(), mkJob("_dmarc.hopbits.io", 0, v4, pinned("1.1.1.1")), dnsN)
	if err != nil {
		t.Fatalf("admit underscore DNS target: %v", err)
	}
	rep, err := l1.QueryDNS(context.Background(), module.DNSQuery{Qtype: "TXT", Resolver: "isp", Protocol: "udp", Timeout: time.Second})
	l1.Close()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Resolver != "isp" || strings.Contains(rep.Resolver, "192.168") {
		t.Fatalf("ISP resolver leaked or wrong: %q", rep.Resolver)
	}
	if len(rep.Answers) != 1 || rep.Answers[0].Data != "v=DMARC1; p=reject" {
		t.Fatalf("TXT answer = %+v", rep.Answers)
	}
	if dialedAddrs[0] != "udp/192.168.178.1:53" {
		t.Fatalf("expected resolv.conf nameserver dial, got %v", dialedAddrs)
	}

	// 2. Consecutive DNS job to a DIFFERENT domain with placeholder PinnedAddress 1.1.1.1
	// succeeds immediately (no /24 destination spacing collision on 1.1.1.0/24!),
	// tests TC=1 automatic TCP retry and CAA parsing.
	l2, err := g.Admit(context.Background(), mkJob("caa.example.org", 0, v4, pinned("1.1.1.1")), dnsN)
	if err != nil {
		t.Fatalf("admit second DNS domain immediately: %v", err)
	}
	repCAA, err := l2.QueryDNS(context.Background(), module.DNSQuery{Qtype: "CAA", Resolver: "1.1.1.1", Protocol: "udp", Timeout: time.Second})
	l2.Close()
	if err != nil {
		t.Fatal(err)
	}
	if repCAA.Protocol != "tcp" || len(repCAA.Answers) != 1 || repCAA.Answers[0].Data != `0 issue "letsencrypt.org"` {
		t.Fatalf("TC=1 retry / CAA parse failed: %+v", repCAA)
	}

	// 3. NXDOMAIN returns cleanly without error.
	l3, err := g.Admit(context.Background(), mkJob("nx.example.com", 0, v4, pinned("1.1.1.1")), dnsN)
	if err != nil {
		t.Fatal(err)
	}
	repNX, err := l3.QueryDNS(context.Background(), module.DNSQuery{Qtype: "A", Resolver: "8.8.8.8", Protocol: "udp", Timeout: time.Second})
	l3.Close()
	if err != nil {
		t.Fatal(err)
	}
	if repNX.Rcode != "NXDOMAIN" || repNX.RcodeNum != 3 || len(repNX.Answers) != 0 {
		t.Fatalf("NXDOMAIN reply = %+v", repNX)
	}

	// 4. PTR lookup on public IP literal 8.8.8.8 with PinnedAddress 1.1.1.1.
	clk.advance(time.Minute)
	l4, err := g.Admit(context.Background(), mkJob("8.8.8.8", 0, v4, pinned("1.1.1.1")), dnsN)
	if err != nil {
		t.Fatalf("admit PTR IP literal: %v", err)
	}
	repPTR, err := l4.QueryDNS(context.Background(), module.DNSQuery{Qtype: "PTR", Resolver: "9.9.9.9", Protocol: "udp", Timeout: time.Second})
	l4.Close()
	if err != nil {
		t.Fatal(err)
	}
	if repPTR.Qname != "8.8.8.8.in-addr.arpa" || len(repPTR.Answers) != 1 || repPTR.Answers[0].Data != "dns.google" {
		t.Fatalf("PTR reply = %+v", repPTR)
	}

	// 5. Invalid resolver is refused with INVALID_PARAMS.
	clk.advance(time.Minute)
	l5, err := g.Admit(context.Background(), mkJob("hopbits.io", 0, v4, pinned("1.1.1.1")), dnsN)
	if err != nil {
		t.Fatal(err)
	}
	_, err = l5.QueryDNS(context.Background(), module.DNSQuery{Qtype: "A", Resolver: "192.168.1.1", Protocol: "udp", Timeout: time.Second})
	l5.Close()
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS)

	// 6. Private/local/ownNet DNS targets are refused at Admit.
	g.SetOwnNetwork(nil, []netip.Addr{netip.MustParseAddr("84.15.200.5")})
	for _, badHost := range []string{
		"localhost",
		"printer.local",
		"nas.home.arpa",
		"192.168.1.1",
		"84.15.200.1",
		"1.1.168.192.in-addr.arpa",
		"1.200.15.84.in-addr.arpa",
	} {
		_, err := g.Admit(context.Background(), mkJob(badHost, 0, v4, pinned("1.1.1.1")), dnsN)
		wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
	}

	// 7. Traffic was charged to the daily counter.
	g.mu.Lock()
	used := g.trafficUsed
	g.mu.Unlock()
	if used <= 0 {
		t.Fatalf("expected positive traffic charge from DNS queries, got %d", used)
	}
}
