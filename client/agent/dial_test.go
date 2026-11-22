package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/net/dns/dnsmessage"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/protocol"
)

// newTestDNSResolver starts an in-process UDP DNS server on 127.0.0.1 that
// answers queries for any name with the configured A and AAAA records, and
// returns a *net.Resolver wired to it.
func newTestDNSResolver(t *testing.T, v4Addrs []netip.Addr, v6Addrs []netip.Addr) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp4 for test DNS: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, clientAddr, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			var req dnsmessage.Message
			if err := req.Unpack(buf[:n]); err != nil || len(req.Questions) == 0 {
				continue
			}
			q := req.Questions[0]
			resp := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:                 req.Header.ID,
					Response:           true,
					Authoritative:      true,
					RecursionAvailable: true,
					RCode:              dnsmessage.RCodeSuccess,
				},
				Questions: []dnsmessage.Question{q},
			}
			hdr := dnsmessage.ResourceHeader{
				Name:  q.Name,
				Class: dnsmessage.ClassINET,
				TTL:   60,
			}
			switch q.Type {
			case dnsmessage.TypeAAAA:
				for _, ip := range v6Addrs {
					hdr6 := hdr
					hdr6.Type = dnsmessage.TypeAAAA
					resp.Answers = append(resp.Answers, dnsmessage.Resource{
						Header: hdr6,
						Body:   &dnsmessage.AAAAResource{AAAA: ip.As16()},
					})
				}
			case dnsmessage.TypeA:
				for _, ip := range v4Addrs {
					hdr4 := hdr
					hdr4.Type = dnsmessage.TypeA
					resp.Answers = append(resp.Answers, dnsmessage.Resource{
						Header: hdr4,
						Body:   &dnsmessage.AResource{A: ip.As4()},
					})
				}
			}
			out, perr := resp.Pack()
			if perr == nil {
				_, _ = pc.WriteTo(out, clientAddr)
			}
		}
	}()

	dnsAddr := pc.LocalAddr().String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp4", dnsAddr)
		},
	}
}

// listenDualStackLoopback binds both [::1]:port and 127.0.0.1:port on the same
// ephemeral TCP port.
func listenDualStackLoopback(t *testing.T) (ln4, ln6 net.Listener, port int) {
	t.Helper()
	probe6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	_ = probe6.Close()

	for range 20 {
		l6, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Fatalf("listen tcp6: %v", err)
		}
		p := l6.Addr().(*net.TCPAddr).Port
		l4, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			t.Cleanup(func() {
				_ = l4.Close()
				_ = l6.Close()
			})
			return l4, l6, p
		}
		_ = l6.Close()
	}
	t.Fatal("could not allocate matching loopback port on 127.0.0.1 and [::1]")
	return nil, nil, 0
}

func selfSignedTLSForHost(t *testing.T, dnsName string) (serverTLS, clientTLS *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"http/1.1"},
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}},
		}, &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    pool,
			ServerName: dnsName,
		}
}

func TestDialPreferIPv4DualStackConnectsViaIPv4AndAllowsBothFamilies(t *testing.T) {
	ln4, ln6, port := listenDualStackLoopback(t)
	v4Loop := netip.MustParseAddr("127.0.0.1")
	v6Loop := netip.IPv6Loopback()
	resolver := newTestDNSResolver(t, []netip.Addr{v4Loop}, []netip.Addr{v6Loop})

	const gwHost = "dualstack.gateway.test"
	target := fmt.Sprintf("%s:%d", gwHost, port)

	// Serve a dual-stack TLS WebSocket gateway that populates
	// Welcome.ObservedAddresses from the real TCP peer address (r.RemoteAddr),
	// matching production gateway behaviour.
	h := newHarness(t, false)
	serverTLS, clientTLS := selfSignedTLSForHost(t, gwHost)
	observedPeerCh := make(chan string, 4)

	mux := http.NewServeMux()
	mux.HandleFunc(protocol.Path, func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		c.SetReadLimit(protocol.MaxFrameBytes)
		gc := &gwConn{c: c, frames: make(chan *nodev1.Envelope, 1024), done: make(chan struct{})}
		if r.TLS != nil {
			gc.exporter, _ = r.TLS.ExportKeyingMaterial(protocol.TLSExporterLabel, nil, protocol.TLSExporterLength)
		}
		observedPeerCh <- r.RemoteAddr
		go gc.readLoop()
		select {
		case h.gw.conns <- gc:
		case <-h.gw.stop:
			return
		}
		select {
		case <-gc.done:
		case <-h.gw.stop:
		}
	})
	srv := &http.Server{
		Handler:   mux,
		TLSConfig: serverTLS,
		ErrorLog:  slog.NewLogLogger(slog.NewTextHandler(io.Discard, nil), slog.LevelError),
	}
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.Serve(tls.NewListener(ln6, serverTLS)) }()
	go func() { _ = srv.Serve(tls.NewListener(ln4, serverTLS)) }()

	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  resolver,
	}

	// 1. Direct dialPreferIPv4 check: connects to 127.0.0.1 even when AAAA ::1
	// is available on the same port.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rawConn, err := dialPreferIPv4(dialer)(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("dialPreferIPv4(%q): %v", target, err)
	}
	remoteIP, err := netip.ParseAddrPort(rawConn.RemoteAddr().String())
	_ = rawConn.Close()
	if err != nil {
		t.Fatalf("parse remote addr %q: %v", rawConn.RemoteAddr(), err)
	}
	if got := remoteIP.Addr().Unmap(); got != v4Loop {
		t.Fatalf("dialPreferIPv4 connected to %s, want 127.0.0.1 (IPv4)", got)
	}
	observed := parseAddrs([]string{rawConn.LocalAddr().String()})
	if refuse4, refuse6 := refusedFamilies(nodev1.NetworkMode_NETWORK_MODE_HOST, observed); refuse4 || refuse6 {
		t.Fatalf("refusedFamilies(HOST, %v) = (%v, %v), want (false, false)", observed, refuse4, refuse6)
	}

	// 2. End-to-end Agent session check over wss://dualstack.gateway.test:<port>/v1/node
	// in NETWORK_MODE_HOST: Welcome.ObservedAddresses carries the real IPv4 peer
	// address and Gate.RefuseFamilies(false, false) leaves both IPv4 and IPv6 open.
	cfg := h.config()
	cfg.GatewayURL = fmt.Sprintf("wss://%s%s", target, protocol.Path)
	cfg.TLSConfig = clientTLS
	cfg.NetworkMode = nodev1.NetworkMode_NETWORK_MODE_HOST

	h.start(cfg, func(a *Agent) {
		a.client.Transport.(*http.Transport).DialContext = dialPreferIPv4(dialer)
	})
	gc := h.gw.accept(t)
	var peerAddr string
	select {
	case peerAddr = <-observedPeerCh:
	case <-time.After(waitTimeout):
		t.Fatal("timed out waiting for gateway peer address")
	}
	peerAP, err := netip.ParseAddrPort(peerAddr)
	if err != nil {
		t.Fatalf("parse gateway RemoteAddr %q: %v", peerAddr, err)
	}
	if !peerAP.Addr().Unmap().Is4() {
		t.Fatalf("gateway observed non-IPv4 peer %q on dual-stack host", peerAddr)
	}

	_, hello := gc.hello(t)
	w := h.gw.welcomeFor(gc, hello)
	w.ObservedAddresses = []string{peerAddr}
	gc.sendWelcome(t, signWelcome(t, w, h.keys.dispPriv, h.keys.dispKeyID))
	gc.pingPong(t)

	snap := h.gate.snapshot()
	if len(snap.ownObserved) != 1 || snap.ownObserved[0] != v4Loop {
		t.Fatalf("gate ownObserved = %v, want [127.0.0.1]", snap.ownObserved)
	}
	if snap.refuseCalls != 1 || snap.refuse4 || snap.refuse6 {
		t.Fatalf("gate RefuseFamilies: calls=%d refuse4=%v refuse6=%v, want calls=1 refuse4=false refuse6=false",
			snap.refuseCalls, snap.refuse4, snap.refuse6)
	}
}

func TestDialPreferIPv4FallsBackToIPv6(t *testing.T) {
	probe6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	_ = probe6.Close()

	startIPv6Echo := func(t *testing.T) (net.Listener, int) {
		t.Helper()
		// Reserve a matching 127.0.0.1 port, then close ONLY 127.0.0.1 so IPv4
		// connection attempts are deterministically refused while [::1]:port
		// accepts connections.
		ln4, ln6, port := listenDualStackLoopback(t)
		_ = ln4.Close()
		go func() {
			for {
				c, err := ln6.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		return ln6, port
	}

	t.Run("dualstack hostname with ipv4 closed falls back to ipv6", func(t *testing.T) {
		_, port := startIPv6Echo(t)
		resolver := newTestDNSResolver(t,
			[]netip.Addr{netip.MustParseAddr("127.0.0.1")},
			[]netip.Addr{netip.IPv6Loopback()},
		)
		dialer := &net.Dialer{Timeout: 5 * time.Second, Resolver: resolver}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := dialPreferIPv4(dialer)(ctx, "tcp", fmt.Sprintf("dualstack.gateway.test:%d", port))
		if err != nil {
			t.Fatalf("dialPreferIPv4 fallback failed: %v", err)
		}
		ap := netip.MustParseAddrPort(conn.RemoteAddr().String())
		_ = conn.Close()
		if ap.Addr() != netip.IPv6Loopback() {
			t.Fatalf("fallback connected to %s, want ::1", ap.Addr())
		}
	})

	t.Run("ipv6 only hostname with AAAA only falls back immediately", func(t *testing.T) {
		_, port := startIPv6Echo(t)
		resolver := newTestDNSResolver(t, nil, []netip.Addr{netip.IPv6Loopback()})
		dialer := &net.Dialer{Timeout: 5 * time.Second, Resolver: resolver}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := dialPreferIPv4(dialer)(ctx, "tcp", fmt.Sprintf("v6only.gateway.test:%d", port))
		if err != nil {
			t.Fatalf("dialPreferIPv4 AAAA-only fallback failed: %v", err)
		}
		ap := netip.MustParseAddrPort(conn.RemoteAddr().String())
		_ = conn.Close()
		if ap.Addr() != netip.IPv6Loopback() {
			t.Fatalf("AAAA-only fallback connected to %s, want ::1", ap.Addr())
		}
	})

	t.Run("explicit ipv6 literal dials ipv6 directly without ipv4 attempt", func(t *testing.T) {
		_, port := startIPv6Echo(t)
		var v4Attempts, v6Attempts atomic.Int32
		dialer := &net.Dialer{
			Timeout: 5 * time.Second,
			ControlContext: func(_ context.Context, network, _ string, _ syscall.RawConn) error {
				switch network {
				case "tcp4":
					v4Attempts.Add(1)
				case "tcp6":
					v6Attempts.Add(1)
				}
				return nil
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := dialPreferIPv4(dialer)(ctx, "tcp", fmt.Sprintf("[::1]:%d", port))
		if err != nil {
			t.Fatalf("dialPreferIPv4([::1]:%d) failed: %v", port, err)
		}
		_ = conn.Close()
		if v4Attempts.Load() != 0 || v6Attempts.Load() != 1 {
			t.Fatalf("literal [::1] attempts: tcp4=%d tcp6=%d, want tcp4=0 tcp6=1",
				v4Attempts.Load(), v6Attempts.Load())
		}
	})

	t.Run("blackholed ipv4 caps wait and falls back to ipv6", func(t *testing.T) {
		_, port := startIPv6Echo(t)
		resolver := newTestDNSResolver(t,
			[]netip.Addr{netip.MustParseAddr("127.0.0.1")},
			[]netip.Addr{netip.IPv6Loopback()},
		)
		var v4Attempts, v6Attempts atomic.Int32
		dialer := &net.Dialer{
			Timeout:  200 * time.Millisecond,
			Resolver: resolver,
			ControlContext: func(ctx context.Context, network, _ string, _ syscall.RawConn) error {
				if network == "tcp4" {
					v4Attempts.Add(1)
					<-ctx.Done()
					return ctx.Err()
				}
				v6Attempts.Add(1)
				return nil
			},
		}

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := dialPreferIPv4(dialer)(ctx, "tcp", fmt.Sprintf("blackholed4.gateway.test:%d", port))
		if err != nil {
			t.Fatalf("blackholed IPv4 fallback failed: %v", err)
		}
		_ = conn.Close()
		elapsed := time.Since(start)
		if v4Attempts.Load() != 1 || v6Attempts.Load() != 1 {
			t.Fatalf("attempts: tcp4=%d tcp6=%d, want 1 and 1", v4Attempts.Load(), v6Attempts.Load())
		}
		if elapsed > time.Second {
			t.Fatalf("blackholed IPv4 took %v before IPv6 fallback completed", elapsed)
		}
	})
}
