package anchor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
)

type fakeSink struct {
	mu  sync.Mutex
	obs []*nodev1.Observation
	ch  chan []*nodev1.Observation
}

func newFakeSink() *fakeSink {
	return &fakeSink{ch: make(chan []*nodev1.Observation, 32)}
}

func (s *fakeSink) SendObservations(_ context.Context, obs []*nodev1.Observation) error {
	s.mu.Lock()
	s.obs = append(s.obs, obs...)
	s.mu.Unlock()
	s.ch <- obs
	return nil
}

func (s *fakeSink) waitCount(t *testing.T, want int) []*nodev1.Observation {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		s.mu.Lock()
		got := append([]*nodev1.Observation(nil), s.obs...)
		s.mu.Unlock()
		if len(got) >= want {
			return got
		}
		select {
		case <-s.ch:
		case <-deadline:
			t.Fatalf("timed out waiting for %d observations (got %d)", want, len(got))
		}
	}
}

func selfSignedWildcardCert(t *testing.T, dnsNames ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return cert, pool
}

func TestAnchorHTTP11CalibrationAndDomainCheck(t *testing.T) {
	cert, pool := selfSignedWildcardCert(t, "*.anchor.hopbits.io", "anchor.hopbits.io")
	sink := newFakeSink()
	srv, err := New(Config{
		ListenAddr:    "127.0.0.1:0",
		Domain:        "anchor.hopbits.io",
		TLSConfig:     &tls.Config{Certificates: []tls.Certificate{cert}},
		Sink:          sink,
		FlushInterval: 20 * time.Millisecond,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	addr := ln.Addr().String()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: "rnd123.anchor.hopbits.io",
			},
			// Verify HTTP/1.1 works cleanly without HTTP/2 upgrades.
		},
	}

	nonceHex := hex.EncodeToString([]byte("calib-nonce-1"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/calibration?nonce="+nonceHex, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "rnd123.anchor.hopbits.io:443"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("calibration GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Proto != "HTTP/1.1" || !resp.Close {
		t.Fatalf("unexpected calibration response: status=%d proto=%s close=%v body=%q",
			resp.StatusCode, resp.Proto, resp.Close, string(body))
	}

	// Wrong Host must fail with 421 Misdirected Request and not record an observation.
	badReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/calibration?nonce=bad", nil)
	badReq.Host = "evil.example.com"
	badResp, err := client.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("wrong host returned %d, want 421", badResp.StatusCode)
	}

	// /healthz must succeed and never emit a spurious observation.
	hzReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/healthz", nil)
	hzReq.Host = "rnd123.anchor.hopbits.io"
	hzResp, err := client.Do(hzReq)
	if err != nil {
		t.Fatal(err)
	}
	hzResp.Body.Close()
	if hzResp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz returned %d", hzResp.StatusCode)
	}

	obs := sink.waitCount(t, 1)
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if string(obs[0].GetNonce()) != "calib-nonce-1" || !obs[0].GetServedAndAcknowledged() || obs[0].GetSourceAddress() != "127.0.0.1" {
		t.Fatalf("unexpected calibration observation: %+v", obs[0])
	}

	cancel()
	<-done
}

func TestAnchorWSEchoAndRecordICMP(t *testing.T) {
	sink := newFakeSink()
	srv, err := New(Config{
		ListenAddr:    "127.0.0.1:0",
		Sink:          sink,
		FlushInterval: 20 * time.Millisecond,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	wsURL := "ws://" + ln.Addr().String() + "/ws_echo"
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	wantPayload := []byte("ws-echo-nonce-9")
	if err := conn.Write(ctx, websocket.MessageBinary, wantPayload); err != nil {
		t.Fatal(err)
	}
	typ, gotPayload, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if typ != websocket.MessageBinary || string(gotPayload) != string(wantPayload) {
		t.Fatalf("ws echo mismatch: typ=%v payload=%q", typ, gotPayload)
	}
	_ = conn.Close(websocket.StatusNormalClosure, "done")

	srv.RecordICMP(netip.MustParseAddr("198.51.100.7"), []byte("icmp-nonce-7"), 57, true)

	obs := sink.waitCount(t, 2)
	var gotWS, gotICMP bool
	for _, o := range obs {
		if string(o.GetNonce()) == "ws-echo-nonce-9" && o.GetServedAndAcknowledged() && o.GetSourceAddress() == "127.0.0.1" {
			gotWS = true
		}
		if string(o.GetIcmpNonce()) == "icmp-nonce-7" && o.GetArrivingTtl() == 57 && o.GetSourceAddress() == "198.51.100.7" {
			gotICMP = true
		}
	}
	if !gotWS || !gotICMP {
		t.Fatalf("missing expected observations: gotWS=%v gotICMP=%v obs=%+v", gotWS, gotICMP, obs)
	}

	cancel()
	<-done
}
