package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/protocol"
)

func signPauseFile(t *testing.T, priv ed25519.PrivateKey, doc PauseDocument) []byte {
	t.Helper()
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(SignedPauseFile{
		Body: body,
		Sig:  protocol.Sign(priv, protocol.PurposePauseFile, body),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIsAnchorDomainHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"anchor.hopbits.io", true},
		{"a1b2.anchor.hopbits.io", true},
		{"sub.node.anchor.hopbits.io.", true},
		{"ANCHOR.HOPBITS.IO", true},
		{"pause.anchor.hopbits.io", false},
		{"PAUSE.ANCHOR.HOPBITS.IO.", false},
		{"sub.pause.anchor.hopbits.io", false},
		{"evilanchor.hopbits.io", false},
		{"anchor.hopbits.io.evil.com", false},
		{"127.0.0.1", false},
		{"2001:db8::1", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsAnchorDomainHost(tc.host); got != tc.want {
			t.Errorf("IsAnchorDomainHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestPauseFileVerificationRollbackAndExpiry(t *testing.T) {
	_, recPriv := mustKey(t)
	h := newHarness(t, false)
	cfg := h.config()
	recPub := recPriv.Public().(ed25519.PublicKey)
	cfg.Roots = protocol.Roots{h.keys.rootPub, recPub}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	valid := signPauseFile(t, h.keys.rootPriv, PauseDocument{
		Paused:      true,
		IssuedUnix:  t0.Unix(),
		ExpiresUnix: t0.Add(10 * time.Minute).Unix(),
		Reason:      "incident-1",
	})
	paused, err := a.ApplyPauseFile(valid)
	if err != nil || !paused || !a.IsPaused() {
		t.Fatalf("valid pause file failed: paused=%v isPaused=%v err=%v", paused, a.IsPaused(), err)
	}

	// Recovery root (index 1) must not sign the pause file.
	recSigned := signPauseFile(t, recPriv, PauseDocument{
		Paused:      false,
		IssuedUnix:  t0.Add(time.Minute).Unix(),
		ExpiresUnix: t0.Add(15 * time.Minute).Unix(),
	})
	if _, err := a.ApplyPauseFile(recSigned); err == nil {
		t.Fatal("pause file signed by recovery root was accepted")
	}

	// Tampered body must fail verification.
	var tampered SignedPauseFile
	_ = json.Unmarshal(valid, &tampered)
	tampered.Body[0] ^= ' '
	tamperedRaw, _ := json.Marshal(tampered)
	if _, err := a.ApplyPauseFile(tamperedRaw); err == nil {
		t.Fatal("tampered pause file was accepted")
	}

	// Wrong purpose signature fails verification.
	body, _ := json.Marshal(PauseDocument{
		Paused:      false,
		IssuedUnix:  t0.Add(time.Minute).Unix(),
		ExpiresUnix: t0.Add(15 * time.Minute).Unix(),
	})
	wrongPurpose, _ := json.Marshal(SignedPauseFile{
		Body: body,
		Sig:  protocol.Sign(h.keys.rootPriv, protocol.PurposeReleaseManifest, body),
	})
	if _, err := a.ApplyPauseFile(wrongPurpose); err == nil {
		t.Fatal("wrong-purpose pause signature was accepted")
	}

	// Advance newer pause, then verify rollback protection refuses older IssuedUnix.
	newer := signPauseFile(t, h.keys.rootPriv, PauseDocument{
		Paused:      false,
		IssuedUnix:  t0.Add(2 * time.Minute).Unix(),
		ExpiresUnix: t0.Add(20 * time.Minute).Unix(),
	})
	if paused, err := a.ApplyPauseFile(newer); err != nil || paused || a.IsPaused() {
		t.Fatalf("clearing pause failed: paused=%v isPaused=%v err=%v", paused, a.IsPaused(), err)
	}
	if _, err := a.ApplyPauseFile(valid); err == nil {
		t.Fatal("stale rollback pause file was accepted")
	}

	// Re-activate pause, then verify it lapses once ExpiresUnix passes.
	rePaused := signPauseFile(t, h.keys.rootPriv, PauseDocument{
		Paused:      true,
		IssuedUnix:  t0.Add(3 * time.Minute).Unix(),
		ExpiresUnix: t0.Add(5 * time.Minute).Unix(),
	})
	if paused, err := a.ApplyPauseFile(rePaused); err != nil || !paused || !a.IsPaused() {
		t.Fatalf("re-pause failed: %v", err)
	}
	h.clock.Set(t0.Add(6 * time.Minute))
	if a.IsPaused() {
		t.Fatal("expired pause stayed active")
	}
	if _, err := a.ApplyPauseFile(rePaused); err == nil {
		t.Fatal("already-expired pause file was accepted")
	}
}

func TestPauseFileAppliesRevocationsAndGatesJobs(t *testing.T) {
	h := newHarness(t, true)
	// Let module block so we can verify pause cancels in-flight non-anchor work.
	h.mod.block = make(chan struct{})
	defer close(h.mod.block)

	var pfMu sync.Mutex
	currentPause := signPauseFile(t, h.keys.rootPriv, PauseDocument{
		Paused:      false,
		IssuedUnix:  t0.Unix(),
		ExpiresUnix: t0.Add(time.Hour).Unix(),
	})
	pf := &fakePauseFetcher{get: func() ([]byte, error) {
		pfMu.Lock()
		defer pfMu.Unlock()
		return currentPause, nil
	}}

	cfg := h.config()
	cfg.PauseFetcher = pf
	cfg.PausePollInterval = 15 * time.Millisecond
	r := h.start(cfg, nil)
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)
	id := h.nodeID(r)

	// Start one non-anchor job that blocks inside fakeModule.
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Job{Job: h.job(id, "j-inflight", nil)}})
	waitStarted(t, h.mod, "j-inflight")

	// Publish signed pause file carrying a revocation for the dispatcher key.
	rev := h.keys.revocation(t, h.keys.dispKeyID)
	pfMu.Lock()
	currentPause = signPauseFile(t, h.keys.rootPriv, PauseDocument{
		Paused:      true,
		IssuedUnix:  t0.Add(time.Minute).Unix(),
		ExpiresUnix: t0.Add(time.Hour).Unix(),
		Reason:      "emergency halt",
		Revocations: []SignedRevocationEntry{{Body: rev.Body, Sig: rev.Sig, RootIndex: rev.RootIndex}},
	})
	pfMu.Unlock()

	waitUntil(t, "pause activated from background poll", func() bool { return r.a.IsPaused() })

	// In-flight non-anchor job completes as failed/cancelled via pause cancellation.
	resEnv := gc.waitFor(t, "cancelled inflight job result", func(e *nodev1.Envelope) bool {
		return e.GetResult() != nil
	})
	var res nodev1.Result
	if err := proto.Unmarshal(resEnv.GetResult().GetBody(), &res); err != nil {
		t.Fatal(err)
	}
	if res.GetJobId() != "j-inflight" || res.GetOutcome() != nodev1.Outcome_OUTCOME_CANCELLED {
		t.Fatalf("inflight job result after pause: %v", &res)
	}

	// Revoked dispatcher key now fails job verification with ERROR_CODE_KEY_REVOKED.
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Job{Job: h.job(id, "j-revoked-key", nil)}})
	errEnv := gc.waitFor(t, "revoked dispatcher key error", func(e *nodev1.Envelope) bool {
		return e.GetError() != nil && e.GetError().GetCode() == nodev1.ErrorCode_ERROR_CODE_KEY_REVOKED
	})
	if errEnv == nil {
		t.Fatal("expected ERROR_CODE_KEY_REVOKED")
	}

	// Certify a fresh dispatcher key and push it in ConfigUpdate; non-anchor job
	// still refused locally due to active pause, while anchor-domain job succeeds.
	newDispPub, newDispPriv := mustKey(t)
	newDispCert, newDispID := h.keys.certify(t, newDispPub, h.keys.rootPriv)
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Config{Config: &nodev1.ConfigUpdate{
		DispatcherCerts: []*nodev1.SignedKeyCertificate{newDispCert},
	}}})
	signWithNew := func(j *nodev1.Job) *nodev1.SignedJob {
		h.keys.dispPriv = newDispPriv
		h.keys.dispKeyID = newDispID
		return h.keys.signJob(t, j)
	}
	_ = newDispCert

	// Build jobs signed with the fresh dispatcher key.
	nonAnchor := &nodev1.Job{
		JobId:          "j-non-anchor-paused",
		Attempt:        1,
		JobClass:       nodev1.JobClass_JOB_CLASS_MEASURE,
		Kind:           "fake",
		KindVersion:    1,
		Params:         []byte("p"),
		Target:         &nodev1.Target{Host: "probe-target.example", Port: 443, Family: nodev1.AddressFamily_ADDRESS_FAMILY_IPV4, PinnedAddress: "203.0.113.7"},
		DeadlineUnixMs: t0.Add(5 * time.Minute).UnixMilli(),
		IssuedUnixMs:   t0.UnixMilli(),
		NodeId:         id,
		MeasurementId:  "m-1",
	}
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Job{Job: signWithNew(nonAnchor)}})
	ack := gc.waitFor(t, "refusal while paused", func(e *nodev1.Envelope) bool {
		return e.GetJobAck() != nil && e.GetJobAck().GetJobId() == "j-non-anchor-paused"
	}).GetJobAck()
	if ack.GetAccepted() || ack.GetError() != nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY {
		t.Fatalf("non-anchor job during pause: ack=%v", ack)
	}

	anchorJob := &nodev1.Job{
		JobId:          "j-anchor-allowed",
		Attempt:        1,
		JobClass:       nodev1.JobClass_JOB_CLASS_MEASURE,
		Kind:           "fake",
		KindVersion:    1,
		Params:         []byte("p"),
		Target:         &nodev1.Target{Host: "a1.anchor.hopbits.io", Port: 443, Family: nodev1.AddressFamily_ADDRESS_FAMILY_IPV4, PinnedAddress: "203.0.113.8"},
		DeadlineUnixMs: t0.Add(5 * time.Minute).UnixMilli(),
		IssuedUnixMs:   t0.UnixMilli(),
		NodeId:         id,
		MeasurementId:  "m-2",
	}
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Job{Job: h.keys.signJob(t, anchorJob)}})
	anchorAck := gc.waitFor(t, "anchor job allowed while paused", func(e *nodev1.Envelope) bool {
		return e.GetJobAck() != nil && e.GetJobAck().GetJobId() == "j-anchor-allowed"
	}).GetJobAck()
	if !anchorAck.GetAccepted() {
		t.Fatalf("anchor job was refused during pause: %v", anchorAck)
	}
}

func TestHTTPPauseFetcherOverTLSAndURLValidation(t *testing.T) {
	_, priv := mustKey(t)
	payload := signPauseFile(t, priv, PauseDocument{
		Paused:      true,
		IssuedUnix:  t0.Unix(),
		ExpiresUnix: t0.Add(time.Hour).Unix(),
	})

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pause.json" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	client := newControlHTTPClient(&tls.Config{RootCAs: pool})
	f := NewHTTPPauseFetcher(srv.URL+"/pause.json", client)
	got, err := f.FetchPause(context.Background())
	if err != nil {
		t.Fatalf("FetchPause: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch")
	}

	// Unsafe schemes, userinfo, fragments, non-443 ports, never-ports, and
	// private/CGNAT/metadata IP literals must all be refused by validateControlURL.
	for _, bad := range []string{
		"http://pause.anchor.hopbits.io/pause.json",
		"file:///etc/passwd",
		"ftp://anchor.hopbits.io/pause.json",
		"https://user:pass@pause.anchor.hopbits.io/pause.json",
		"http://user@127.0.0.1:8080/pause.json",
		"https://pause.anchor.hopbits.io/pause.json#frag",
		"https://pause.anchor.hopbits.io:8443/pause.json",
		"https://127.0.0.1:22/pause.json",
		"http://127.0.0.1:6379/pause.json",
		"https://10.0.0.1/pause.json",
		"https://100.64.0.1/pause.json",
		"https://169.254.169.254/pause.json",
		"https://192.168.1.1/pause.json",
		"https://[fd00::1]/pause.json",
	} {
		bf := NewHTTPPauseFetcher(bad, client)
		if _, err := bf.FetchPause(context.Background()); err == nil {
			t.Errorf("accepted unsafe control URL %q", bad)
		}
	}

	// Verify newControlHTTPClient DialContext blocks DNS answers resolving a
	// non-loopback hostname to loopback, RFC1918, CGNAT, or metadata addresses.
	for _, deniedIP := range []string{
		"127.0.0.1",
		"::1",
		"10.1.2.3",
		"100.64.5.6",
		"169.254.169.254",
		"192.168.0.10",
	} {
		ip := netip.MustParseAddr(deniedIP)
		rebindClient := newControlHTTPClientWithLookup(&tls.Config{RootCAs: pool}, func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{ip}, nil
		})
		rf := NewHTTPPauseFetcher("https://rebind.anchor.hopbits.io/pause.json", rebindClient)
		if _, err := rf.FetchPause(context.Background()); err == nil {
			t.Errorf("control client allowed non-loopback hostname resolving to denied IP %s", deniedIP)
		}
	}
}

type fakePauseFetcher struct {
	get func() ([]byte, error)
}

func (f *fakePauseFetcher) FetchPause(context.Context) ([]byte, error) {
	return f.get()
}
