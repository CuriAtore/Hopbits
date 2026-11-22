package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/protocol"
)

func TestHelloIsSignedByTheDeviceKey(t *testing.T) {
	h := newHarness(t, false)
	r := h.start(h.config(), nil)
	gc := h.gw.accept(t)
	env, hello := gc.hello(t)

	pub := ed25519.PublicKey(hello.GetPublicKey())
	sh := env.GetHello()
	if !protocol.Verify(pub, protocol.PurposeHello, sh.GetBody(), sh.GetSig()) {
		t.Fatal("Hello signature does not verify with its own public key")
	}
	if protocol.Verify(pub, protocol.PurposeResult, sh.GetBody(), sh.GetSig()) {
		t.Fatal("Hello signature verifies under another purpose")
	}
	key, err := LoadOrCreateKey(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(key.Public()) {
		t.Fatal("Hello carries a key other than the stored device key")
	}
	if !bytes.Equal(hello.GetNodeId(), protocol.NodeID(pub)) {
		t.Fatal("node id is not derived from the public key")
	}
	if got := protocol.NodeIDString(hello.GetNodeId()); got != r.a.NodeID() {
		t.Fatalf("Hello node id %s, agent reports %s", got, r.a.NodeID())
	}
	checks := []struct {
		name      string
		got, want any
	}{
		{"protocol version", hello.GetProtocolVersion(), uint32(protocol.Version)},
		{"client kind", hello.GetClientKind(), nodev1.ClientKind_CLIENT_KIND_AGENT},
		{"client version", hello.GetClientVersion(), "1.2.3-test"},
		{"os", hello.GetOs(), runtime.GOOS + "/" + runtime.GOARCH},
		{"network mode", hello.GetNetworkMode(), nodev1.NetworkMode_NETWORK_MODE_NATIVE},
		{"capabilities", strings.Join(hello.GetCapabilities(), ","), "measure.fake.v1:ipv4"},
		{"enrolment token", hello.GetEnrollmentToken(), "enroll-token"},
		{"timestamp", hello.GetTimestampUnixMs(), t0.UnixMilli()},
		{"nonce length", len(hello.GetNonce()), nonceSize},
		{"envelope version", env.GetV(), uint32(protocol.Version)},
		{"first seq", env.GetSeq(), uint64(1)},
		{"ack before any frame", env.GetAck(), uint64(0)},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}

	// A new connection says Hello again with a fresh nonce.
	_ = gc.c.CloseNow()
	_, again := h.gw.accept(t).hello(t)
	if bytes.Equal(again.GetNonce(), hello.GetNonce()) {
		t.Fatal("Hello nonce reused across connections")
	}
}

func TestSessionSetup(t *testing.T) {
	h := newHarness(t, false)
	h.start(h.config(), nil)
	gc := h.gw.accept(t)
	_, hello := gc.hello(t)
	gc.sendWelcome(t, signWelcome(t, h.gw.welcomeFor(gc, hello), h.keys.dispPriv, h.keys.dispKeyID))

	capsEnv := gc.waitFor(t, "capability update", func(e *nodev1.Envelope) bool { return e.GetCaps() != nil })
	caps := capsEnv.GetCaps()
	if got := strings.Join(caps.GetCapabilities(), ","); got != "measure.fake.v1:ipv4" {
		t.Errorf("capabilities %q", got)
	}
	if len(caps.GetSelfTests()) != 1 || !caps.GetSelfTests()[0].GetOk() ||
		caps.GetSelfTests()[0].GetFamily() != nodev1.AddressFamily_ADDRESS_FAMILY_IPV4 {
		t.Errorf("self-test results %v", caps.GetSelfTests())
	}
	// Private prefixes stay on the node; public ones go to the server.
	if got := strings.Join(caps.GetInterfacePrefixes(), ","); got != "203.0.113.0/26" {
		t.Errorf("interface prefixes sent to the server: %q", got)
	}
	if caps.GetNetworkMode() != nodev1.NetworkMode_NETWORK_MODE_NATIVE {
		t.Errorf("network mode %v", caps.GetNetworkMode())
	}
	if capsEnv.GetSeq() != 2 || capsEnv.GetAck() != 1 {
		t.Errorf("capability update seq %d ack %d, want 2 and 1", capsEnv.GetSeq(), capsEnv.GetAck())
	}

	consentEnv := gc.waitFor(t, "consent state", func(e *nodev1.Envelope) bool { return e.GetConsent() != nil })
	sc := consentEnv.GetConsent()
	if !protocol.Verify(ed25519.PublicKey(hello.GetPublicKey()), protocol.PurposeConsent, sc.GetBody(), sc.GetSig()) {
		t.Fatal("consent state signature does not verify")
	}
	cs := &nodev1.ConsentState{}
	if err := proto.Unmarshal(sc.GetBody(), cs); err != nil {
		t.Fatal(err)
	}
	if len(cs.GetClasses()) != 1 || cs.GetClasses()[0].GetJobClass() != nodev1.JobClass_JOB_CLASS_MEASURE ||
		cs.GetClasses()[0].GetGrantedUnix() != t0.Unix() {
		t.Errorf("consent classes %v", cs.GetClasses())
	}

	// The gate received the verified Welcome's limits and own network.
	gc.pingPong(t)
	g := h.gate.snapshot()
	if len(g.limits) != 1 || g.limits[0].GetJobsPerMinute() != 20 {
		t.Errorf("limits applied: %v", g.limits)
	}
	if g.ownCalls != 1 || !slices.Equal(g.ownPrefixes, testInterfacePrefixes) {
		t.Errorf("own network prefixes: %v (%d calls)", g.ownPrefixes, g.ownCalls)
	}
	if len(g.ownObserved) != 2 || g.ownObserved[0].String() != "198.51.100.20" || g.ownObserved[1].String() != "2001:db8::7" {
		t.Errorf("own network observed addresses: %v", g.ownObserved)
	}
	if g.refuseCalls != 1 || g.refuse4 || g.refuse6 {
		t.Errorf("refuse families: calls=%d refuse4=%v refuse6=%v", g.refuseCalls, g.refuse4, g.refuse6)
	}
}

func TestWelcomeRefuseFamilies(t *testing.T) {
	cases := []struct {
		name     string
		mode     nodev1.NetworkMode
		observed []string
		want4    bool
		want6    bool
	}{
		{
			name:     "bridge ipv4 only refuses ipv6",
			mode:     nodev1.NetworkMode_NETWORK_MODE_BRIDGE,
			observed: []string{"198.51.100.20:443"},
			want4:    false,
			want6:    true,
		},
		{
			name:     "rootless ipv4 only refuses ipv6",
			mode:     nodev1.NetworkMode_NETWORK_MODE_ROOTLESS,
			observed: []string{"198.51.100.20"},
			want4:    false,
			want6:    true,
		},
		{
			name:     "podman ipv4 only refuses ipv6",
			mode:     nodev1.NetworkMode_NETWORK_MODE_PODMAN,
			observed: []string{"198.51.100.20"},
			want4:    false,
			want6:    true,
		},
		{
			name:     "unspecified container mode ipv4 only refuses ipv6",
			mode:     nodev1.NetworkMode_NETWORK_MODE_UNSPECIFIED,
			observed: []string{"198.51.100.20"},
			want4:    false,
			want6:    true,
		},
		{
			name:     "host ipv4 only allows ipv6 via interface prefixes",
			mode:     nodev1.NetworkMode_NETWORK_MODE_HOST,
			observed: []string{"198.51.100.20"},
			want4:    false,
			want6:    false,
		},
		{
			name:     "native ipv4 only allows ipv6 via interface prefixes",
			mode:     nodev1.NetworkMode_NETWORK_MODE_NATIVE,
			observed: []string{"198.51.100.20"},
			want4:    false,
			want6:    false,
		},
		{
			name:     "bridge ipv6 only refuses ipv4 only",
			mode:     nodev1.NetworkMode_NETWORK_MODE_BRIDGE,
			observed: []string{"[2001:db8::7]:51000"},
			want4:    true,
			want6:    false,
		},
		{
			name:     "host empty observed refuses ipv4 only",
			mode:     nodev1.NetworkMode_NETWORK_MODE_HOST,
			observed: nil,
			want4:    true,
			want6:    false,
		},
		{
			name:     "bridge empty observed refuses both",
			mode:     nodev1.NetworkMode_NETWORK_MODE_BRIDGE,
			observed: nil,
			want4:    true,
			want6:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, false)
			cfg := h.config()
			cfg.NetworkMode = tc.mode
			h.start(cfg, nil)
			gc := h.gw.accept(t)
			_, hello := gc.hello(t)
			w := h.gw.welcomeFor(gc, hello)
			w.ObservedAddresses = tc.observed
			gc.sendWelcome(t, signWelcome(t, w, h.keys.dispPriv, h.keys.dispKeyID))
			gc.pingPong(t)
			g := h.gate.snapshot()
			if g.refuseCalls != 1 || g.refuse4 != tc.want4 || g.refuse6 != tc.want6 {
				t.Fatalf("RefuseFamilies: calls=%d got (%v, %v), want (%v, %v)",
					g.refuseCalls, g.refuse4, g.refuse6, tc.want4, tc.want6)
			}
		})
	}
}

func TestWelcomeRejected(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, h *harness, gc *gwConn, hello *nodev1.Hello) *nodev1.SignedWelcome
	}{
		{"bad signature", func(t *testing.T, h *harness, gc *gwConn, hello *nodev1.Hello) *nodev1.SignedWelcome {
			sw := signWelcome(t, h.gw.welcomeFor(gc, hello), h.keys.dispPriv, h.keys.dispKeyID)
			sw.Sig[0] ^= 1
			return sw
		}},
		{"tampered body", func(t *testing.T, h *harness, gc *gwConn, hello *nodev1.Hello) *nodev1.SignedWelcome {
			sw := signWelcome(t, h.gw.welcomeFor(gc, hello), h.keys.dispPriv, h.keys.dispKeyID)
			w := h.gw.welcomeFor(gc, hello)
			w.Limits = &nodev1.Limits{JobsPerMinute: 1000}
			sw.Body, _ = proto.Marshal(w)
			return sw
		}},
		{"wrong nonce", func(t *testing.T, h *harness, gc *gwConn, hello *nodev1.Hello) *nodev1.SignedWelcome {
			w := h.gw.welcomeFor(gc, hello)
			w.HelloNonce = bytes.Repeat([]byte{7}, nonceSize)
			return signWelcome(t, w, h.keys.dispPriv, h.keys.dispKeyID)
		}},
		{"missing nonce", func(t *testing.T, h *harness, gc *gwConn, hello *nodev1.Hello) *nodev1.SignedWelcome {
			w := h.gw.welcomeFor(gc, hello)
			w.HelloNonce = nil
			return signWelcome(t, w, h.keys.dispPriv, h.keys.dispKeyID)
		}},
		{"wrong node id", func(t *testing.T, h *harness, gc *gwConn, hello *nodev1.Hello) *nodev1.SignedWelcome {
			w := h.gw.welcomeFor(gc, hello)
			w.NodeId = bytes.Repeat([]byte{1}, protocol.NodeIDLength)
			return signWelcome(t, w, h.keys.dispPriv, h.keys.dispKeyID)
		}},
		{"key not certified by a root", func(t *testing.T, h *harness, gc *gwConn, hello *nodev1.Hello) *nodev1.SignedWelcome {
			pub, priv := mustKey(t)
			_, notRoot := mustKey(t)
			cert, keyID := h.keys.certify(t, pub, notRoot)
			w := h.gw.welcomeFor(gc, hello)
			w.DispatcherCerts = []*nodev1.SignedKeyCertificate{cert}
			return signWelcome(t, w, priv, keyID)
		}},
		{"revoked key", func(t *testing.T, h *harness, gc *gwConn, hello *nodev1.Hello) *nodev1.SignedWelcome {
			w := h.gw.welcomeFor(gc, hello)
			w.Revocations = []*nodev1.SignedRevocation{h.keys.revocation(t, h.keys.dispKeyID)}
			return signWelcome(t, w, h.keys.dispPriv, h.keys.dispKeyID)
		}},
		{"exporter on a connection without TLS", func(t *testing.T, h *harness, gc *gwConn, hello *nodev1.Hello) *nodev1.SignedWelcome {
			w := h.gw.welcomeFor(gc, hello)
			w.TlsExporter = bytes.Repeat([]byte{9}, protocol.TLSExporterLength)
			return signWelcome(t, w, h.keys.dispPriv, h.keys.dispKeyID)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, false)
			h.start(h.config(), nil)
			gc := h.gw.accept(t)
			_, hello := gc.hello(t)
			gc.sendWelcome(t, c.build(t, h, gc, hello))
			gc.expectClosed(t, func(e *nodev1.Envelope) bool { return e.GetCaps() != nil || e.GetConsent() != nil })

			g := h.gate.snapshot()
			if len(g.limits) != 0 || g.ownCalls != 0 {
				t.Fatalf("a rejected Welcome reached the gate: limits %v, own network calls %d", g.limits, g.ownCalls)
			}
			// The failure counts as a failed connect: the agent backs off and
			// tries again.
			h.gw.accept(t).hello(t)
		})
	}
}

func TestWelcomeTLSExporter(t *testing.T) {
	t.Run("matching exporter", func(t *testing.T) {
		h := newHarness(t, true)
		h.start(h.config(), nil)
		gc := h.gw.accept(t)
		if len(gc.exporter) != protocol.TLSExporterLength {
			t.Fatalf("gateway exporter has %d bytes", len(gc.exporter))
		}
		h.gw.establish(t, gc)
	})
	t.Run("exporter of another TLS session", func(t *testing.T) {
		h := newHarness(t, true)
		h.start(h.config(), nil)
		gc := h.gw.accept(t)
		_, hello := gc.hello(t)
		w := h.gw.welcomeFor(gc, hello)
		w.TlsExporter = bytes.Clone(gc.exporter)
		w.TlsExporter[0] ^= 1
		gc.sendWelcome(t, signWelcome(t, w, h.keys.dispPriv, h.keys.dispKeyID))
		gc.expectClosed(t, func(e *nodev1.Envelope) bool { return e.GetCaps() != nil })
	})
}

func TestJobProducesSignedResult(t *testing.T) {
	h := newHarness(t, false)
	r := h.start(h.config(), nil)
	gc := h.gw.accept(t)
	hello := h.gw.establish(t, gc)
	nodeID := h.nodeID(r)

	gc.sendJob(t, h.job(nodeID, "job-1", nil))
	if ack := gc.jobAck(t, "job-1"); !ack.GetAccepted() || ack.GetAttempt() != 1 {
		t.Fatalf("job not accepted: %v", ack)
	}
	sr, res := gc.result(t, "job-1")
	if !protocol.Verify(ed25519.PublicKey(hello.GetPublicKey()), protocol.PurposeResult, sr.GetBody(), sr.GetSig()) {
		t.Fatal("result signature does not verify with the device key")
	}
	want := &nodev1.Result{
		JobId:            "job-1",
		Attempt:          1,
		NodeId:           nodeID,
		Kind:             "fake",
		KindVersion:      1,
		Outcome:          nodev1.Outcome_OUTCOME_OK,
		TsSource:         nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO,
		ConnectedAddress: "203.0.113.7",
		Resolution:       nodev1.ResolutionSource_RESOLUTION_SOURCE_SERVER,
		Data:             []byte("data:p"),
		Load:             &nodev1.NodeLoad{RunningJobs: 1},
		NetworkMode:      nodev1.NetworkMode_NETWORK_MODE_NATIVE,
		ValidityFlags:    uint32(nodev1.ValidityFlag_VALIDITY_FLAG_FRESH_CONNECTION),
		ClientVersion:    "1.2.3-test",
		MeasuredUnixMs:   t0.UnixMilli(),
	}
	if !proto.Equal(res, want) {
		t.Fatalf("result\n got %v\nwant %v", res, want)
	}

	// The result waits in the buffer until the server acknowledges it.
	if files := pendingFiles(t, h.dir); len(files) != 1 {
		t.Fatalf("pending files before ResultAck: %v", files)
	}
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_ResultAck{ResultAck: &nodev1.ResultAck{JobId: "job-1", Attempt: 1}}})
	waitUntil(t, "the acknowledged result leaves the buffer", func() bool {
		return r.a.results.len() == 0 && len(pendingFiles(t, h.dir)) == 0
	})
	if g := h.gate.snapshot(); g.admitted != 1 || g.closed != 1 {
		t.Fatalf("gate admitted %d and closed %d leases, want 1 and 1", g.admitted, g.closed)
	}
	recs := r.a.jobLog.records()
	if len(recs) != 1 || recs[0].JobID != "job-1" || recs[0].Outcome != "OK" || recs[0].TargetHost != "probe-target.example" {
		t.Fatalf("job log %+v", recs)
	}
}

func TestJobRefusals(t *testing.T) {
	h := newHarness(t, false)
	logs := &syncBuffer{}
	cfg := h.config()
	cfg.Logger = slogTo(logs)
	r := h.start(cfg, nil)
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)
	nodeID := h.nodeID(r)

	cases := []struct {
		name   string
		mutate func(*nodev1.Job)
		code   nodev1.ErrorCode
	}{
		{"wrong node id", func(j *nodev1.Job) { j.NodeId = bytes.Repeat([]byte{2}, protocol.NodeIDLength) },
			nodev1.ErrorCode_ERROR_CODE_SIGNATURE_INVALID},
		{"deadline passed", func(j *nodev1.Job) { j.DeadlineUnixMs = t0.Add(-time.Second).UnixMilli() },
			nodev1.ErrorCode_ERROR_CODE_JOB_EXPIRED},
		{"deadline now", func(j *nodev1.Job) { j.DeadlineUnixMs = t0.UnixMilli() },
			nodev1.ErrorCode_ERROR_CODE_JOB_EXPIRED},
		{"no deadline", func(j *nodev1.Job) { j.DeadlineUnixMs = 0 },
			nodev1.ErrorCode_ERROR_CODE_JOB_EXPIRED},
		{"issued too far ahead", func(j *nodev1.Job) {
			j.IssuedUnixMs = t0.Add(121 * time.Second).UnixMilli()
			j.DeadlineUnixMs = t0.Add(5 * time.Minute).UnixMilli()
		}, nodev1.ErrorCode_ERROR_CODE_JOB_EXPIRED},
		{"class not enabled", func(j *nodev1.Job) { j.JobClass = nodev1.JobClass_JOB_CLASS_UNSPECIFIED },
			nodev1.ErrorCode_ERROR_CODE_CLASS_NOT_ENABLED},
		{"unknown kind", func(j *nodev1.Job) { j.Kind = "traceroute" },
			nodev1.ErrorCode_ERROR_CODE_KIND_UNSUPPORTED},
		{"unknown version", func(j *nodev1.Job) { j.KindVersion = 2 },
			nodev1.ErrorCode_ERROR_CODE_KIND_VERSION_UNSUPPORTED},
		{"params the module refuses", func(j *nodev1.Job) { j.Params = []byte("bad") },
			nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS},
	}
	for i, c := range cases {
		id := "refused-" + string(rune('a'+i))
		gc.sendJob(t, h.job(nodeID, id, c.mutate))
		ack := gc.jobAck(t, id)
		if ack.GetAccepted() || ack.GetError() != c.code {
			t.Errorf("%s: ack %v, want refusal %v", c.name, ack, c.code)
		}
	}

	// The gate has the last word on every target.
	h.gate.setRefuse(nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
	gc.sendJob(t, h.job(nodeID, "gate-refused", nil))
	if ack := gc.jobAck(t, "gate-refused"); ack.GetAccepted() || ack.GetError() != nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL {
		t.Errorf("gate refusal: ack %v", ack)
	}
	h.gate.setRefuse(nodev1.ErrorCode_ERROR_CODE_UNSPECIFIED)

	// A job whose signature fails is never parsed, so it gets an Error.
	bad := h.job(nodeID, "bad-sig", nil)
	bad.Sig[3] ^= 1
	gc.sendJob(t, bad)
	if e := gc.errorFrame(t); e.GetCode() != nodev1.ErrorCode_ERROR_CODE_SIGNATURE_INVALID {
		t.Errorf("bad signature: error %v", e)
	}
	unknownKey := h.job(nodeID, "unknown-key", nil)
	unknownKey.KeyId = "k-unknown"
	gc.sendJob(t, unknownKey)
	if e := gc.errorFrame(t); e.GetCode() != nodev1.ErrorCode_ERROR_CODE_SIGNATURE_INVALID {
		t.Errorf("unknown key: error %v", e)
	}
	// A job just inside the issue-time tolerance runs.
	gc.sendJob(t, h.job(nodeID, "issued-ahead", func(j *nodev1.Job) {
		j.IssuedUnixMs = t0.Add(119 * time.Second).UnixMilli()
		j.DeadlineUnixMs = t0.Add(5 * time.Minute).UnixMilli()
	}))
	if ack := gc.jobAck(t, "issued-ahead"); !ack.GetAccepted() {
		t.Errorf("job issued 119 s ahead refused: %v", ack)
	}
	gc.result(t, "issued-ahead")
	gc.pingPong(t)

	if n := h.mod.runs.Load(); n != 1 {
		t.Fatalf("module ran %d times, want only the accepted job", n)
	}
	if g := h.gate.snapshot(); g.admitted != 1 {
		t.Fatalf("gate admitted %d jobs, want 1", g.admitted)
	}
	refused := 0
	for _, rec := range r.a.jobLog.records() {
		if rec.Outcome == outcomeNotRun {
			refused++
		}
	}
	if refused != len(cases)+1 {
		t.Fatalf("job log holds %d refusals, want %d", refused, len(cases)+1)
	}
	// Refusal reasons can name addresses the node resolved; logs never do.
	if strings.Contains(logs.String(), "192.0.2.99") {
		t.Fatal("a refusal reason with an address reached the logs")
	}
	seed, err := os.ReadFile(filepath.Join(h.dir, keyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), strings.TrimSpace(string(seed))) {
		t.Fatal("the device key reached the logs")
	}
}

func TestConsentMissing(t *testing.T) {
	h := newHarness(t, false)
	r := h.start(h.config(), func(a *Agent) {
		// The operator withdrew consent for the measure class.
		delete(a.consent, nodev1.JobClass_JOB_CLASS_MEASURE)
	})
	gc := h.gw.accept(t)
	_, hello := gc.hello(t)
	if len(hello.GetCapabilities()) != 0 {
		t.Fatalf("capabilities advertised without consent: %v", hello.GetCapabilities())
	}
	gc.sendWelcome(t, signWelcome(t, h.gw.welcomeFor(gc, hello), h.keys.dispPriv, h.keys.dispKeyID))
	gc.waitFor(t, "consent state", func(e *nodev1.Envelope) bool { return e.GetConsent() != nil })

	gc.sendJob(t, h.job(h.nodeID(r), "no-consent", nil))
	if ack := gc.jobAck(t, "no-consent"); ack.GetAccepted() || ack.GetError() != nodev1.ErrorCode_ERROR_CODE_CONSENT_MISSING {
		t.Fatalf("ack %v, want CONSENT_MISSING", ack)
	}
	if h.mod.runs.Load() != 0 {
		t.Fatal("module ran without consent")
	}
}

func TestDuplicateJobRunsOnce(t *testing.T) {
	h := newHarness(t, false)
	h.mod.block = make(chan struct{})
	r := h.start(h.config(), nil)
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)
	sj := h.job(h.nodeID(r), "dup", nil)

	gc.sendJob(t, sj)
	if !gc.jobAck(t, "dup").GetAccepted() {
		t.Fatal("first copy refused")
	}
	waitStarted(t, h.mod, "dup")
	// A copy while the job runs is acknowledged again, not run.
	gc.sendJob(t, sj)
	if !gc.jobAck(t, "dup").GetAccepted() {
		t.Fatal("copy of a running job refused")
	}
	if _, pong := gc.pingPong(t); pong.GetRunningJobs() != 1 {
		t.Fatalf("pong reports %d running jobs, want 1", pong.GetRunningJobs())
	}
	close(h.mod.block)
	gc.result(t, "dup")
	// A copy after the job finished is acknowledged again, not run.
	gc.sendJob(t, sj)
	if !gc.jobAck(t, "dup").GetAccepted() {
		t.Fatal("copy of a finished job refused")
	}
	gc.pingPong(t)
	if n := h.mod.runs.Load(); n != 1 {
		t.Fatalf("module ran %d times, want 1", n)
	}
	if g := h.gate.snapshot(); g.admitted != 1 {
		t.Fatalf("gate charged %d admissions, want 1", g.admitted)
	}
}

func TestPingGetsPong(t *testing.T) {
	h := newHarness(t, false)
	h.start(h.config(), nil)
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)
	nonce := []byte("0123456789abcdef")
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Ping{Ping: &nodev1.Ping{Nonce: nonce}}})
	env := gc.waitFor(t, "pong", func(e *nodev1.Envelope) bool { return e.GetPong() != nil })
	pong := env.GetPong()
	if !bytes.Equal(pong.GetNonce(), nonce) {
		t.Fatalf("pong nonce %q, want %q", pong.GetNonce(), nonce)
	}
	if pong.GetNodeSendMonoNs() < pong.GetNodeRecvMonoNs() || pong.GetNodeRecvMonoNs() <= 0 {
		t.Fatalf("pong times recv %d send %d", pong.GetNodeRecvMonoNs(), pong.GetNodeSendMonoNs())
	}
	// Welcome was seq 1 and the Ping seq 2.
	if env.GetAck() != 2 {
		t.Fatalf("pong acks %d, want 2", env.GetAck())
	}
}

func TestUnknownFramesKeepTheSession(t *testing.T) {
	h := newHarness(t, false)
	h.start(h.config(), nil)
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)

	gc.send(t, &nodev1.Envelope{Channel: 3, Body: &nodev1.Envelope_Ping{Ping: &nodev1.Ping{Nonce: []byte("x")}}})
	if e := gc.errorFrame(t); e.GetCode() != nodev1.ErrorCode_ERROR_CODE_CLASS_NOT_ENABLED {
		t.Fatalf("reserved channel: %v", e)
	}
	gc.send(t, &nodev1.Envelope{})
	if e := gc.errorFrame(t); e.GetCode() != nodev1.ErrorCode_ERROR_CODE_UNSUPPORTED_MESSAGE {
		t.Fatalf("envelope without a body: %v", e)
	}
	// A body this client does not know arrives as an unknown field.
	unknown := protowireField(70, []byte{0x0a, 0x01, 'x'})
	gc.sendRaw(t, append(mustEncode(t, &nodev1.Envelope{V: 1}), unknown...))
	if e := gc.errorFrame(t); e.GetCode() != nodev1.ErrorCode_ERROR_CODE_UNSUPPORTED_MESSAGE {
		t.Fatalf("unknown body: %v", e)
	}
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Hello{Hello: &nodev1.SignedHello{}}})
	if e := gc.errorFrame(t); e.GetCode() != nodev1.ErrorCode_ERROR_CODE_UNSUPPORTED_MESSAGE {
		t.Fatalf("node-to-server message from the server: %v", e)
	}
	gc.sendRaw(t, []byte{0xff, 0xff, 0xff})
	if e := gc.errorFrame(t); e.GetCode() != nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION {
		t.Fatalf("garbage frame: %v", e)
	}
	gc.pingPong(t)
}

func TestJobInTheGateWhenTheSessionEnds(t *testing.T) {
	waitEntered := func(t *testing.T, entered <-chan string) {
		t.Helper()
		select {
		case <-entered:
		case <-time.After(waitTimeout):
			t.Fatal("the job never reached the gate")
		}
	}
	t.Run("not redelivered: dropped without running", func(t *testing.T) {
		h := newHarness(t, false)
		entered, release := h.gate.holdAdmissions()
		r := h.start(h.config(), nil)
		gc := h.gw.accept(t)
		h.gw.establish(t, gc)
		gc.sendJob(t, h.job(h.nodeID(r), "orphan", nil))
		waitEntered(t, entered)
		_ = gc.c.CloseNow()
		h.gw.establish(t, h.gw.accept(t))
		close(release)
		waitUntil(t, "the orphaned lease is closed", func() bool { return h.gate.snapshot().closed == 1 })
		if h.mod.runs.Load() != 0 {
			t.Fatal("a job whose session ended before its acknowledgement ran")
		}
	})
	t.Run("redelivered: answered on the new session", func(t *testing.T) {
		h := newHarness(t, false)
		entered, release := h.gate.holdAdmissions()
		r := h.start(h.config(), nil)
		gc := h.gw.accept(t)
		h.gw.establish(t, gc)
		sj := h.job(h.nodeID(r), "redelivered", nil)
		gc.sendJob(t, sj)
		waitEntered(t, entered)
		_ = gc.c.CloseNow()
		gc2 := h.gw.accept(t)
		h.gw.establish(t, gc2)
		gc2.sendJob(t, sj)
		gc2.pingPong(t)
		close(release)
		if !gc2.jobAck(t, "redelivered").GetAccepted() {
			t.Fatal("redelivered job refused")
		}
		gc2.result(t, "redelivered")
		if n := h.mod.runs.Load(); n != 1 {
			t.Fatalf("module ran %d times", n)
		}
	})
}

func TestJobCancel(t *testing.T) {
	h := newHarness(t, false)
	h.mod.block = make(chan struct{})
	r := h.start(h.config(), nil)
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)
	gc.sendJob(t, h.job(h.nodeID(r), "cancel-me", nil))
	if !gc.jobAck(t, "cancel-me").GetAccepted() {
		t.Fatal("job refused")
	}
	waitStarted(t, h.mod, "cancel-me")
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_JobCancel{JobCancel: &nodev1.JobCancel{JobId: "cancel-me", Attempt: 1}}})
	if _, res := gc.result(t, "cancel-me"); res.GetOutcome() != nodev1.Outcome_OUTCOME_CANCELLED {
		t.Fatalf("outcome %v, want CANCELLED", res.GetOutcome())
	}
}

func TestConfigUpdate(t *testing.T) {
	h := newHarness(t, false)
	r := h.start(h.config(), nil)
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)

	cu := &nodev1.ConfigUpdate{
		Limits:       &nodev1.Limits{MaxConcurrency: 2},
		DenyPrefixes: []string{"198.51.100.0/24", "not a prefix", "2001:db8::1", "198.51.100.0/24"},
		DoNotProbe:   []string{"opted-out.example", "192.0.2.0/24"},
	}
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Config{Config: cu}})
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Config{Config: &nodev1.ConfigUpdate{DenyPrefixes: []string{"198.51.100.0/24"}}}})
	gc.pingPong(t)

	g := h.gate.snapshot()
	if len(g.limits) != 2 || g.limits[1].GetMaxConcurrency() != 2 {
		t.Errorf("limits %v", g.limits)
	}
	var deny []string
	for _, p := range g.deny {
		deny = append(deny, p.String())
	}
	if strings.Join(deny, ",") != "198.51.100.0/24,2001:db8::1/128" || g.denyCalls != 1 {
		t.Errorf("deny prefixes %v in %d calls", deny, g.denyCalls)
	}
	if len(g.doNotProbe) != 1 || strings.Join(g.doNotProbe[0], ",") != "opted-out.example,192.0.2.0/24" {
		t.Errorf("do-not-probe %v", g.doNotProbe)
	}

	// A root-signed revocation withdraws the dispatcher key at once.
	rev := h.keys.revocation(t, h.keys.dispKeyID)
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Config{Config: &nodev1.ConfigUpdate{Revocations: []*nodev1.SignedRevocation{rev}}}})
	gc.sendJob(t, h.job(h.nodeID(r), "after-revocation", nil))
	if e := gc.errorFrame(t); e.GetCode() != nodev1.ErrorCode_ERROR_CODE_KEY_REVOKED {
		t.Fatalf("job from a revoked key: %v", e)
	}
	if h.mod.runs.Load() != 0 {
		t.Fatal("a job signed by a revoked key ran")
	}
}

func TestRevocationSurvivesRestart(t *testing.T) {
	h := newHarness(t, false)
	r := h.start(h.config(), nil)
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)
	rev := h.keys.revocation(t, h.keys.dispKeyID)
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Config{Config: &nodev1.ConfigUpdate{Revocations: []*nodev1.SignedRevocation{rev}}}})
	gc.pingPong(t)
	if err := r.stop(t); err == nil {
		t.Fatal("Run returned nil after its context ended")
	}

	// After a restart, a Welcome from the revoked key that omits the
	// revocation is still refused.
	h.start(h.config(), nil)
	gc2 := h.gw.accept(t)
	_, hello := gc2.hello(t)
	gc2.sendWelcome(t, signWelcome(t, h.gw.welcomeFor(gc2, hello), h.keys.dispPriv, h.keys.dispKeyID))
	gc2.expectClosed(t, func(e *nodev1.Envelope) bool { return e.GetCaps() != nil })
}

func TestResultsResentAfterReconnect(t *testing.T) {
	h := newHarness(t, false)
	r := h.start(h.config(), nil)
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)
	gc.sendJob(t, h.job(h.nodeID(r), "resend", nil))
	gc.jobAck(t, "resend")
	first, _ := gc.result(t, "resend")

	// The connection drops before the server acknowledges the result.
	_ = gc.c.CloseNow()
	gc2 := h.gw.accept(t)
	h.gw.establish(t, gc2)
	again, _ := gc2.result(t, "resend")
	if !bytes.Equal(again.GetBody(), first.GetBody()) || !bytes.Equal(again.GetSig(), first.GetSig()) {
		t.Fatal("the resent result differs from the original")
	}
	gc2.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_ResultAck{ResultAck: &nodev1.ResultAck{JobId: "resend", Attempt: 1}}})
	waitUntil(t, "the result leaves the buffer", func() bool { return len(pendingFiles(t, h.dir)) == 0 })
	if n := h.mod.runs.Load(); n != 1 {
		t.Fatalf("module ran %d times", n)
	}
}

func TestPendingResultsSurviveRestart(t *testing.T) {
	h := newHarness(t, false)
	r := h.start(h.config(), nil)
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)
	nodeID := h.nodeID(r)
	sj := h.job(nodeID, "durable", nil)
	gc.sendJob(t, sj)
	gc.jobAck(t, "durable")
	first, _ := gc.result(t, "durable")
	r.stop(t)

	r2 := h.start(h.config(), nil)
	if r2.a.NodeID() != r.a.NodeID() {
		t.Fatal("node id changed across a restart")
	}
	gc2 := h.gw.accept(t)
	h.gw.establish(t, gc2)
	again, _ := gc2.result(t, "durable")
	if !bytes.Equal(again.GetBody(), first.GetBody()) {
		t.Fatal("the resent result differs from the original")
	}
	// A replay of the job after the restart is acknowledged, not run.
	gc2.sendJob(t, sj)
	if !gc2.jobAck(t, "durable").GetAccepted() {
		t.Fatal("replayed job refused")
	}
	gc2.pingPong(t)
	if n := h.mod.runs.Load(); n != 1 {
		t.Fatalf("module ran %d times across the restart, want 1", n)
	}
}

func TestByeWindowIsHonoured(t *testing.T) {
	h := newHarness(t, false)
	waits := make(chan time.Duration, 16)
	// hook records every wait; the first `proceed` waits return at once and
	// later ones last until Run ends, so the agent never reconnects early.
	hook := func(proceed int32) func(*Agent) {
		var left atomic.Int32
		left.Store(proceed)
		return func(a *Agent) {
			a.sleep = func(ctx context.Context, d time.Duration) error {
				waits <- d
				if left.Add(-1) >= 0 {
					return nil
				}
				<-ctx.Done()
				return ctx.Err()
			}
			a.jitter = func(n time.Duration) time.Duration { return n / 2 }
		}
	}
	nextWait := func() time.Duration {
		t.Helper()
		select {
		case d := <-waits:
			return d
		case <-time.After(waitTimeout):
			t.Fatal("the agent did not wait")
			return 0
		}
	}

	r := h.start(h.config(), hook(0))
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Bye{Bye: &nodev1.Bye{
		Reason:        nodev1.ByeReason_BYE_REASON_CAPACITY,
		ReconnectMinS: 3600,
		ReconnectMaxS: 3600,
	}}})
	if d := nextWait(); d != time.Hour {
		t.Fatalf("waited %v after a one-hour Bye", d)
	}
	st := readState(t, h.dir)
	if st.ReconnectAfterUnixMs != t0.Add(time.Hour).UnixMilli() || st.ByeReason != "BYE_REASON_CAPACITY" {
		t.Fatalf("state.json %+v", st)
	}
	r.stop(t)

	// A restart inside the window waits for the rest of it.
	h.clock.Set(t0.Add(10 * time.Minute))
	h.start(h.config(), hook(1))
	if d := nextWait(); d != 50*time.Minute {
		t.Fatalf("waited %v after a restart inside the window, want 50m", d)
	}
	// A Bye in place of a Welcome is honoured too, drawn from its window.
	gc2 := h.gw.accept(t)
	gc2.hello(t)
	gc2.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Bye{Bye: &nodev1.Bye{
		Reason:        nodev1.ByeReason_BYE_REASON_DEPLOY,
		ReconnectMinS: 0,
		ReconnectMaxS: 120,
	}}})
	if d := nextWait(); d != time.Minute {
		t.Fatalf("waited %v for a 0-120 s window with mid-point jitter", d)
	}
}

func TestByeWindowBlocksReconnect(t *testing.T) {
	h := newHarness(t, false)
	h.start(h.config(), nil)
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Bye{Bye: &nodev1.Bye{
		Reason:        nodev1.ByeReason_BYE_REASON_DEPLOY,
		ReconnectMinS: 1,
		ReconnectMaxS: 1,
	}}})
	gc.expectClosed(t, nil)
	// The backoff alone would reconnect within 20 ms.
	h.gw.noConnectionFor(t, 600*time.Millisecond)
	h.gw.accept(t).hello(t)
}

func TestRunEndsWithItsContext(t *testing.T) {
	h := newHarness(t, false)
	h.mod.block = make(chan struct{})
	r := h.start(h.config(), nil)
	gc := h.gw.accept(t)
	h.gw.establish(t, gc)
	gc.sendJob(t, h.job(h.nodeID(r), "long", nil))
	gc.jobAck(t, "long")
	waitStarted(t, h.mod, "long")

	// A second Run while the first is active is refused at once.
	if err := r.a.Run(context.Background()); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("concurrent Run returned %v", err)
	}
	if err := r.stop(t); err != context.Canceled {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
	// The job stopped with Run and its result waits for the next session.
	if r.a.runningJobs() != 0 || r.a.results.len() != 1 {
		t.Fatalf("after Run: %d running jobs, %d buffered results", r.a.runningJobs(), r.a.results.len())
	}
}

func readState(t *testing.T, dir string) persistedState {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	var st persistedState
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func mustEncode(t *testing.T, env *nodev1.Envelope) []byte {
	t.Helper()
	b, err := protocol.EncodeEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// protowireField encodes a length-delimited field by hand, for field
// numbers the schema does not define.
func protowireField(num int, payload []byte) []byte {
	b := appendVarint(nil, uint64(num)<<3|2)
	b = appendVarint(b, uint64(len(payload)))
	return append(b, payload...)
}

func appendVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// slogTo logs everything to w.
func slogTo(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// waitStarted waits until the fake module starts jobID.
func waitStarted(t *testing.T, m *fakeModule, jobID string) {
	t.Helper()
	select {
	case id := <-m.started:
		if id != jobID {
			t.Fatalf("module started %q, want %q", id, jobID)
		}
	case <-time.After(waitTimeout):
		t.Fatalf("module did not start %q", jobID)
	}
}

func TestHelloTransmitsSanitizedAndTruncatedNodeLabel(t *testing.T) {
	t.Run("sanitized_label", func(t *testing.T) {
		h := newHarness(t, false)
		cfg := h.config()
		cfg.NodeLabel = "  \x00lon-pi4\x07\x7f\n  "
		h.start(cfg, nil)
		gc := h.gw.accept(t)
		env, hello := gc.hello(t)
		if got := hello.GetLabel(); got != "lon-pi4" {
			t.Fatalf("Hello.Label = %q, want lon-pi4", got)
		}
		pub := ed25519.PublicKey(hello.GetPublicKey())
		if !protocol.Verify(pub, protocol.PurposeHello, env.GetHello().GetBody(), env.GetHello().GetSig()) {
			t.Fatal("SignedHello signature did not verify")
		}
	})

	t.Run("80_rune_truncation_warns", func(t *testing.T) {
		h := newHarness(t, false)
		var logs syncBuffer
		cfg := h.config()
		cfg.Logger = slogTo(&logs)
		cfg.NodeLabel = strings.Repeat("あ", 88)
		h.start(cfg, nil)
		gc := h.gw.accept(t)
		_, hello := gc.hello(t)
		want := strings.Repeat("あ", 80)
		if got := hello.GetLabel(); got != want {
			t.Fatalf("Hello.Label runes = %d, want 80", len([]rune(got)))
		}
		if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "truncated") {
			t.Fatalf("expected WARN log on label truncation, got:\n%s", logs.String())
		}
	})
}
