package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/protocol"
)

// t0 is the fake wall clock's start, inside the test certificates' window.
var t0 = time.Unix(1_800_000_000, 0)

// waitTimeout bounds every wait in these tests.
const waitTimeout = 10 * time.Second

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// fakeClock is a settable wall clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// testKeys is a root key and a root-certified dispatcher key.
type testKeys struct {
	rootPub   ed25519.PublicKey
	rootPriv  ed25519.PrivateKey
	dispPub   ed25519.PublicKey
	dispPriv  ed25519.PrivateKey
	dispCert  *nodev1.SignedKeyCertificate
	dispKeyID string
}

func newTestKeys(t *testing.T) *testKeys {
	t.Helper()
	k := &testKeys{}
	k.rootPub, k.rootPriv = mustKey(t)
	k.dispPub, k.dispPriv = mustKey(t)
	k.dispCert, k.dispKeyID = k.certify(t, k.dispPub, k.rootPriv)
	return k
}

// certify certifies pub as a dispatcher key with signer as root 0.
func (k *testKeys) certify(t *testing.T, pub ed25519.PublicKey, signer ed25519.PrivateKey) (*nodev1.SignedKeyCertificate, string) {
	t.Helper()
	cert := protocol.NewKeyCertificate(pub, nodev1.KeyRole_KEY_ROLE_DISPATCHER, t0.Add(-time.Hour), t0.Add(90*24*time.Hour))
	sc, err := protocol.CertifyKey(signer, 0, cert)
	if err != nil {
		t.Fatal(err)
	}
	return sc, cert.GetKeyId()
}

func (k *testKeys) signJob(t *testing.T, j *nodev1.Job) *nodev1.SignedJob {
	t.Helper()
	body, err := proto.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	return &nodev1.SignedJob{Body: body, Sig: protocol.Sign(k.dispPriv, protocol.PurposeJob, body), KeyId: k.dispKeyID}
}

func (k *testKeys) revocation(t *testing.T, keyIDs ...string) *nodev1.SignedRevocation {
	t.Helper()
	sr, err := protocol.SignRevocation(k.rootPriv, 0, &nodev1.Revocation{KeyIds: keyIDs, IssuedUnix: t0.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return sr
}

// fakeGateway is an in-process node endpoint driven by the test.
type fakeGateway struct {
	keys  *testKeys
	srv   *httptest.Server
	url   string
	conns chan *gwConn
	stop  chan struct{}

	mu  sync.Mutex
	all []*gwConn
}

func newFakeGateway(t *testing.T, keys *testKeys, useTLS bool) *fakeGateway {
	t.Helper()
	g := &fakeGateway{keys: keys, conns: make(chan *gwConn, 16), stop: make(chan struct{})}
	g.srv = httptest.NewUnstartedServer(http.HandlerFunc(g.handle))
	scheme := "ws"
	if useTLS {
		g.srv.StartTLS()
		scheme = "wss"
	} else {
		g.srv.Start()
	}
	g.url = scheme + "://" + g.srv.Listener.Addr().String() + protocol.Path
	t.Cleanup(g.close)
	return g
}

func (g *fakeGateway) close() {
	close(g.stop)
	g.mu.Lock()
	all := append([]*gwConn(nil), g.all...)
	g.mu.Unlock()
	for _, c := range all {
		_ = c.c.CloseNow()
	}
	g.srv.Close()
}

func (g *fakeGateway) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != protocol.Path {
		http.NotFound(w, r)
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(protocol.MaxFrameBytes)
	gc := &gwConn{c: c, frames: make(chan *nodev1.Envelope, 1024), done: make(chan struct{})}
	if r.TLS != nil {
		gc.exporter, _ = r.TLS.ExportKeyingMaterial(protocol.TLSExporterLabel, nil, protocol.TLSExporterLength)
	}
	g.mu.Lock()
	g.all = append(g.all, gc)
	g.mu.Unlock()
	go gc.readLoop()
	select {
	case g.conns <- gc:
	case <-g.stop:
		return
	}
	select {
	case <-gc.done:
	case <-g.stop:
	}
}

// accept waits for the agent's next connection.
func (g *fakeGateway) accept(t *testing.T) *gwConn {
	t.Helper()
	select {
	case gc := <-g.conns:
		return gc
	case <-time.After(waitTimeout):
		t.Fatal("timed out waiting for the agent to connect")
		return nil
	}
}

// noConnectionFor fails if the agent connects within d.
func (g *fakeGateway) noConnectionFor(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-g.conns:
		t.Fatal("the agent connected when it should have waited")
	case <-time.After(d):
	}
}

// gwConn is one accepted agent connection.
type gwConn struct {
	c        *websocket.Conn
	exporter []byte
	frames   chan *nodev1.Envelope
	done     chan struct{}

	mu  sync.Mutex
	seq uint64
}

func (gc *gwConn) readLoop() {
	defer close(gc.done)
	for {
		typ, b, err := gc.c.Read(context.Background())
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			continue
		}
		env, err := protocol.DecodeEnvelope(b)
		if err != nil {
			continue
		}
		gc.frames <- env
	}
}

var (
	errConnClosed = errors.New("connection closed")
	errWaitTimout = errors.New("timed out")
)

func (gc *gwConn) next(d time.Duration) (*nodev1.Envelope, error) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case env := <-gc.frames:
		return env, nil
	case <-gc.done:
		select {
		case env := <-gc.frames:
			return env, nil
		default:
			return nil, errConnClosed
		}
	case <-timer.C:
		return nil, errWaitTimout
	}
}

// waitFor returns the first frame that matches, skipping others.
func (gc *gwConn) waitFor(t *testing.T, what string, match func(*nodev1.Envelope) bool) *nodev1.Envelope {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		env, err := gc.next(time.Until(deadline))
		if err != nil {
			t.Fatalf("waiting for %s: %v", what, err)
		}
		if match(env) {
			return env
		}
	}
}

// expectClosed waits for the agent to close the connection and fails if a
// forbidden frame arrives first.
func (gc *gwConn) expectClosed(t *testing.T, forbidden func(*nodev1.Envelope) bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		env, err := gc.next(time.Until(deadline))
		switch {
		case errors.Is(err, errConnClosed):
			return
		case err != nil:
			t.Fatalf("waiting for the agent to close the connection: %v", err)
		case forbidden != nil && forbidden(env):
			t.Fatalf("unexpected frame before the close: %v", env)
		}
	}
}

func (gc *gwConn) send(t *testing.T, env *nodev1.Envelope) {
	t.Helper()
	gc.mu.Lock()
	gc.seq++
	env.Seq = gc.seq
	gc.mu.Unlock()
	b, err := protocol.EncodeEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	gc.sendRaw(t, b)
}

func (gc *gwConn) sendRaw(t *testing.T, b []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	if err := gc.c.Write(ctx, websocket.MessageBinary, b); err != nil {
		t.Fatalf("gateway write: %v", err)
	}
}

// hello waits for the agent's SignedHello and decodes it.
func (gc *gwConn) hello(t *testing.T) (*nodev1.Envelope, *nodev1.Hello) {
	t.Helper()
	env := gc.waitFor(t, "hello", func(e *nodev1.Envelope) bool { return e.GetHello() != nil })
	h := &nodev1.Hello{}
	if err := proto.Unmarshal(env.GetHello().GetBody(), h); err != nil {
		t.Fatal(err)
	}
	return env, h
}

// welcomeFor builds a valid Welcome answering h on this connection.
func (g *fakeGateway) welcomeFor(gc *gwConn, h *nodev1.Hello) *nodev1.Welcome {
	return &nodev1.Welcome{
		HelloNonce:         h.GetNonce(),
		TlsExporter:        gc.exporter,
		SessionId:          "session-1",
		HeartbeatIntervalS: 45,
		ServerTimeUnixMs:   t0.UnixMilli(),
		DispatcherCerts:    []*nodev1.SignedKeyCertificate{g.keys.dispCert},
		ObservedAddresses:  []string{"198.51.100.20", "[2001:db8::7]:51000"},
		Limits:             &nodev1.Limits{JobsPerMinute: 20},
		NodeId:             h.GetNodeId(),
	}
}

func signWelcome(t *testing.T, w *nodev1.Welcome, priv ed25519.PrivateKey, keyID string) *nodev1.SignedWelcome {
	t.Helper()
	body, err := proto.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	return &nodev1.SignedWelcome{Body: body, Sig: protocol.Sign(priv, protocol.PurposeWelcome, body), KeyId: keyID}
}

func (gc *gwConn) sendWelcome(t *testing.T, sw *nodev1.SignedWelcome) {
	t.Helper()
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Welcome{Welcome: sw}})
}

// establish completes the handshake and waits for the capability update and
// the consent state.
func (g *fakeGateway) establish(t *testing.T, gc *gwConn) *nodev1.Hello {
	t.Helper()
	_, h := gc.hello(t)
	gc.sendWelcome(t, signWelcome(t, g.welcomeFor(gc, h), g.keys.dispPriv, g.keys.dispKeyID))
	gc.waitFor(t, "capability update", func(e *nodev1.Envelope) bool { return e.GetCaps() != nil })
	gc.waitFor(t, "consent state", func(e *nodev1.Envelope) bool { return e.GetConsent() != nil })
	return h
}

func (gc *gwConn) sendJob(t *testing.T, sj *nodev1.SignedJob) {
	t.Helper()
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Job{Job: sj}})
}

func (gc *gwConn) jobAck(t *testing.T, jobID string) *nodev1.JobAck {
	t.Helper()
	return gc.waitFor(t, "job ack for "+jobID, func(e *nodev1.Envelope) bool {
		return e.GetJobAck().GetJobId() == jobID
	}).GetJobAck()
}

func (gc *gwConn) errorFrame(t *testing.T) *nodev1.Error {
	t.Helper()
	return gc.waitFor(t, "error frame", func(e *nodev1.Envelope) bool { return e.GetError() != nil }).GetError()
}

// result waits for the signed result of jobID and decodes it.
func (gc *gwConn) result(t *testing.T, jobID string) (*nodev1.SignedResult, *nodev1.Result) {
	t.Helper()
	for {
		env := gc.waitFor(t, "result for "+jobID, func(e *nodev1.Envelope) bool { return e.GetResult() != nil })
		r := &nodev1.Result{}
		if err := proto.Unmarshal(env.GetResult().GetBody(), r); err != nil {
			t.Fatal(err)
		}
		if r.GetJobId() == jobID {
			return env.GetResult(), r
		}
	}
}

// pingPong sends a Ping and waits for its Pong: every frame sent before it
// has then been handled by the agent's read loop.
func (gc *gwConn) pingPong(t *testing.T) (*nodev1.Envelope, *nodev1.Pong) {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	gc.send(t, &nodev1.Envelope{Body: &nodev1.Envelope_Ping{Ping: &nodev1.Ping{Nonce: nonce, ServerSendUnixMs: t0.UnixMilli()}}})
	env := gc.waitFor(t, "pong", func(e *nodev1.Envelope) bool {
		return e.GetPong() != nil && string(e.GetPong().GetNonce()) == string(nonce)
	})
	return env, env.GetPong()
}

// fakeGate is a permissive safety gate that records what it is told.
type fakeGate struct {
	mu          sync.Mutex
	refuse      nodev1.ErrorCode
	hold        chan struct{}
	entered     chan string
	admitted    int
	closed      int
	limits      []*nodev1.Limits
	ownCalls    int
	ownPrefixes []netip.Prefix
	ownObserved []netip.Addr
	refuse4     bool
	refuse6     bool
	refuseCalls int
	deny        []netip.Prefix
	denyCalls   int
	doNotProbe  [][]string
}

func (g *fakeGate) setRefuse(code nodev1.ErrorCode) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refuse = code
}

// holdAdmissions makes Admit report each job on entered and wait until
// release is closed.
func (g *fakeGate) holdAdmissions() (entered <-chan string, release chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.hold = make(chan struct{})
	g.entered = make(chan string, 16)
	return g.entered, g.hold
}

func (g *fakeGate) Admit(ctx context.Context, job *module.Job, _ module.Needs) (module.Lease, error) {
	g.mu.Lock()
	hold, entered := g.hold, g.entered
	g.mu.Unlock()
	if hold != nil {
		entered <- job.ID
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refuse != nodev1.ErrorCode_ERROR_CODE_UNSPECIFIED {
		return nil, module.Refuse(g.refuse, "refused by the test gate at 192.0.2.99")
	}
	addr, err := netip.ParseAddr(job.Target.GetPinnedAddress())
	if err != nil {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "no pinned address")
	}
	g.admitted++
	return &fakeLease{g: g, host: job.Target.GetHost(), port: uint16(job.Target.GetPort()), addr: addr}, nil
}

func (g *fakeGate) SetOwnNetwork(p []netip.Prefix, observed []netip.Addr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ownCalls++
	g.ownPrefixes, g.ownObserved = p, observed
}

func (g *fakeGate) ApplyLimits(l *nodev1.Limits) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.limits = append(g.limits, l)
}

func (g *fakeGate) AddDenyPrefixes(p []netip.Prefix) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.denyCalls++
	g.deny = append(g.deny, p...)
}

func (g *fakeGate) SetDoNotProbe(entries []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.doNotProbe = append(g.doNotProbe, entries)
}

func (g *fakeGate) HostProbe() module.HostProbe { return fakeProbe{} }

func (g *fakeGate) RefuseFamilies(ipv4, ipv6 bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refuseCalls++
	g.refuse4, g.refuse6 = ipv4, ipv6
}

func (g *fakeGate) snapshot() fakeGate {
	g.mu.Lock()
	defer g.mu.Unlock()
	return fakeGate{
		admitted: g.admitted, closed: g.closed, limits: g.limits, ownCalls: g.ownCalls,
		ownPrefixes: g.ownPrefixes, ownObserved: g.ownObserved,
		refuse4: g.refuse4, refuse6: g.refuse6, refuseCalls: g.refuseCalls,
		deny: g.deny, denyCalls: g.denyCalls, doNotProbe: g.doNotProbe,
	}
}

type fakeProbe struct{}

func (fakeProbe) ICMP(nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	return true, nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, "fake"
}

func (fakeProbe) Trace(nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	return true, nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, "fake"
}

func (fakeProbe) HasIPv6() bool { return false }

type fakeLease struct {
	g      *fakeGate
	host   string
	port   uint16
	addr   netip.Addr
	closed atomic.Bool
}

func (l *fakeLease) Host() string     { return l.host }
func (l *fakeLease) Port() uint16     { return l.port }
func (l *fakeLease) Addr() netip.Addr { return l.addr }
func (l *fakeLease) Resolution() nodev1.ResolutionSource {
	return nodev1.ResolutionSource_RESOLUTION_SOURCE_SERVER
}
func (l *fakeLease) Verified() bool { return false }
func (l *fakeLease) DialTCP(context.Context) (net.Conn, error) {
	return nil, errors.New("the fake lease does not dial")
}
func (l *fakeLease) Pinger() (module.Pinger, error) { return nil, errors.New("no ICMP in tests") }
func (l *fakeLease) QueryDNS(context.Context, module.DNSQuery) (module.DNSReply, error) {
	return module.DNSReply{}, errors.New("no DNS in tests")
}
func (l *fakeLease) TraceHop(context.Context, string, int, int, time.Duration) (module.HopSample, error) {
	return module.HopSample{}, errors.New("no trace in tests")
}
func (l *fakeLease) CheckHTTP(string, string) error { return nil }
func (l *fakeLease) ProbeHeaders() http.Header      { return http.Header{} }
func (l *fakeLease) Close() error {
	if !l.closed.Swap(true) {
		l.g.mu.Lock()
		l.g.closed++
		l.g.mu.Unlock()
	}
	return nil
}

// fakeModule is kind "fake" version 1. Params "bad" fail its check; with
// block set, Run waits for it to close or for the job to end.
type fakeModule struct {
	runs    atomic.Int32
	block   chan struct{}
	started chan string
}

func newFakeModule() *fakeModule { return &fakeModule{started: make(chan string, 64)} }

func (m *fakeModule) Kind() string           { return "fake" }
func (m *fakeModule) Version() uint32        { return 1 }
func (m *fakeModule) Class() nodev1.JobClass { return nodev1.JobClass_JOB_CLASS_MEASURE }
func (m *fakeModule) Needs() module.Needs {
	return module.Needs{Transport: module.TransportTCP, Ports: []uint16{443}}
}

func (m *fakeModule) SelfTest(context.Context, module.Env) []protocol.Capability {
	return []protocol.Capability{
		{Class: "measure", Kind: "fake", Version: 1, Qualifiers: []string{"ipv4"}},
		// A module may not claim another kind; the agent drops this.
		{Class: "measure", Kind: "other", Version: 1},
	}
}

func (m *fakeModule) Check(job *module.Job) error {
	if string(job.Params) == "bad" {
		return module.Refuse(nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS, "bad params")
	}
	return nil
}

func (m *fakeModule) Run(ctx context.Context, job *module.Job, tn module.TargetNet) module.Result {
	m.runs.Add(1)
	m.started <- job.ID
	if m.block != nil {
		select {
		case <-m.block:
		case <-ctx.Done():
			return module.Result{Outcome: nodev1.Outcome_OUTCOME_CANCELLED}
		}
	}
	if _, isLease := tn.(module.Lease); isLease {
		return module.Result{Outcome: nodev1.Outcome_OUTCOME_FAIL, Data: []byte("module saw the lease")}
	}
	return module.Result{
		Outcome:       nodev1.Outcome_OUTCOME_OK,
		TSSource:      nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO,
		ValidityFlags: uint32(nodev1.ValidityFlag_VALIDITY_FLAG_FRESH_CONNECTION),
		Data:          []byte("data:" + string(job.Params)),
	}
}

// harness wires an agent to a fake gateway, gate and module.
type harness struct {
	t     *testing.T
	keys  *testKeys
	gw    *fakeGateway
	gate  *fakeGate
	mod   *fakeModule
	clock *fakeClock
	dir   string
}

func newHarness(t *testing.T, useTLS bool) *harness {
	t.Helper()
	keys := newTestKeys(t)
	return &harness{
		t:     t,
		keys:  keys,
		gw:    newFakeGateway(t, keys, useTLS),
		gate:  &fakeGate{},
		mod:   newFakeModule(),
		clock: &fakeClock{t: t0},
		dir:   t.TempDir(),
	}
}

// interfacePrefixes is what the fake host reports.
var testInterfacePrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.168.1.0/24"),
	netip.MustParsePrefix("203.0.113.0/26"),
}

func (h *harness) config() Config {
	h.t.Helper()
	reg, err := module.NewRegistry(h.mod)
	if err != nil {
		h.t.Fatal(err)
	}
	cfg := Config{
		GatewayURL:      h.gw.url,
		DataDir:         h.dir,
		ClientVersion:   "1.2.3-test",
		NetworkMode:     nodev1.NetworkMode_NETWORK_MODE_NATIVE,
		EnrollmentToken: "enroll-token",
		Roots:           protocol.Roots{h.keys.rootPub},
		Registry:        reg,
		Gate:            h.gate,
		InterfacePrefixes: func() ([]netip.Prefix, error) {
			return append([]netip.Prefix(nil), testInterfacePrefixes...), nil
		},
		Logger:             testLogger(h.t),
		Now:                h.clock.Now,
		BackoffMin:         2 * time.Millisecond,
		BackoffMax:         20 * time.Millisecond,
		PausePollInterval:  -1,
		UpdatePollInterval: -1,
	}
	if h.gw.srv.TLS != nil {
		pool := x509.NewCertPool()
		pool.AddCert(h.gw.srv.Certificate())
		cfg.TLSConfig = &tls.Config{RootCAs: pool}
	}
	return cfg
}

// runningAgent is an agent whose Run is active.
type runningAgent struct {
	a      *Agent
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
	err    error
}

// start creates an agent, lets prepare adjust it, and runs it until the
// test ends or stop is called.
func (h *harness) start(cfg Config, prepare func(*Agent)) *runningAgent {
	h.t.Helper()
	a, err := New(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	if prepare != nil {
		prepare(a)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &runningAgent{a: a, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- a.Run(ctx) }()
	h.t.Cleanup(func() { r.stop(h.t) })
	return r
}

func (r *runningAgent) stop(t *testing.T) error {
	t.Helper()
	r.once.Do(func() {
		r.cancel()
		select {
		case r.err = <-r.done:
		case <-time.After(waitTimeout):
			t.Error("Run did not return after its context ended")
		}
	})
	return r.err
}

func (h *harness) nodeID(r *runningAgent) []byte {
	h.t.Helper()
	id, err := protocol.ParseNodeID(r.a.NodeID())
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}

// job builds a valid job for nodeID; mutate changes it before signing.
func (h *harness) job(nodeID []byte, id string, mutate func(*nodev1.Job)) *nodev1.SignedJob {
	h.t.Helper()
	j := &nodev1.Job{
		JobId:       id,
		Attempt:     1,
		JobClass:    nodev1.JobClass_JOB_CLASS_MEASURE,
		Kind:        "fake",
		KindVersion: 1,
		Params:      []byte("p"),
		Target: &nodev1.Target{
			Host:          "probe-target.example",
			Port:          443,
			Family:        nodev1.AddressFamily_ADDRESS_FAMILY_IPV4,
			PinnedAddress: "203.0.113.7",
		},
		DeadlineUnixMs: t0.Add(time.Minute).UnixMilli(),
		IssuedUnixMs:   t0.UnixMilli(),
		NodeId:         nodeID,
		MeasurementId:  "m-1",
	}
	if mutate != nil {
		mutate(j)
	}
	return h.keys.signJob(h.t, j)
}

func pendingFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, pendingDirName))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// waitUntil polls cond until it holds or the wait times out.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// testLogger logs through t until the test ends.
func testLogger(t *testing.T) *slog.Logger {
	w := &testWriter{t: t}
	t.Cleanup(func() {
		w.mu.Lock()
		w.off = true
		w.mu.Unlock()
	})
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type testWriter struct {
	mu  sync.Mutex
	t   *testing.T
	off bool
}

func (w *testWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.off {
		w.t.Log(strings.TrimRight(string(p), "\n"))
	}
	return len(p), nil
}
