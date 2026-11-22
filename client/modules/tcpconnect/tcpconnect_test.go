package tcpconnect

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/modules/internal/kittest"
)

// fakeNet is a TargetNet whose DialTCP is scripted per sample.
type fakeNet struct {
	port     uint16
	verified bool
	// dial answers the n-th DialTCP call, counting from 0.
	dial func(ctx context.Context, n int) (net.Conn, error)

	mu        sync.Mutex
	dials     int
	deadlines []time.Duration
}

func (f *fakeNet) Host() string     { return "example.com" }
func (f *fakeNet) Port() uint16     { return f.port }
func (f *fakeNet) Addr() netip.Addr { return netip.MustParseAddr("127.0.0.1") }
func (f *fakeNet) Resolution() nodev1.ResolutionSource {
	return nodev1.ResolutionSource_RESOLUTION_SOURCE_SERVER
}
func (f *fakeNet) Verified() bool                 { return f.verified }
func (f *fakeNet) Pinger() (module.Pinger, error) { return nil, errors.New("fake: no ICMP") }
func (f *fakeNet) QueryDNS(context.Context, module.DNSQuery) (module.DNSReply, error) {
	return module.DNSReply{}, errors.New("fake: no DNS")
}
func (f *fakeNet) TraceHop(context.Context, string, int, int, time.Duration) (module.HopSample, error) {
	return module.HopSample{}, errors.New("fake: no trace")
}
func (f *fakeNet) CheckHTTP(string, string) error { return errors.New("fake: no HTTP") }
func (f *fakeNet) ProbeHeaders() http.Header      { return http.Header{} }

func (f *fakeNet) DialTCP(ctx context.Context) (net.Conn, error) {
	f.mu.Lock()
	n := f.dials
	f.dials++
	if d, ok := ctx.Deadline(); ok {
		f.deadlines = append(f.deadlines, time.Until(d))
	}
	f.mu.Unlock()
	return f.dial(ctx, n)
}

func (f *fakeNet) dialCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dials
}

// closeCounter is a connection that counts its Close calls.
type closeCounter struct {
	net.Conn
	mu     *sync.Mutex
	closed *int
}

func (c closeCounter) Close() error {
	c.mu.Lock()
	*c.closed++
	c.mu.Unlock()
	return c.Conn.Close()
}

// pipeConn returns one end of an in-memory connection.
func pipeConn(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { b.Close() })
	return a
}

var (
	errRefused     = &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	errUnreachable = &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("network is unreachable")}
)

func newJob(t *testing.T, port uint32, p *measurev1.TcpConnectParams, window time.Duration) *module.Job {
	t.Helper()
	b, err := proto.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now()
	return &module.Job{
		ID:          "job-1",
		Attempt:     1,
		Class:       nodev1.JobClass_JOB_CLASS_MEASURE,
		Kind:        Kind,
		KindVersion: Version,
		Target:      &nodev1.Target{Host: "example.com", Port: port, PinnedAddress: "127.0.0.1"},
		Params:      b,
		Issued:      issued,
		Deadline:    issued.Add(window),
	}
}

func decode(t *testing.T, r module.Result) *measurev1.TcpConnectResult {
	t.Helper()
	var res measurev1.TcpConnectResult
	if err := proto.Unmarshal(r.Data, &res); err != nil {
		t.Fatal(err)
	}
	return &res
}

func wantOutcome(t *testing.T, r module.Result, o nodev1.Outcome, code nodev1.ErrorCode) {
	t.Helper()
	if r.Outcome != o || r.Error != code {
		t.Fatalf("got outcome %v error %v, want %v %v", r.Outcome, r.Error, o, code)
	}
}

func TestModuleIdentity(t *testing.T) {
	m := New()
	if m.Kind() != "tcp_connect" || m.Version() != 1 || m.Class() != nodev1.JobClass_JOB_CLASS_MEASURE {
		t.Fatalf("identity %s v%d %v", m.Kind(), m.Version(), m.Class())
	}
	n := m.Needs()
	if n.Transport != module.TransportTCP || !slices.Equal(n.Ports, []uint16{443, 80}) {
		t.Fatalf("needs %+v", n)
	}
	// Needs returns a copy; changing it changes nothing.
	n.Ports[0] = 22
	if m.Needs().Ports[0] != 443 {
		t.Fatal("ports changed through Needs")
	}
}

func TestParseDefaults(t *testing.T) {
	p, err := parse(newJob(t, 443, &measurev1.TcpConnectParams{}, time.Minute), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.timeout != 5*time.Second || p.samples != 1 {
		t.Fatalf("defaults %+v", p)
	}
}

func TestCheckLimits(t *testing.T) {
	cases := []struct {
		name    string
		port    uint32
		params  *measurev1.TcpConnectParams
		window  time.Duration
		granted bool
		code    nodev1.ErrorCode
	}{
		{"defaults", 443, &measurev1.TcpConnectParams{}, time.Minute, false, 0},
		{"port 80", 80, &measurev1.TcpConnectParams{}, time.Minute, false, 0},
		{"timeout below minimum", 443, &measurev1.TcpConnectParams{TimeoutMs: 999}, time.Minute, false, nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS},
		{"timeout minimum", 443, &measurev1.TcpConnectParams{TimeoutMs: 1000}, time.Minute, false, 0},
		{"timeout maximum", 443, &measurev1.TcpConnectParams{TimeoutMs: 10000}, time.Minute, false, 0},
		{"timeout above maximum", 443, &measurev1.TcpConnectParams{TimeoutMs: 10001}, time.Minute, false, nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS},
		{"three samples", 443, &measurev1.TcpConnectParams{Samples: 3}, time.Minute, false, 0},
		{"four samples", 443, &measurev1.TcpConnectParams{Samples: 4}, time.Minute, false, nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS},
		{"deadline fits one default sample", 443, &measurev1.TcpConnectParams{}, 6 * time.Second, false, 0},
		{"deadline short of one sample", 443, &measurev1.TcpConnectParams{}, 5999 * time.Millisecond, false, nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS},
		{"deadline fits three samples", 443, &measurev1.TcpConnectParams{Samples: 3, TimeoutMs: 2000}, 9 * time.Second, false, 0},
		{"deadline short of three samples", 443, &measurev1.TcpConnectParams{Samples: 3, TimeoutMs: 2000}, 8999 * time.Millisecond, false, nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS},
		{"port 22 without grant", 22, &measurev1.TcpConnectParams{}, time.Minute, false, nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING},
		{"port 8443 without grant", 8443, &measurev1.TcpConnectParams{}, time.Minute, false, nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING},
		{"port 8443 with grant", 8443, &measurev1.TcpConnectParams{}, time.Minute, true, 0},
		{"port 0", 0, &measurev1.TcpConnectParams{}, time.Minute, true, nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS},
		{"port above 65535", 65536, &measurev1.TcpConnectParams{}, time.Minute, true, nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS},
	}
	m := New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := newJob(t, tc.port, tc.params, tc.window)
			if tc.granted {
				job.Target.Grant = &nodev1.SignedTargetGrant{Body: []byte("grant"), Sig: []byte("sig")}
			}
			err := m.Check(job)
			if tc.code == 0 {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || module.CodeOf(err) != tc.code {
				t.Fatalf("got %v, want code %v", err, tc.code)
			}
		})
	}
	job := newJob(t, 443, &measurev1.TcpConnectParams{}, time.Minute)
	job.Params = []byte{0x08}
	if module.CodeOf(m.Check(job)) != nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS {
		t.Fatal("truncated params accepted")
	}
}

func TestRunSamplesAgainstListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	var mu sync.Mutex
	closed := 0
	tn := &fakeNet{port: 443, dial: func(ctx context.Context, _ int) (net.Conn, error) {
		var d net.Dialer
		c, err := d.DialContext(ctx, "tcp", ln.Addr().String())
		if err != nil {
			return nil, err
		}
		return closeCounter{Conn: c, mu: &mu, closed: &closed}, nil
	}}
	clock := kittest.NewClock()
	m := &prober{clock: clock.Kit()}
	// The fake clock does not move during a dial; time the dial for real.
	m.clock.Now = time.Now

	r := m.Run(context.Background(), newJob(t, 443, &measurev1.TcpConnectParams{Samples: 3}, time.Minute), tn)
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_OK, 0)
	if r.TSSource != nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO {
		t.Fatalf("ts source %v", r.TSSource)
	}
	res := decode(t, r)
	if res.GetSucceeded() != 3 || len(res.GetConnectUs()) != 3 || res.GetMinUs() == 0 || res.GetMinUs() > res.GetMedianUs() {
		t.Fatalf("result %v", res)
	}
	for _, us := range res.GetConnectUs() {
		if us == 0 {
			t.Fatalf("successful sample reported as 0: %v", res.GetConnectUs())
		}
	}
	if got := clock.Sleeps(); !slices.Equal(got, []time.Duration{Gap, Gap}) {
		t.Fatalf("waits %v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if closed != 3 {
		t.Fatalf("%d connections closed, want 3", closed)
	}
}

// scripted returns a dial function that answers sample n with steps[n]:
// a connect that takes the given time on clock, or an error.
type step struct {
	took time.Duration
	err  error
}

func scripted(t *testing.T, clock *kittest.Clock, steps ...step) func(context.Context, int) (net.Conn, error) {
	return func(_ context.Context, n int) (net.Conn, error) {
		if n >= len(steps) {
			t.Errorf("dial %d not scripted", n)
			return nil, errUnreachable
		}
		clock.Advance(steps[n].took)
		if steps[n].err != nil {
			return nil, steps[n].err
		}
		return pipeConn(t), nil
	}
}

func TestRunStatistics(t *testing.T) {
	cases := []struct {
		name      string
		steps     []step
		outcome   nodev1.Outcome
		connect   []uint32
		succeeded uint32
		min, med  uint32
	}{
		{
			name:    "three successes",
			steps:   []step{{took: 300 * time.Microsecond}, {took: 100 * time.Microsecond}, {took: 200 * time.Microsecond}},
			outcome: nodev1.Outcome_OUTCOME_OK, connect: []uint32{300, 100, 200}, succeeded: 3, min: 100, med: 200,
		},
		{
			name:    "first refused, two succeed",
			steps:   []step{{err: errRefused}, {took: 400 * time.Microsecond}, {took: 200 * time.Microsecond}},
			outcome: nodev1.Outcome_OUTCOME_OK, connect: []uint32{0, 400, 200}, succeeded: 2, min: 200, med: 300,
		},
		{
			name:    "sub-microsecond connect still counts",
			steps:   []step{{took: 0}, {took: 0}, {took: 0}},
			outcome: nodev1.Outcome_OUTCOME_OK, connect: []uint32{1, 1, 1}, succeeded: 3, min: 1, med: 1,
		},
		{
			name:    "all fail, the last error decides",
			steps:   []step{{err: errRefused}, {err: errRefused}, {err: errUnreachable}},
			outcome: nodev1.Outcome_OUTCOME_UNREACHABLE, connect: []uint32{0, 0, 0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := kittest.NewClock()
			tn := &fakeNet{port: 443}
			tn.dial = scripted(t, clock, tc.steps...)
			r := (&prober{clock: clock.Kit()}).Run(context.Background(), newJob(t, 443, &measurev1.TcpConnectParams{Samples: 3}, time.Minute), tn)
			wantOutcome(t, r, tc.outcome, 0)
			res := decode(t, r)
			if !slices.Equal(res.GetConnectUs(), tc.connect) || res.GetSucceeded() != tc.succeeded ||
				res.GetMinUs() != tc.min || res.GetMedianUs() != tc.med {
				t.Fatalf("result %v", res)
			}
			wantTS := nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO
			if tc.succeeded == 0 {
				wantTS = nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE
			}
			if r.TSSource != wantTS {
				t.Fatalf("ts source %v", r.TSSource)
			}
		})
	}
}

func TestRunRefusedOnClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	tn := &fakeNet{port: 443, dial: func(ctx context.Context, _ int) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}}
	r := New().Run(context.Background(), newJob(t, 443, &measurev1.TcpConnectParams{}, time.Minute), tn)
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_REFUSED, 0)
	if res := decode(t, r); !slices.Equal(res.GetConnectUs(), []uint32{0}) || res.GetSucceeded() != 0 {
		t.Fatalf("result %v", res)
	}
	if r.TSSource != nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE {
		t.Fatalf("ts source %v", r.TSSource)
	}
}

func TestRunAppliesPerSampleTimeout(t *testing.T) {
	// The dial reports a timeout as net does; the context it got must end
	// after the per-sample timeout.
	tn := &fakeNet{port: 443, dial: func(ctx context.Context, _ int) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}
	}}
	clock := kittest.NewClock()
	r := (&prober{clock: clock.Kit()}).Run(context.Background(), newJob(t, 443, &measurev1.TcpConnectParams{TimeoutMs: 2000, Samples: 2}, time.Minute), tn)
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_TIMEOUT, 0)
	tn.mu.Lock()
	defer tn.mu.Unlock()
	if len(tn.deadlines) != 2 {
		t.Fatalf("%d dials", len(tn.deadlines))
	}
	for _, d := range tn.deadlines {
		if d <= 1500*time.Millisecond || d > 2*time.Second {
			t.Fatalf("dial context ends in %v, want about 2s", d)
		}
	}
}

func TestRunStopsAtJobDeadline(t *testing.T) {
	tn := &fakeNet{port: 443, dial: func(ctx context.Context, _ int) (net.Conn, error) {
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: ctx.Err()}
	}}
	job := newJob(t, 443, &measurev1.TcpConnectParams{}, time.Minute)
	job.Deadline = time.Now().Add(100 * time.Millisecond)
	job.Issued = job.Deadline.Add(-time.Minute)
	start := time.Now()
	r := New().Run(context.Background(), job, tn)
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_TIMEOUT, 0)
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("took %v", took)
	}
}

func TestRunRefusalStopsSampling(t *testing.T) {
	cases := []struct {
		err     error
		outcome nodev1.Outcome
		code    nodev1.ErrorCode
	}{
		{module.Refuse(nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL, "own network"),
			nodev1.Outcome_OUTCOME_DENIED_LOCAL, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL},
		{module.Refuse(nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED, "spacing"),
			nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE, nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED},
	}
	for _, tc := range cases {
		clock := kittest.NewClock()
		tn := &fakeNet{port: 443, dial: scripted(t, clock, step{err: tc.err})}
		r := (&prober{clock: clock.Kit()}).Run(context.Background(), newJob(t, 443, &measurev1.TcpConnectParams{Samples: 3}, time.Minute), tn)
		wantOutcome(t, r, tc.outcome, tc.code)
		if tn.dialCount() != 1 {
			t.Fatalf("%d dials after a refusal", tn.dialCount())
		}
	}
}

func TestRunCancelled(t *testing.T) {
	clock := kittest.NewClock()
	tn := &fakeNet{port: 443}
	tn.dial = scripted(t, clock, step{err: errRefused})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The first sample is refused; the job is cancelled in the wait.
	m := &prober{clock: clock.Kit()}
	m.clock.Sleep = func(ctx context.Context, d time.Duration) error {
		cancel()
		return clock.Sleep(ctx, d)
	}
	r := m.Run(ctx, newJob(t, 443, &measurev1.TcpConnectParams{Samples: 3}, time.Minute), tn)
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_CANCELLED, 0)
	if tn.dialCount() != 1 {
		t.Fatalf("%d dials", tn.dialCount())
	}
}

func TestRunEnforcesLimitsItself(t *testing.T) {
	clock := kittest.NewClock()
	cases := []struct {
		name string
		job  *module.Job
		tn   *fakeNet
		code nodev1.ErrorCode
	}{
		{"too many samples", newJob(t, 443, &measurev1.TcpConnectParams{Samples: 50}, time.Hour), &fakeNet{port: 443}, nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS},
		{"unverified port 22", func() *module.Job {
			j := newJob(t, 22, &measurev1.TcpConnectParams{}, time.Minute)
			j.Target.Grant = &nodev1.SignedTargetGrant{Body: []byte("grant"), Sig: []byte("forged")}
			return j
		}(), &fakeNet{port: 22}, nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.tn.dial = scripted(t, clock)
			r := (&prober{clock: clock.Kit()}).Run(context.Background(), tc.job, tc.tn)
			wantOutcome(t, r, nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE, tc.code)
			if tc.tn.dialCount() != 0 || r.Data != nil {
				t.Fatalf("%d dials, data %v", tc.tn.dialCount(), r.Data)
			}
		})
	}
	// A verified target may use another port; the safety layer still
	// applies the compiled never-list.
	tn := &fakeNet{port: 8443, verified: true}
	tn.dial = scripted(t, clock, step{took: time.Millisecond})
	job := newJob(t, 8443, &measurev1.TcpConnectParams{}, time.Minute)
	job.Target.Grant = &nodev1.SignedTargetGrant{Body: []byte("grant"), Sig: []byte("sig")}
	r := (&prober{clock: clock.Kit()}).Run(context.Background(), job, tn)
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_OK, 0)
}

type fakeProbe struct{ ipv6 bool }

func (p fakeProbe) ICMP(nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	return false, nodev1.TimestampSource_TIMESTAMP_SOURCE_UNSPECIFIED, ""
}
func (p fakeProbe) Trace(nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	return false, nodev1.TimestampSource_TIMESTAMP_SOURCE_UNSPECIFIED, ""
}
func (p fakeProbe) HasIPv6() bool { return p.ipv6 }

func TestSelfTest(t *testing.T) {
	for _, tc := range []struct {
		probe module.HostProbe
		want  string
	}{
		{fakeProbe{ipv6: false}, "measure.tcp_connect.v1:ipv4:ts.user"},
		{fakeProbe{ipv6: true}, "measure.tcp_connect.v1:ipv4:ipv6:ts.user"},
		{nil, "measure.tcp_connect.v1:ipv4:ts.user"},
	} {
		caps := New().SelfTest(context.Background(), module.Env{Probe: tc.probe})
		if len(caps) != 1 || caps[0].String() != tc.want {
			t.Fatalf("got %v, want %s", caps, tc.want)
		}
	}
}
