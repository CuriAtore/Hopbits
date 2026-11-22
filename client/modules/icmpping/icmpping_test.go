package icmpping

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/modules/internal/kittest"
)

// noReply is the fake pinger's lost reply. Like the safety layer's, it
// reports Timeout, which says the request was sent.
type noReply struct{}

func (noReply) Error() string { return "fake: no reply" }
func (noReply) Timeout() bool { return true }

var errNoReply error = noReply{}

// sendFailure is the error of an echo request the socket could not send:
// the operating system's permission error when blocked, otherwise an
// unreachable network.
func sendFailure(blocked bool) error {
	if blocked {
		n := syscall.Errno(1) // EPERM
		if runtime.GOOS == "windows" {
			n = syscall.Errno(10013) // WSAEACCES
		}
		return fmt.Errorf("safety: send echo 1: %w", &net.OpError{Op: "write", Net: "ip4:icmp", Err: os.NewSyscallError("sendto", n)})
	}
	return fmt.Errorf("safety: send echo 1: %w", &net.OpError{Op: "write", Net: "ip4:icmp", Err: errors.New("network is unreachable")})
}

// script is the fake pinger's answer to one sequence number.
type script struct {
	rtt time.Duration
	ttl int
	err error
	// waitFor makes Echo wait until the echo with this sequence number has
	// been sent, or until ctx ends.
	waitFor uint16
}

// call is one Echo call.
type call struct {
	seq     uint16
	timeout time.Duration
}

// fakePinger answers echoes from a script. Unscripted packets are lost.
type fakePinger struct {
	ts      nodev1.TimestampSource
	replies map[uint16]script

	mu        sync.Mutex
	calls     []call
	active    int
	maxActive int
	closed    int
	started   map[uint16]chan struct{}
}

func newPinger(ts nodev1.TimestampSource, replies map[uint16]script) *fakePinger {
	return &fakePinger{ts: ts, replies: replies, started: make(map[uint16]chan struct{})}
}

// startedCh returns the channel closed when seq's echo is sent. The
// caller holds p.mu.
func (p *fakePinger) startedCh(seq uint16) chan struct{} {
	ch, ok := p.started[seq]
	if !ok {
		ch = make(chan struct{})
		p.started[seq] = ch
	}
	return ch
}

func (p *fakePinger) Echo(ctx context.Context, seq uint16, timeout time.Duration) (module.EchoReply, error) {
	p.mu.Lock()
	p.calls = append(p.calls, call{seq, timeout})
	p.active++
	p.maxActive = max(p.maxActive, p.active)
	close(p.startedCh(seq))
	s, scripted := p.replies[seq]
	var wait chan struct{}
	if s.waitFor != 0 {
		wait = p.startedCh(s.waitFor)
	}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
	}()

	if wait != nil {
		select {
		case <-wait:
		case <-ctx.Done():
			return module.EchoReply{}, ctx.Err()
		}
	}
	switch {
	case !scripted:
		return module.EchoReply{}, errNoReply
	case s.err != nil:
		return module.EchoReply{}, s.err
	}
	return module.EchoReply{RTT: s.rtt, TTL: s.ttl}, nil
}

func (p *fakePinger) TimestampSource() nodev1.TimestampSource { return p.ts }

func (p *fakePinger) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed++
	return nil
}

func (p *fakePinger) state() (calls []call, active, maxActive, closed int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.calls), p.active, p.maxActive, p.closed
}

// fakeNet is a TargetNet that only hands out a fake pinger.
type fakeNet struct {
	pinger *fakePinger
	err    error

	mu      sync.Mutex
	pingers int
}

func (f *fakeNet) Host() string     { return "192.0.2.1" }
func (f *fakeNet) Port() uint16     { return 0 }
func (f *fakeNet) Addr() netip.Addr { return netip.MustParseAddr("192.0.2.1") }
func (f *fakeNet) Resolution() nodev1.ResolutionSource {
	return nodev1.ResolutionSource_RESOLUTION_SOURCE_SERVER
}
func (f *fakeNet) Verified() bool { return false }
func (f *fakeNet) DialTCP(context.Context) (net.Conn, error) {
	return nil, errors.New("fake: no TCP")
}
func (f *fakeNet) QueryDNS(context.Context, module.DNSQuery) (module.DNSReply, error) {
	return module.DNSReply{}, errors.New("fake: no DNS")
}
func (f *fakeNet) TraceHop(context.Context, string, int, int, time.Duration) (module.HopSample, error) {
	return module.HopSample{}, errors.New("fake: no trace")
}
func (f *fakeNet) CheckHTTP(string, string) error { return errors.New("fake: no HTTP") }
func (f *fakeNet) ProbeHeaders() http.Header      { return http.Header{} }

func (f *fakeNet) Pinger() (module.Pinger, error) {
	f.mu.Lock()
	f.pingers++
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.pinger, nil
}

func newJob(t *testing.T, p *measurev1.IcmpPingParams, window time.Duration) *module.Job {
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
		Target:      &nodev1.Target{Host: "192.0.2.1", PinnedAddress: "192.0.2.1"},
		Params:      b,
		Issued:      issued,
		Deadline:    issued.Add(window),
	}
}

func decode(t *testing.T, r module.Result) *measurev1.IcmpPingResult {
	t.Helper()
	if r.Data == nil {
		t.Fatalf("result has no data: %+v", r)
	}
	var res measurev1.IcmpPingResult
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

func fast(clock *kittest.Clock) *pinger { return &pinger{clock: clock.Kit()} }

func TestModuleIdentity(t *testing.T) {
	m := New()
	if m.Kind() != "icmp_ping" || m.Version() != 1 || m.Class() != nodev1.JobClass_JOB_CLASS_MEASURE {
		t.Fatalf("identity %s v%d %v", m.Kind(), m.Version(), m.Class())
	}
	if n := m.Needs(); n.Transport != module.TransportICMP || len(n.Ports) != 0 {
		t.Fatalf("needs %+v", n)
	}
}

func TestParseDefaults(t *testing.T) {
	p, err := parse(newJob(t, &measurev1.IcmpPingParams{}, time.Minute), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.packets != 3 || p.interval != time.Second || p.timeout != 2*time.Second {
		t.Fatalf("defaults %+v", p)
	}
}

func TestCheckLimits(t *testing.T) {
	cases := []struct {
		name   string
		params *measurev1.IcmpPingParams
		window time.Duration
		ok     bool
	}{
		{"defaults fit exactly", &measurev1.IcmpPingParams{}, 5 * time.Second, true},
		{"defaults short by 1 ms", &measurev1.IcmpPingParams{}, 4999 * time.Millisecond, false},
		{"2 packets", &measurev1.IcmpPingParams{Packets: 2}, time.Minute, false},
		{"3 packets", &measurev1.IcmpPingParams{Packets: 3}, time.Minute, true},
		{"16 packets", &measurev1.IcmpPingParams{Packets: 16}, time.Minute, true},
		{"17 packets", &measurev1.IcmpPingParams{Packets: 17}, time.Minute, false},
		{"interval 199 ms", &measurev1.IcmpPingParams{IntervalMs: 199}, time.Minute, false},
		{"interval 200 ms", &measurev1.IcmpPingParams{IntervalMs: 200}, time.Minute, true},
		{"interval 5000 ms", &measurev1.IcmpPingParams{IntervalMs: 5000}, time.Minute, true},
		{"interval 5001 ms", &measurev1.IcmpPingParams{IntervalMs: 5001}, time.Minute, false},
		{"timeout 499 ms", &measurev1.IcmpPingParams{TimeoutMs: 499}, time.Minute, false},
		{"timeout 500 ms", &measurev1.IcmpPingParams{TimeoutMs: 500}, time.Minute, true},
		{"timeout 5000 ms", &measurev1.IcmpPingParams{TimeoutMs: 5000}, time.Minute, true},
		{"timeout 5001 ms", &measurev1.IcmpPingParams{TimeoutMs: 5001}, time.Minute, false},
		{"fastest job fits", &measurev1.IcmpPingParams{Packets: 16, IntervalMs: 200, TimeoutMs: 500}, 3700 * time.Millisecond, true},
		{"fastest job short", &measurev1.IcmpPingParams{Packets: 16, IntervalMs: 200, TimeoutMs: 500}, 3699 * time.Millisecond, false},
		{"slowest job fits", &measurev1.IcmpPingParams{Packets: 16, IntervalMs: 5000, TimeoutMs: 5000}, 85 * time.Second, true},
	}
	m := New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := m.Check(newJob(t, tc.params, tc.window))
			if tc.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !tc.ok && module.CodeOf(err) != nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS {
				t.Fatalf("got %v, want INVALID_PARAMS", err)
			}
		})
	}
	job := newJob(t, &measurev1.IcmpPingParams{}, time.Minute)
	job.Params = []byte("not a message")
	if module.CodeOf(m.Check(job)) != nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS {
		t.Fatal("garbage params accepted")
	}
	job = newJob(t, &measurev1.IcmpPingParams{}, time.Minute)
	job.Deadline = time.Time{}
	if m.Check(job) == nil {
		t.Fatal("job without a deadline accepted")
	}
}

func TestRunStatistics(t *testing.T) {
	pg := newPinger(nodev1.TimestampSource_TIMESTAMP_SOURCE_KERNEL_RX, map[uint16]script{
		1: {rtt: 10 * time.Millisecond, ttl: 57},
		2: {err: errNoReply},
		3: {rtt: 12 * time.Millisecond, ttl: 58},
		4: {rtt: 11 * time.Millisecond, ttl: 58},
	})
	clock := kittest.NewClock()
	params := &measurev1.IcmpPingParams{Packets: 4, IntervalMs: 200, TimeoutMs: 1000}
	r := fast(clock).Run(context.Background(), newJob(t, params, time.Minute), &fakeNet{pinger: pg})
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_OK, 0)
	if r.TSSource != nodev1.TimestampSource_TIMESTAMP_SOURCE_KERNEL_RX {
		t.Fatalf("ts source %v", r.TSSource)
	}
	res := decode(t, r)
	if res.GetSent() != 4 || res.GetReceived() != 3 || !slices.Equal(res.GetRttUs(), []uint32{10000, 0, 12000, 11000}) {
		t.Fatalf("result %v", res)
	}
	if res.GetMinUs() != 10000 || res.GetMedianUs() != 11000 || res.GetMaxUs() != 12000 || res.GetReplyTtl() != 57 {
		t.Fatalf("statistics %v", res)
	}

	calls, active, _, closed := pg.state()
	var seqs []uint16
	for _, c := range calls {
		seqs = append(seqs, c.seq)
		if c.timeout != time.Second {
			t.Fatalf("echo %d timeout %v", c.seq, c.timeout)
		}
	}
	slices.Sort(seqs)
	if !slices.Equal(seqs, []uint16{1, 2, 3, 4}) {
		t.Fatalf("sequence numbers %v", seqs)
	}
	if got := clock.Sleeps(); !slices.Equal(got, []time.Duration{200 * time.Millisecond, 200 * time.Millisecond, 200 * time.Millisecond}) {
		t.Fatalf("spacing %v", got)
	}
	if active != 0 || closed != 1 {
		t.Fatalf("%d echoes still running, pinger closed %d times", active, closed)
	}
}

func TestRunAllLost(t *testing.T) {
	pg := newPinger(nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, nil)
	r := fast(kittest.NewClock()).Run(context.Background(), newJob(t, &measurev1.IcmpPingParams{}, time.Minute), &fakeNet{pinger: pg})
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_TIMEOUT, 0)
	if r.TSSource != nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE {
		t.Fatalf("a failure carries a timestamp source: %v", r.TSSource)
	}
	res := decode(t, r)
	if res.GetSent() != 3 || res.GetReceived() != 0 || !slices.Equal(res.GetRttUs(), []uint32{0, 0, 0}) ||
		res.GetMinUs() != 0 || res.GetMedianUs() != 0 || res.GetMaxUs() != 0 || res.GetReplyTtl() != 0 {
		t.Fatalf("result %v", res)
	}
}

func TestRunWithoutPinger(t *testing.T) {
	tn := &fakeNet{err: errors.New("no ICMP socket")}
	r := fast(kittest.NewClock()).Run(context.Background(), newJob(t, &measurev1.IcmpPingParams{}, time.Minute), tn)
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE, nodev1.ErrorCode_ERROR_CODE_PERMISSION_WITHHELD)
	if r.Data != nil || r.TSSource != nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE {
		t.Fatalf("result %+v", r)
	}
}

func TestRunOverlapsWaits(t *testing.T) {
	// Packet 1 gets its reply only after packet 3 has been sent, as when the
	// round trip is longer than the interval, and packet 3 only once packet
	// 1 is out. Sending one packet at a time would lose packet 1, and the
	// two echoes are always in flight together.
	pg := newPinger(nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, map[uint16]script{
		1: {rtt: 450 * time.Millisecond, ttl: 50, waitFor: 3},
		2: {rtt: 440 * time.Millisecond, ttl: 50},
		3: {rtt: 430 * time.Millisecond, ttl: 50, waitFor: 1},
	})
	job := newJob(t, &measurev1.IcmpPingParams{IntervalMs: 200, TimeoutMs: 500}, time.Minute)
	job.Deadline = time.Now().Add(5 * time.Second)
	job.Issued = job.Deadline.Add(-time.Minute)
	r := fast(kittest.NewClock()).Run(context.Background(), job, &fakeNet{pinger: pg})
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_OK, 0)
	if res := decode(t, r); res.GetReceived() != 3 {
		t.Fatalf("result %v", res)
	}
	if _, active, maxActive, _ := pg.state(); maxActive < 2 || active != 0 {
		t.Fatalf("max %d echoes at once, %d still running", maxActive, active)
	}
}

func TestRunCancelled(t *testing.T) {
	t.Run("before the first packet", func(t *testing.T) {
		pg := newPinger(nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := fast(kittest.NewClock()).Run(ctx, newJob(t, &measurev1.IcmpPingParams{}, time.Minute), &fakeNet{pinger: pg})
		wantOutcome(t, r, nodev1.Outcome_OUTCOME_CANCELLED, 0)
		calls, _, _, closed := pg.state()
		if len(calls) != 0 || closed != 1 || decode(t, r).GetSent() != 0 {
			t.Fatalf("%d echoes sent, pinger closed %d times", len(calls), closed)
		}
	})
	t.Run("between packets", func(t *testing.T) {
		pg := newPinger(nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		clock := kittest.NewClock()
		m := fast(clock)
		sleeps := 0
		m.clock.Sleep = func(ctx context.Context, d time.Duration) error {
			if sleeps++; sleeps == 2 {
				cancel()
			}
			return clock.Sleep(ctx, d)
		}
		r := m.Run(ctx, newJob(t, &measurev1.IcmpPingParams{Packets: 5}, time.Minute), &fakeNet{pinger: pg})
		wantOutcome(t, r, nodev1.Outcome_OUTCOME_CANCELLED, 0)
		if res := decode(t, r); res.GetSent() != 2 || len(res.GetRttUs()) != 2 {
			t.Fatalf("result %v", res)
		}
	})
}

func TestRunEchoRefusals(t *testing.T) {
	rate := module.Refuse(nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED, "ICMP rate cap")
	t.Run("all refused", func(t *testing.T) {
		pg := newPinger(nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, map[uint16]script{
			1: {err: rate}, 2: {err: rate}, 3: {err: rate},
		})
		r := fast(kittest.NewClock()).Run(context.Background(), newJob(t, &measurev1.IcmpPingParams{}, time.Minute), &fakeNet{pinger: pg})
		wantOutcome(t, r, nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE, nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED)
		if res := decode(t, r); res.GetSent() != 0 {
			t.Fatalf("result %v", res)
		}
	})
	t.Run("one refused", func(t *testing.T) {
		pg := newPinger(nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, map[uint16]script{
			1: {rtt: 5 * time.Millisecond, ttl: 60}, 2: {err: rate}, 3: {rtt: 7 * time.Millisecond, ttl: 60},
		})
		r := fast(kittest.NewClock()).Run(context.Background(), newJob(t, &measurev1.IcmpPingParams{}, time.Minute), &fakeNet{pinger: pg})
		wantOutcome(t, r, nodev1.Outcome_OUTCOME_OK, 0)
		res := decode(t, r)
		if res.GetSent() != 2 || res.GetReceived() != 2 || !slices.Equal(res.GetRttUs(), []uint32{5000, 7000}) {
			t.Fatalf("result %v", res)
		}
	})
}

func TestRunFailedSendsAreNotLosses(t *testing.T) {
	cases := []struct {
		name    string
		blocked bool
		outcome nodev1.Outcome
		code    nodev1.ErrorCode
	}{
		{"firewall refuses ICMP", true, nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY},
		{"no route", false, nodev1.Outcome_OUTCOME_UNREACHABLE, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fail := sendFailure(tc.blocked)
			pg := newPinger(nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, map[uint16]script{
				1: {err: fail}, 2: {err: fail}, 3: {err: fail},
			})
			r := fast(kittest.NewClock()).Run(context.Background(), newJob(t, &measurev1.IcmpPingParams{}, time.Minute), &fakeNet{pinger: pg})
			wantOutcome(t, r, tc.outcome, tc.code)
			if res := decode(t, r); res.GetSent() != 0 || len(res.GetRttUs()) != 0 {
				t.Fatalf("unsent echoes reported as sent: %v", res)
			}
		})
	}
	t.Run("some sent", func(t *testing.T) {
		// Echoes the rate cap or a failed send kept back are left out, not
		// reported as lost: the target answered every echo that left.
		rate := module.Refuse(nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED, "no send slot")
		pg := newPinger(nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, map[uint16]script{
			1: {rtt: 5 * time.Millisecond, ttl: 60}, 2: {err: rate}, 3: {err: sendFailure(false)}, 4: {rtt: 6 * time.Millisecond, ttl: 60},
		})
		r := fast(kittest.NewClock()).Run(context.Background(), newJob(t, &measurev1.IcmpPingParams{Packets: 4}, time.Minute), &fakeNet{pinger: pg})
		wantOutcome(t, r, nodev1.Outcome_OUTCOME_OK, 0)
		if res := decode(t, r); res.GetSent() != 2 || res.GetReceived() != 2 || !slices.Equal(res.GetRttUs(), []uint32{5000, 6000}) {
			t.Fatalf("result %v", res)
		}
	})
}

func TestRunZeroRTTCountsAsReply(t *testing.T) {
	pg := newPinger(nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, map[uint16]script{
		1: {rtt: 0, ttl: 64}, 2: {rtt: 0, ttl: 64}, 3: {rtt: 0, ttl: 64},
	})
	r := fast(kittest.NewClock()).Run(context.Background(), newJob(t, &measurev1.IcmpPingParams{}, time.Minute), &fakeNet{pinger: pg})
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_OK, 0)
	if res := decode(t, r); res.GetReceived() != 3 || !slices.Equal(res.GetRttUs(), []uint32{1, 1, 1}) {
		t.Fatalf("result %v", res)
	}
}

func TestRunEnforcesLimitsItself(t *testing.T) {
	for _, params := range []*measurev1.IcmpPingParams{
		{Packets: 100},
		{IntervalMs: 10},
		{TimeoutMs: 60_000},
	} {
		pg := newPinger(nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, nil)
		tn := &fakeNet{pinger: pg}
		r := fast(kittest.NewClock()).Run(context.Background(), newJob(t, params, time.Hour), tn)
		wantOutcome(t, r, nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE, nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS)
		if calls, _, _, _ := pg.state(); len(calls) != 0 || tn.pingers != 0 {
			t.Fatalf("%v: %d echoes, %d pingers", params, len(calls), tn.pingers)
		}
	}
}

func TestRunStopsAtJobDeadline(t *testing.T) {
	// Every echo waits for a packet that is never sent, so only the job's
	// deadline ends the run. The real clock spaces the packets.
	pg := newPinger(nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, map[uint16]script{
		1: {waitFor: 99}, 2: {waitFor: 99}, 3: {waitFor: 99},
	})
	job := newJob(t, &measurev1.IcmpPingParams{IntervalMs: 200, TimeoutMs: 500}, time.Minute)
	job.Deadline = time.Now().Add(300 * time.Millisecond)
	job.Issued = job.Deadline.Add(-time.Minute)
	start := time.Now()
	r := New().Run(context.Background(), job, &fakeNet{pinger: pg})
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("took %v", took)
	}
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_TIMEOUT, 0)
	calls, active, _, closed := pg.state()
	if len(calls) != 2 || active != 0 || closed != 1 {
		t.Fatalf("%d echoes sent, %d still running, closed %d times", len(calls), active, closed)
	}
}

func TestTTLClamp(t *testing.T) {
	for in, want := range map[int]uint32{-1: 0, 0: 0, 64: 64, 255: 255, 300: 255} {
		if got := ttl(in); got != want {
			t.Errorf("ttl(%d) = %d, want %d", in, got, want)
		}
	}
}

// fakeProbe answers ICMP questions per family.
type fakeProbe struct {
	ipv6  bool
	v4ok  bool
	v4ts  nodev1.TimestampSource
	v6ok  bool
	v6ts  nodev1.TimestampSource
	asked *[]nodev1.AddressFamily
}

func (p fakeProbe) ICMP(f nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	if p.asked != nil {
		*p.asked = append(*p.asked, f)
	}
	if f == nodev1.AddressFamily_ADDRESS_FAMILY_IPV4 {
		return p.v4ok, p.v4ts, ""
	}
	return p.v6ok, p.v6ts, ""
}
func (p fakeProbe) Trace(nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	return false, nodev1.TimestampSource_TIMESTAMP_SOURCE_UNSPECIFIED, ""
}
func (p fakeProbe) HasIPv6() bool { return p.ipv6 }

func TestSelfTest(t *testing.T) {
	kernel := nodev1.TimestampSource_TIMESTAMP_SOURCE_KERNEL_RX
	user := nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO
	cases := []struct {
		name string
		env  module.Env
		want []string
	}{
		{"both families", module.Env{Probe: fakeProbe{ipv6: true, v4ok: true, v4ts: kernel, v6ok: true, v6ts: user}},
			[]string{"measure.icmp_ping.v1:ipv4:ts.kernel", "measure.icmp_ping.v1:ipv6:ts.user"}},
		{"no global IPv6", module.Env{Probe: fakeProbe{ipv6: false, v4ok: true, v4ts: user, v6ok: true, v6ts: user}},
			[]string{"measure.icmp_ping.v1:ipv4:ts.user"}},
		{"IPv4 fails", module.Env{Probe: fakeProbe{ipv6: true, v6ok: true, v6ts: kernel}},
			[]string{"measure.icmp_ping.v1:ipv6:ts.kernel"}},
		{"Windows API timing", module.Env{Probe: fakeProbe{v4ok: true, v4ts: nodev1.TimestampSource_TIMESTAMP_SOURCE_OS_API_MS}},
			[]string{"measure.icmp_ping.v1:ipv4:ts.osms"}},
		{"untimed", module.Env{Probe: fakeProbe{v4ok: true, v4ts: nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE}}, nil},
		{"Docker Desktop", module.Env{NetworkMode: nodev1.NetworkMode_NETWORK_MODE_DOCKER_DESKTOP,
			Probe: fakeProbe{v4ok: true, v4ts: user}}, nil},
		{"no probe", module.Env{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, c := range New().SelfTest(context.Background(), tc.env) {
				got = append(got, c.String())
			}
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}

	var asked []nodev1.AddressFamily
	New().SelfTest(context.Background(), module.Env{Probe: fakeProbe{ipv6: false, v4ok: true, v4ts: user, asked: &asked}})
	if !slices.Equal(asked, []nodev1.AddressFamily{nodev1.AddressFamily_ADDRESS_FAMILY_IPV4}) {
		t.Fatalf("asked about %v", asked)
	}
}
