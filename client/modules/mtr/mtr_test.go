package mtr

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

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/modules/internal/kittest"
)

type timeoutErr struct{}

func (timeoutErr) Error() string { return "timed out" }
func (timeoutErr) Timeout() bool { return true }

type fakeNet struct {
	dst   netip.Addr
	trace func(ctx context.Context, proto string, ttl, seq int, timeout time.Duration) (module.HopSample, error)
}

func (f *fakeNet) Host() string     { return f.dst.String() }
func (f *fakeNet) Port() uint16     { return 0 }
func (f *fakeNet) Addr() netip.Addr { return f.dst }
func (f *fakeNet) Resolution() nodev1.ResolutionSource {
	return nodev1.ResolutionSource_RESOLUTION_SOURCE_SERVER
}
func (f *fakeNet) Verified() bool { return false }
func (f *fakeNet) DialTCP(context.Context) (net.Conn, error) {
	return nil, errors.New("fake: no TCP")
}
func (f *fakeNet) Pinger() (module.Pinger, error) { return nil, errors.New("fake: no ICMP") }
func (f *fakeNet) QueryDNS(context.Context, module.DNSQuery) (module.DNSReply, error) {
	return module.DNSReply{}, errors.New("fake: no DNS")
}
func (f *fakeNet) TraceHop(ctx context.Context, proto string, ttl, seq int, timeout time.Duration) (module.HopSample, error) {
	return f.trace(ctx, proto, ttl, seq, timeout)
}
func (f *fakeNet) CheckHTTP(string, string) error { return errors.New("fake: no HTTP") }
func (f *fakeNet) ProbeHeaders() http.Header      { return http.Header{} }

func newJob(t *testing.T, p *measurev1.MtrParams, window time.Duration) *module.Job {
	t.Helper()
	b, err := measurev1.MarshalWire(p)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	return &module.Job{
		ID:          "job-mtr-1",
		Attempt:     1,
		Class:       nodev1.JobClass_JOB_CLASS_MEASURE,
		Kind:        Kind,
		KindVersion: Version,
		Target:      &nodev1.Target{Host: "1.1.1.1", PinnedAddress: "1.1.1.1"},
		Params:      b,
		Issued:      now,
		Deadline:    now.Add(window),
	}
}

func TestCheckValidation(t *testing.T) {
	m := New()
	if err := m.Check(newJob(t, &measurev1.MtrParams{}, 22*time.Second)); err != nil {
		t.Fatalf("default params refused: %v", err)
	}
	if err := m.Check(newJob(t, &measurev1.MtrParams{Protocol: "icmp", MaxHops: 30, Cycles: 10, TimeoutMs: 1500}, 22*time.Second)); err != nil {
		t.Fatalf("max params with 22s server window refused: %v", err)
	}
	for _, bad := range []*measurev1.MtrParams{
		{Protocol: "tcp"},
		{MaxHops: 3},
		{MaxHops: 31},
		{Cycles: 2},
		{Cycles: 11},
		{TimeoutMs: 299},
		{TimeoutMs: 1501},
	} {
		if err := m.Check(newJob(t, bad, time.Minute)); module.CodeOf(err) != nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS {
			t.Fatalf("expected INVALID_PARAMS for %+v, got %v", bad, err)
		}
	}
}

func TestRunCyclesLossAndSampleStdevMath(t *testing.T) {
	dst := netip.MustParseAddr("1.1.1.1")
	var mu sync.Mutex
	hopCounts := map[int]int{}
	// Hop 3 (destination) RTTs across 5 cycles: 10ms, 12ms, 14ms, 16ms, 18ms ->
	// mean = 14000µs, sample variance = ((16+4+0+4+16)*1e6)/4 = 10_000_000 -> stdev = 3162µs, last = 18000µs.
	dstRTTs := []time.Duration{
		10 * time.Millisecond,
		12 * time.Millisecond,
		14 * time.Millisecond,
		16 * time.Millisecond,
		18 * time.Millisecond,
	}

	tn := &fakeNet{
		dst: dst,
		trace: func(_ context.Context, _ string, ttl, _ int, _ time.Duration) (module.HopSample, error) {
			mu.Lock()
			c := hopCounts[ttl]
			hopCounts[ttl] = c + 1
			mu.Unlock()

			switch ttl {
			case 1:
				return module.HopSample{Redacted: true, RTT: time.Millisecond, Protocol: "udp"}, nil
			case 2:
				// Lose 2 of 5 probes -> 40.0% packet loss; 1 of 3 -> 33.3% test covered below.
				if c == 1 || c == 3 {
					return module.HopSample{Protocol: "udp"}, timeoutErr{}
				}
				return module.HopSample{Addr: netip.MustParseAddr("62.155.240.1"), RTT: 5 * time.Millisecond, Protocol: "udp"}, nil
			case 3:
				rtt := dstRTTs[min(c, len(dstRTTs)-1)]
				return module.HopSample{Addr: dst, Reached: true, RTT: rtt, Protocol: "udp"}, nil
			default:
				return module.HopSample{Addr: dst, Reached: true, RTT: 20 * time.Millisecond, Protocol: "udp"}, nil
			}
		},
	}

	clk := kittest.NewClock()
	m := &runner{clock: clk.Kit()}
	r := m.Run(context.Background(), newJob(t, &measurev1.MtrParams{Cycles: 5, MaxHops: 24}, time.Minute), tn)
	if r.Outcome != nodev1.Outcome_OUTCOME_OK {
		t.Fatalf("outcome = %v, want OUTCOME_OK", r.Outcome)
	}

	// Verify >= 80ms spacing between cycles 2..5 (4 cycle gaps).
	wantSleeps := []time.Duration{CycleGap, CycleGap, CycleGap, CycleGap}
	if !slices.Equal(clk.Sleeps(), wantSleeps) {
		t.Fatalf("cycle sleeps = %v, want %v", clk.Sleeps(), wantSleeps)
	}

	var res measurev1.MtrResult
	if err := measurev1.UnmarshalWire(r.Data, &res); err != nil {
		t.Fatal(err)
	}
	if !res.DestinationReached || res.Cycles != 5 || res.TotalHops != 3 || len(res.Hops) != 3 || res.RttUs != 14000 {
		t.Fatalf("unexpected MtrResult: %+v", res)
	}
	if !res.Hops[0].Redacted || res.Hops[0].IP != "" || res.Hops[0].LossPct != 0 {
		t.Fatalf("hop 1 = %+v", res.Hops[0])
	}
	if res.Hops[1].Sent != 5 || res.Hops[1].Received != 3 || res.Hops[1].LossPct != 40.0 {
		t.Fatalf("hop 2 loss math = %+v", res.Hops[1])
	}
	h3 := res.Hops[2]
	if h3.MinUs != 10000 || h3.AvgUs != 14000 || h3.MaxUs != 18000 || h3.LastUs != 18000 || h3.StdevUs != 3162 {
		t.Fatalf("hop 3 telemetry = %+v, want min=10000 avg=14000 max=18000 last=18000 stdev=3162", h3)
	}

	// Direct unit check on fractional rounding (1 lost of 3 sent -> 33.3%).
	w33 := buildMtrHopWire(2, &hopAccum{ip: "62.155.240.1", sent: 3, rtts: []uint32{5000, 5000}})
	if w33.LossPct != 33.3 || w33.StdevUs != 0 {
		t.Fatalf("1/3 loss rounding = %+v", w33)
	}
}
