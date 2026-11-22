package traceroute

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
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

func newJob(t *testing.T, p *measurev1.TracerouteParams, window time.Duration) *module.Job {
	t.Helper()
	b, err := measurev1.MarshalWire(p)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	return &module.Job{
		ID:          "job-tr-1",
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
	if err := m.Check(newJob(t, &measurev1.TracerouteParams{}, 18*time.Second)); err != nil {
		t.Fatalf("default params with 18s server window refused: %v", err)
	}
	if err := m.Check(newJob(t, &measurev1.TracerouteParams{Protocol: "icmp", MaxHops: 30, Probes: 3, TimeoutMs: 2000}, 18*time.Second)); err != nil {
		t.Fatalf("max params with 18s server window refused: %v", err)
	}
	for _, bad := range []*measurev1.TracerouteParams{
		{Protocol: "tcp"},
		{MaxHops: 3},
		{MaxHops: 31},
		{Probes: 4},
		{TimeoutMs: 299},
		{TimeoutMs: 2001},
	} {
		if err := m.Check(newJob(t, bad, time.Minute)); module.CodeOf(err) != nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS {
			t.Fatalf("expected INVALID_PARAMS for %+v, got %v", bad, err)
		}
	}
}

func TestRunTrimsAtDestinationAndPreservesRedaction(t *testing.T) {
	dst := netip.MustParseAddr("1.1.1.1")
	tn := &fakeNet{
		dst: dst,
		trace: func(_ context.Context, _ string, ttl, seq int, _ time.Duration) (module.HopSample, error) {
			// Simulate ICMP falling back to UDP on host without ping_group_range.
			switch ttl {
			case 1:
				return module.HopSample{Redacted: true, RTT: 800 * time.Microsecond, Protocol: "udp"}, nil
			case 2:
				// Middle probe lost!
				if seq%3 == 2 {
					return module.HopSample{Protocol: "udp"}, timeoutErr{}
				}
				return module.HopSample{Addr: netip.MustParseAddr("62.155.240.1"), RTT: 6 * time.Millisecond, Protocol: "udp"}, nil
			case 3:
				return module.HopSample{Addr: dst, Reached: true, RTT: 14 * time.Millisecond, Protocol: "udp"}, nil
			default:
				// Batch 1..4 also probes TTL 4, which must be trimmed above TTL 3!
				return module.HopSample{Addr: dst, Reached: true, RTT: 15 * time.Millisecond, Protocol: "udp"}, nil
			}
		},
	}

	r := New().Run(context.Background(), newJob(t, &measurev1.TracerouteParams{Protocol: "icmp", MaxHops: 16, Probes: 3}, time.Minute), tn)
	if r.Outcome != nodev1.Outcome_OUTCOME_OK {
		t.Fatalf("outcome = %v, want OUTCOME_OK", r.Outcome)
	}
	var res measurev1.TracerouteResult
	if err := measurev1.UnmarshalWire(r.Data, &res); err != nil {
		t.Fatal(err)
	}
	if res.Protocol != "udp" || !res.DestinationReached || res.TotalHops != 3 || len(res.Hops) != 3 || res.RttUs != 14000 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !res.Hops[0].Redacted || res.Hops[0].IP != "" || res.Hops[0].MedianUs != 800 {
		t.Fatalf("hop 1 redaction broken: %+v", res.Hops[0])
	}
	if !slices.Equal(res.Hops[1].RttUs, []uint32{6000, 0, 6000}) || res.Hops[1].Received != 2 {
		t.Fatalf("hop 2 loss encoding broken: %+v", res.Hops[1])
	}
}

func TestRunEarlyStopPastHop8(t *testing.T) {
	dst := netip.MustParseAddr("1.1.1.1")
	tn := &fakeNet{
		dst: dst,
		trace: func(_ context.Context, _ string, ttl, _ int, _ time.Duration) (module.HopSample, error) {
			if ttl == 1 {
				return module.HopSample{Redacted: true, RTT: time.Millisecond, Protocol: "udp"}, nil
			}
			if ttl == 2 {
				return module.HopSample{Addr: netip.MustParseAddr("62.155.240.1"), RTT: 5 * time.Millisecond, Protocol: "udp"}, nil
			}
			return module.HopSample{Protocol: "udp"}, timeoutErr{}
		},
	}
	r := New().Run(context.Background(), newJob(t, &measurev1.TracerouteParams{MaxHops: 24, Probes: 1}, time.Minute), tn)
	// Public hop 2 responded -> OUTCOME_OK (partial path), stopped early at hop 13 (8 + 5 silent hops)!
	if r.Outcome != nodev1.Outcome_OUTCOME_OK {
		t.Fatalf("outcome = %v, want OUTCOME_OK", r.Outcome)
	}
	var res measurev1.TracerouteResult
	if err := measurev1.UnmarshalWire(r.Data, &res); err != nil {
		t.Fatal(err)
	}
	if res.DestinationReached || res.TotalHops != 13 {
		t.Fatalf("expected early stop at 13 hops, got %+v", res)
	}
}
