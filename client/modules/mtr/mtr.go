// Package mtr is the node module for kind "mtr", version 1: multi-cycle
// hop-by-hop latency, packet loss and jitter (sample standard deviation)
// telemetry using TargetNet.TraceHop inside the safety layer.
package mtr

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/modules/internal/kit"
	"github.com/hopbits/client/protocol"
)

// Kind and Version name the job kind this module runs.
const (
	Kind    = "mtr"
	Version = 1
)

// Compiled limits of kind "mtr", version 1.
const (
	DefaultMaxHops = 24
	MinMaxHops     = 4
	MaxMaxHops     = 30

	DefaultCycles = 5
	MinCycles     = 3
	MaxCycles     = 10

	DefaultTimeout = 800 * time.Millisecond
	MinTimeout     = 300 * time.Millisecond
	MaxTimeout     = 1500 * time.Millisecond

	// CycleGap is the minimum pause between consecutive MTR cycles.
	CycleGap = 80 * time.Millisecond

	discoveryBatchSize  = 4
	cycleMaxInFlight    = 6
	earlyStopMinHop     = 8
	earlyStopSilentHops = 5
)

type runner struct {
	clock kit.Clock
}

// New returns the mtr module.
func New() module.Module {
	return &runner{clock: kit.RealClock()}
}

// Kind returns "mtr".
func (m *runner) Kind() string { return Kind }

// Version returns 1.
func (m *runner) Version() uint32 { return Version }

// Class returns the measure class.
func (m *runner) Class() nodev1.JobClass { return nodev1.JobClass_JOB_CLASS_MEASURE }

// Needs declares ICMP/trace transport (port 0).
func (m *runner) Needs() module.Needs {
	return module.Needs{Transport: module.TransportICMP}
}

// SelfTest advertises MTR for each working address family on hosts where
// unprivileged hop-limited sockets are supported, excluding Docker Desktop.
func (m *runner) SelfTest(ctx context.Context, env module.Env) []protocol.Capability {
	if ctx.Err() != nil || env.Probe == nil || env.NetworkMode == nodev1.NetworkMode_NETWORK_MODE_DOCKER_DESKTOP {
		return nil
	}
	families := []struct {
		family    nodev1.AddressFamily
		qualifier string
	}{
		{nodev1.AddressFamily_ADDRESS_FAMILY_IPV4, kit.QualIPv4},
		{nodev1.AddressFamily_ADDRESS_FAMILY_IPV6, kit.QualIPv6},
	}
	var caps []protocol.Capability
	for _, f := range families {
		if f.family == nodev1.AddressFamily_ADDRESS_FAMILY_IPV6 && !env.Probe.HasIPv6() {
			continue
		}
		ok, ts, _ := env.Probe.Trace(f.family)
		if !ok {
			continue
		}
		tsq, known := kit.TSQualifier(ts)
		if !known {
			continue
		}
		caps = append(caps, kit.Capability(Kind, Version, f.qualifier, tsq))
	}
	return caps
}

// Check validates a job's params against the compiled limits.
func (m *runner) Check(job *module.Job) error {
	_, err := parse(job, m.clock.Now())
	return err
}

type params struct {
	protocol string
	maxHops  int
	cycles   int
	timeout  time.Duration
}

func parse(job *module.Job, now time.Time) (params, error) {
	if job == nil || job.Target == nil {
		return params{}, kit.Invalid("job has no target")
	}
	if port := job.Target.GetPort(); port != 0 {
		return params{}, kit.Invalid("mtr target port must be 0, got %d", port)
	}
	var raw measurev1.MtrParams
	if err := measurev1.UnmarshalWire(job.Params, &raw); err != nil {
		return params{}, kit.Invalid("params do not decode: %v", err)
	}
	p := params{
		protocol: "udp",
		maxHops:  DefaultMaxHops,
		cycles:   DefaultCycles,
		timeout:  DefaultTimeout,
	}
	if pr := strings.TrimSpace(raw.Protocol); pr != "" {
		lo := strings.ToLower(pr)
		if lo != "udp" && lo != "icmp" {
			return params{}, kit.Invalid("mtr protocol %q must be udp or icmp", raw.Protocol)
		}
		p.protocol = lo
	}
	if mh := raw.MaxHops; mh != 0 {
		if mh < MinMaxHops || mh > MaxMaxHops {
			return params{}, kit.Invalid("max_hops %d is outside %d to %d", mh, MinMaxHops, MaxMaxHops)
		}
		p.maxHops = int(mh)
	}
	if cy := raw.Cycles; cy != 0 {
		if cy < MinCycles || cy > MaxCycles {
			return params{}, kit.Invalid("cycles %d is outside %d to %d", cy, MinCycles, MaxCycles)
		}
		p.cycles = int(cy)
	}
	if ms := raw.TimeoutMs; ms != 0 {
		p.timeout = time.Duration(ms) * time.Millisecond
		if p.timeout < MinTimeout || p.timeout > MaxTimeout {
			return params{}, kit.Invalid("timeout %d ms is outside %v to %v", ms, MinTimeout, MaxTimeout)
		}
	}
	if err := kit.CheckWindow(job, time.Duration(p.cycles)*p.timeout, now); err != nil {
		return params{}, err
	}
	return p, nil
}

type hopAccum struct {
	ip          string
	sawRedacted bool
	sent        uint32
	rtts        []uint32
	reached     bool
	refusal     error
	sendErr     error
}

type cycleSample struct {
	sample module.HopSample
	err    error
	ran    bool
}

func (a *hopAccum) record(cs cycleSample, dstStr string) {
	if !cs.ran {
		return
	}
	var r *module.Refusal
	switch {
	case cs.err == nil:
		a.sent++
		us := kit.SampleMicros(cs.sample.RTT)
		a.rtts = append(a.rtts, us)
		if cs.sample.Redacted {
			a.sawRedacted = true
		} else if cs.sample.Addr.IsValid() && a.ip == "" {
			a.ip = cs.sample.Addr.Unmap().String()
		}
		if cs.sample.Reached || (cs.sample.Addr.IsValid() && cs.sample.Addr.Unmap().String() == dstStr) {
			a.reached = true
		}
	case errors.As(cs.err, &r):
		if a.refusal == nil {
			a.refusal = cs.err
		}
	case kit.LostReply(cs.err):
		a.sent++
	default:
		if a.sendErr == nil {
			a.sendErr = cs.err
		}
	}
}

// Run executes Cycle 1 path discovery in batches of 4 TTLs to determine
// effectiveMaxHops, then runs Cycles 2..cycles across 1..effectiveMaxHops
// with up to 6 in-flight hop probes spaced >= 80ms between cycles.
func (m *runner) Run(ctx context.Context, job *module.Job, tn module.TargetNet) module.Result {
	ctx, cancel := kit.WithDeadline(ctx, job)
	defer cancel()

	p, err := parse(job, m.clock.Now())
	if err != nil {
		return kit.Blocked(err)
	}

	dstStr := tn.Addr().Unmap().String()
	effectiveProto := p.protocol
	var protoMu sync.Mutex
	recordProto := func(s module.HopSample) {
		if s.Protocol == "" {
			return
		}
		protoMu.Lock()
		if s.Protocol == "udp" && p.protocol == "icmp" {
			effectiveProto = "udp"
		} else if effectiveProto == "" {
			effectiveProto = s.Protocol
		}
		protoMu.Unlock()
	}

	accums := make([]hopAccum, p.maxHops)
	effectiveMaxHops := 0
	reachedTTL := 0
	cyclesRun := 0

	// Cycle 1: path discovery in batches of 4 TTLs.
	if ctx.Err() == nil {
		for batchStart := 1; batchStart <= p.maxHops; batchStart += discoveryBatchSize {
			if ctx.Err() != nil {
				break
			}
			batchEnd := min(batchStart+discoveryBatchSize-1, p.maxHops)
			batchCount := batchEnd - batchStart + 1
			samples := make([]cycleSample, batchCount)

			var wg sync.WaitGroup
			for i := range batchCount {
				ttl := batchStart + i
				idx := i
				wg.Go(func() {
					s, perr := tn.TraceHop(ctx, p.protocol, ttl, ttl, p.timeout)
					recordProto(s)
					samples[idx] = cycleSample{sample: s, err: perr, ran: true}
				})
			}
			wg.Wait()

			for i := range batchCount {
				ttl := batchStart + i
				accums[ttl-1].record(samples[i], dstStr)
				if ttl > effectiveMaxHops {
					effectiveMaxHops = ttl
				}
				if accums[ttl-1].reached && (reachedTTL == 0 || ttl < reachedTTL) {
					reachedTTL = ttl
				}
			}

			if reachedTTL > 0 {
				effectiveMaxHops = reachedTTL
				break
			}
			if cut := discoveryDeadTail(accums[:effectiveMaxHops]); cut > 0 {
				effectiveMaxHops = cut
				break
			}
		}
		if effectiveMaxHops > 0 {
			cyclesRun = 1
		}
	}

	// Cycles 2..cycles across 1..effectiveMaxHops with max 6 in-flight probes.
	for cycle := 2; cycle <= p.cycles && effectiveMaxHops > 0; cycle++ {
		if err := m.clock.Sleep(ctx, CycleGap); err != nil {
			break
		}
		if ctx.Err() != nil {
			break
		}

		samples := make([]cycleSample, effectiveMaxHops)
		sem := make(chan struct{}, cycleMaxInFlight)
		var wg sync.WaitGroup
		stopped := false
		for ttl := 1; ttl <= effectiveMaxHops; ttl++ {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				stopped = true
			}
			if stopped {
				break
			}
			hopTTL := ttl
			seq := (cycle-1)*p.maxHops + hopTTL
			wg.Go(func() {
				defer func() { <-sem }()
				s, perr := tn.TraceHop(ctx, p.protocol, hopTTL, seq, p.timeout)
				recordProto(s)
				samples[hopTTL-1] = cycleSample{sample: s, err: perr, ran: true}
			})
		}
		wg.Wait()

		anyRan := false
		for ttl := 1; ttl <= effectiveMaxHops; ttl++ {
			if samples[ttl-1].ran {
				anyRan = true
			}
			accums[ttl-1].record(samples[ttl-1], dstStr)
			if accums[ttl-1].reached && (reachedTTL == 0 || ttl < reachedTTL) {
				reachedTTL = ttl
			}
		}
		if anyRan {
			cyclesRun++
		}
		if reachedTTL > 0 && reachedTTL < effectiveMaxHops {
			effectiveMaxHops = reachedTTL
		}
	}

	hops := make([]measurev1.MtrHopWire, 0, effectiveMaxHops)
	var (
		totalSent    uint32
		anyPublicHop bool
		refusal      error
		sendErr      error
	)
	for i := range effectiveMaxHops {
		a := &accums[i]
		if a.refusal != nil && refusal == nil {
			refusal = a.refusal
		}
		if a.sendErr != nil && sendErr == nil {
			sendErr = a.sendErr
		}
		if a.sent == 0 && ctx.Err() != nil {
			continue
		}
		w := buildMtrHopWire(uint32(i+1), a)
		totalSent += w.Sent
		if w.Received > 0 && !w.Redacted && w.IP != "" {
			anyPublicHop = true
		}
		hops = append(hops, w)
	}

	destReached := reachedTTL > 0 && len(hops) >= reachedTTL
	res := measurev1.MtrResult{
		Protocol:           effectiveProto,
		Cycles:             uint32(cyclesRun),
		DestinationReached: destReached,
		TotalHops:          uint32(len(hops)),
		Hops:               hops,
	}
	if destReached {
		res.RttUs = hops[len(hops)-1].AvgUs
	}

	r := module.Result{TSSource: nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE}
	switch {
	case destReached || anyPublicHop:
		r.Outcome = nodev1.Outcome_OUTCOME_OK
		r.TSSource = nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO
	case errors.Is(ctx.Err(), context.Canceled):
		r.Outcome = nodev1.Outcome_OUTCOME_CANCELLED
	case totalSent == 0 && refusal != nil:
		r.Outcome, r.Error = kit.RefusalOutcome(refusal)
	case totalSent == 0 && sendErr != nil:
		r.Outcome, r.Error = kit.ConnectOutcome(sendErr)
	default:
		r.Outcome = nodev1.Outcome_OUTCOME_TIMEOUT
	}
	if totalSent > 0 || destReached || anyPublicHop {
		if data, merr := measurev1.MarshalWire(&res); merr == nil {
			r.Data = data
		}
	}
	return r
}

// buildMtrHopWire computes Sent, Received, LossPct (rounded to 1 decimal),
// LastUs, MinUs, AvgUs, MaxUs, and sample standard deviation StdevUs.
func buildMtrHopWire(hopNum uint32, a *hopAccum) measurev1.MtrHopWire {
	recv := uint32(len(a.rtts))
	w := measurev1.MtrHopWire{
		Hop:      hopNum,
		IP:       a.ip,
		Redacted: a.ip == "" && a.sawRedacted,
		Sent:     a.sent,
		Received: recv,
	}
	if a.sent > 0 {
		lost := a.sent - recv
		w.LossPct = math.Round((float64(lost)/float64(a.sent))*1000) / 10
	}
	if recv == 0 {
		return w
	}
	w.LastUs = a.rtts[recv-1]
	w.MinUs = slices.Min(a.rtts)
	w.MaxUs = slices.Max(a.rtts)

	var sum float64
	for _, v := range a.rtts {
		sum += float64(v)
	}
	mean := sum / float64(recv)
	w.AvgUs = uint32(math.Round(mean))

	if recv >= 2 {
		var sqDiff float64
		for _, v := range a.rtts {
			d := float64(v) - mean
			sqDiff += d * d
		}
		w.StdevUs = uint32(math.Round(math.Sqrt(sqDiff / float64(recv-1))))
	}
	return w
}

func discoveryDeadTail(accums []hopAccum) int {
	if len(accums) < earlyStopMinHop+earlyStopSilentHops {
		return 0
	}
	silent := 0
	for i := range accums {
		hop := i + 1
		if hop <= earlyStopMinHop {
			continue
		}
		if accums[i].sent > 0 && len(accums[i].rtts) == 0 {
			silent++
			if silent >= earlyStopSilentHops {
				return hop
			}
		} else {
			silent = 0
		}
	}
	return 0
}
