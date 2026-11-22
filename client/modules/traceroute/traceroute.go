// Package traceroute is the node module for kind "traceroute", version 1:
// TTL-limited UDP or ICMP path discovery from ttl=1..max_hops in batches of
// up to 4 concurrent TTLs, using TargetNet.TraceHop inside the safety layer.
package traceroute

import (
	"context"
	"errors"
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
	Kind    = "traceroute"
	Version = 1
)

// Compiled limits of kind "traceroute", version 1.
const (
	DefaultMaxHops = 24
	MinMaxHops     = 4
	MaxMaxHops     = 30

	DefaultProbes = 3
	MinProbes     = 1
	MaxProbes     = 3

	DefaultTimeout = 1000 * time.Millisecond
	MinTimeout     = 300 * time.Millisecond
	MaxTimeout     = 2000 * time.Millisecond

	ttlBatchSize        = 4
	earlyStopMinHop     = 8
	earlyStopSilentHops = 5
)

type tracer struct {
	clock kit.Clock
}

// New returns the traceroute module.
func New() module.Module {
	return &tracer{clock: kit.RealClock()}
}

// Kind returns "traceroute".
func (m *tracer) Kind() string { return Kind }

// Version returns 1.
func (m *tracer) Version() uint32 { return Version }

// Class returns the measure class.
func (m *tracer) Class() nodev1.JobClass { return nodev1.JobClass_JOB_CLASS_MEASURE }

// Needs declares ICMP/trace transport (port 0).
func (m *tracer) Needs() module.Needs {
	return module.Needs{Transport: module.TransportICMP}
}

// SelfTest advertises traceroute for each working address family on hosts
// where unprivileged hop-limited sockets are supported, excluding Docker Desktop.
func (m *tracer) SelfTest(ctx context.Context, env module.Env) []protocol.Capability {
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
func (m *tracer) Check(job *module.Job) error {
	_, err := parse(job, m.clock.Now())
	return err
}

type params struct {
	protocol string
	maxHops  int
	probes   int
	timeout  time.Duration
}

func parse(job *module.Job, now time.Time) (params, error) {
	if job == nil || job.Target == nil {
		return params{}, kit.Invalid("job has no target")
	}
	if port := job.Target.GetPort(); port != 0 {
		return params{}, kit.Invalid("traceroute target port must be 0, got %d", port)
	}
	var raw measurev1.TracerouteParams
	if err := measurev1.UnmarshalWire(job.Params, &raw); err != nil {
		return params{}, kit.Invalid("params do not decode: %v", err)
	}
	p := params{
		protocol: "udp",
		maxHops:  DefaultMaxHops,
		probes:   DefaultProbes,
		timeout:  DefaultTimeout,
	}
	if pr := strings.TrimSpace(raw.Protocol); pr != "" {
		lo := strings.ToLower(pr)
		if lo != "udp" && lo != "icmp" {
			return params{}, kit.Invalid("traceroute protocol %q must be udp or icmp", raw.Protocol)
		}
		p.protocol = lo
	}
	if mh := raw.MaxHops; mh != 0 {
		if mh < MinMaxHops || mh > MaxMaxHops {
			return params{}, kit.Invalid("max_hops %d is outside %d to %d", mh, MinMaxHops, MaxMaxHops)
		}
		p.maxHops = int(mh)
	}
	if pb := raw.Probes; pb != 0 {
		if pb < MinProbes || pb > MaxProbes {
			return params{}, kit.Invalid("probes %d is outside %d to %d", pb, MinProbes, MaxProbes)
		}
		p.probes = int(pb)
	}
	if ms := raw.TimeoutMs; ms != 0 {
		p.timeout = time.Duration(ms) * time.Millisecond
		if p.timeout < MinTimeout || p.timeout > MaxTimeout {
			return params{}, kit.Invalid("timeout %d ms is outside %v to %v", ms, MinTimeout, MaxTimeout)
		}
	}
	if err := kit.CheckWindow(job, 2*p.timeout, now); err != nil {
		return params{}, err
	}
	return p, nil
}

type probeOutcome struct {
	sample module.HopSample
	err    error
}

type hopEval struct {
	wire    measurev1.TraceHopWire
	reached bool
	refusal error
	sendErr error
}

// Run probes TTLs 1..maxHops in batches of 4 TTLs, stopping as soon as any
// TTL reaches tn.Addr() (trimming hops above that TTL) or after 5 consecutive
// 100%-timeout hops past Hop 8.
func (m *tracer) Run(ctx context.Context, job *module.Job, tn module.TargetNet) module.Result {
	ctx, cancel := kit.WithDeadline(ctx, job)
	defer cancel()

	p, err := parse(job, m.clock.Now())
	if err != nil {
		return kit.Blocked(err)
	}

	dst := tn.Addr().Unmap()
	effectiveProto := p.protocol
	var protoMu sync.Mutex

	var evals []hopEval
	reachedTTL := 0

	for batchStart := 1; batchStart <= p.maxHops; batchStart += ttlBatchSize {
		if ctx.Err() != nil {
			break
		}
		batchEnd := min(batchStart+ttlBatchSize-1, p.maxHops)
		batchCount := batchEnd - batchStart + 1
		rawBatch := make([][]probeOutcome, batchCount)
		for i := range batchCount {
			rawBatch[i] = make([]probeOutcome, p.probes)
		}

		var wg sync.WaitGroup
		for i := range batchCount {
			ttl := batchStart + i
			for j := range p.probes {
				seq := (ttl-1)*p.probes + j + 1
				idx, pIdx := i, j
				wg.Go(func() {
					s, perr := tn.TraceHop(ctx, p.protocol, ttl, seq, p.timeout)
					if s.Protocol != "" {
						protoMu.Lock()
						if s.Protocol == "udp" && p.protocol == "icmp" {
							effectiveProto = "udp"
						} else if effectiveProto == "" {
							effectiveProto = s.Protocol
						}
						protoMu.Unlock()
					}
					rawBatch[idx][pIdx] = probeOutcome{sample: s, err: perr}
				})
			}
		}
		wg.Wait()

		for i := range batchCount {
			ttl := batchStart + i
			ev := summarizeHop(uint32(ttl), rawBatch[i], dst)
			evals = append(evals, ev)
			if ev.reached && (reachedTTL == 0 || ttl < reachedTTL) {
				reachedTTL = ttl
			}
		}

		if reachedTTL > 0 {
			evals = evals[:reachedTTL]
			break
		}
		if cut := deadTailCut(evals); cut > 0 {
			evals = evals[:cut]
			break
		}
	}

	hops := make([]measurev1.TraceHopWire, 0, len(evals))
	var (
		totalSent    uint32
		anyPublicHop bool
		refusal      error
		sendErr      error
	)
	for _, ev := range evals {
		if ev.refusal != nil && refusal == nil {
			refusal = ev.refusal
		}
		if ev.sendErr != nil && sendErr == nil {
			sendErr = ev.sendErr
		}
		if ev.wire.Sent == 0 && (len(hops) > 0 || ctx.Err() != nil) {
			// A hop whose probes never left because ctx ended mid-run is omitted.
			if ev.wire.Hop > 1 {
				continue
			}
			if ctx.Err() != nil {
				continue
			}
		}
		totalSent += ev.wire.Sent
		if ev.wire.Received > 0 && !ev.wire.Redacted && ev.wire.IP != "" {
			anyPublicHop = true
		}
		hops = append(hops, ev.wire)
	}

	res := measurev1.TracerouteResult{
		Protocol:           effectiveProto,
		DestinationReached: reachedTTL > 0 && len(hops) >= reachedTTL,
		TotalHops:          uint32(len(hops)),
		Hops:               hops,
	}
	if res.DestinationReached {
		res.RttUs = hops[len(hops)-1].MedianUs
	}

	r := module.Result{TSSource: nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE}
	switch {
	case res.DestinationReached || anyPublicHop:
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
	if totalSent > 0 || res.DestinationReached || anyPublicHop {
		if data, merr := measurev1.MarshalWire(&res); merr == nil {
			r.Data = data
		}
	}
	return r
}

func summarizeHop(hopNum uint32, outcomes []probeOutcome, dst interface{ String() string }) hopEval {
	w := measurev1.TraceHopWire{
		Hop:   hopNum,
		RttUs: make([]uint32, 0, len(outcomes)),
	}
	var (
		got         []uint32
		sawRedacted bool
		reached     bool
		refusal     error
		sendErr     error
	)
	dstStr := dst.String()
	for _, o := range outcomes {
		var r *module.Refusal
		switch {
		case o.err == nil:
			w.Sent++
			w.Received++
			us := kit.SampleMicros(o.sample.RTT)
			w.RttUs = append(w.RttUs, us)
			got = append(got, us)
			if o.sample.Redacted {
				sawRedacted = true
			} else if o.sample.Addr.IsValid() && w.IP == "" {
				w.IP = o.sample.Addr.Unmap().String()
			}
			if o.sample.Reached || (o.sample.Addr.IsValid() && o.sample.Addr.Unmap().String() == dstStr) {
				reached = true
			}
		case errors.As(o.err, &r):
			refusal = o.err
		case kit.LostReply(o.err):
			w.Sent++
			w.RttUs = append(w.RttUs, 0)
		default:
			sendErr = o.err
		}
	}
	if w.IP == "" && sawRedacted {
		w.Redacted = true
	}
	w.MinUs, w.MedianUs, w.MaxUs = kit.Stats(got)
	return hopEval{
		wire:    w,
		reached: reached,
		refusal: refusal,
		sendErr: sendErr,
	}
}

// deadTailCut returns the hop count to stop and trim at once 5 consecutive
// 100%-timeout hops have been observed past Hop 8, or 0 to keep probing.
func deadTailCut(evals []hopEval) int {
	if len(evals) < earlyStopMinHop+earlyStopSilentHops {
		return 0
	}
	silent := 0
	for i, ev := range evals {
		hop := i + 1
		if hop <= earlyStopMinHop {
			continue
		}
		if ev.wire.Sent > 0 && ev.wire.Received == 0 {
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
