// Package icmpping is the node module for kind "icmp_ping", version 1: 3 to
// 16 ICMP echo requests to the job's target, spaced by an interval of at
// least 200 ms, reporting the round trip of each and the TTL of the first
// reply. Echoes go through the job's Pinger, which the safety layer binds
// to the target and holds to the compiled ICMP rate.
package icmpping

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/modules/internal/kit"
	"github.com/hopbits/client/protocol"
)

// Kind and Version name the job kind this module runs.
const (
	Kind    = "icmp_ping"
	Version = 1
)

// Compiled limits of kind "icmp_ping", version 1.
const (
	// DefaultPackets applies when a job names no packet count.
	DefaultPackets = 3
	// MinPackets and MaxPackets bound the echo requests one job sends.
	MinPackets = 3
	MaxPackets = 16
	// DefaultInterval applies when a job names no interval.
	DefaultInterval = time.Second
	// MinInterval and MaxInterval bound the spacing of echo requests.
	MinInterval = 200 * time.Millisecond
	MaxInterval = 5 * time.Second
	// DefaultTimeout applies to each packet when a job names none.
	DefaultTimeout = 2 * time.Second
	// MinTimeout and MaxTimeout bound how long each packet waits for its
	// reply.
	MinTimeout = 500 * time.Millisecond
	MaxTimeout = 5 * time.Second
)

// pinger is the icmp_ping module.
type pinger struct {
	clock kit.Clock
}

// New returns the icmp_ping module.
func New() module.Module {
	return &pinger{clock: kit.RealClock()}
}

// Kind returns "icmp_ping".
func (m *pinger) Kind() string { return Kind }

// Version returns 1.
func (m *pinger) Version() uint32 { return Version }

// Class returns the measure class.
func (m *pinger) Class() nodev1.JobClass { return nodev1.JobClass_JOB_CLASS_MEASURE }

// Needs declares ICMP, which uses no ports.
func (m *pinger) Needs() module.Needs {
	return module.Needs{Transport: module.TransportICMP}
}

// SelfTest asks the host probe whether ICMP echo works for IPv4 and IPv6
// and advertises each family that works, qualified by how it is timed.
// IPv6 also needs a global IPv6 address. Docker Desktop gets nothing,
// because it re-originates traffic from the host and ICMP results from it
// are not valid.
func (m *pinger) SelfTest(ctx context.Context, env module.Env) []protocol.Capability {
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
		ok, ts, _ := env.Probe.ICMP(f.family)
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
func (m *pinger) Check(job *module.Job) error {
	_, err := parse(job, m.clock.Now())
	return err
}

// params are an icmp_ping job's params with defaults applied.
type params struct {
	packets  int
	interval time.Duration
	timeout  time.Duration
}

// parse decodes a job's params, applies the defaults and refuses anything
// outside the compiled limits with INVALID_PARAMS.
func parse(job *module.Job, now time.Time) (params, error) {
	var raw measurev1.IcmpPingParams
	if err := kit.Decode(job.Params, &raw); err != nil {
		return params{}, err
	}
	p := params{packets: DefaultPackets, interval: DefaultInterval, timeout: DefaultTimeout}
	if n := raw.GetPackets(); n != 0 {
		if n < MinPackets || n > MaxPackets {
			return params{}, kit.Invalid("%d packets is outside %d to %d", n, MinPackets, MaxPackets)
		}
		p.packets = int(n)
	}
	if ms := raw.GetIntervalMs(); ms != 0 {
		p.interval = time.Duration(ms) * time.Millisecond
		if p.interval < MinInterval || p.interval > MaxInterval {
			return params{}, kit.Invalid("interval %d ms is outside %v to %v", ms, MinInterval, MaxInterval)
		}
	}
	if ms := raw.GetTimeoutMs(); ms != 0 {
		p.timeout = time.Duration(ms) * time.Millisecond
		if p.timeout < MinTimeout || p.timeout > MaxTimeout {
			return params{}, kit.Invalid("timeout %d ms is outside %v to %v", ms, MinTimeout, MaxTimeout)
		}
	}
	need := time.Duration(p.packets)*p.interval + p.timeout
	if err := kit.CheckWindow(job, need, now); err != nil {
		return params{}, err
	}
	return p, nil
}

// echo is one echo request's fate.
type echo struct {
	reply module.EchoReply
	err   error
}

// Run sends the echo requests with sequence numbers 1 to n, one every
// interval, each waiting up to the timeout for its reply. Waits overlap,
// as with ping, so the job ends within packets × interval + timeout. Only
// requests that left the node count as sent; one the pinger refused or
// could not send is left out. The outcome is OK if any reply arrived,
// TIMEOUT if requests were sent and none was answered, and otherwise the
// outcome of the refusal or of the failed send.
func (m *pinger) Run(ctx context.Context, job *module.Job, tn module.TargetNet) module.Result {
	ctx, cancel := kit.WithDeadline(ctx, job)
	defer cancel()

	// Check ran before the job was accepted; parse again so that Run never
	// sends more than the compiled limits allow, whoever calls it.
	p, err := parse(job, m.clock.Now())
	if err != nil {
		return kit.Blocked(err)
	}
	pg, err := tn.Pinger()
	if err != nil {
		return module.Result{
			Outcome:  nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE,
			Error:    nodev1.ErrorCode_ERROR_CODE_PERMISSION_WITHHELD,
			TSSource: nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE,
		}
	}
	defer pg.Close()

	echoes := m.send(ctx, pg, p)

	res := &measurev1.IcmpPingResult{}
	var got []uint32
	var refusal, sendErr error
	for _, e := range echoes {
		var r *module.Refusal
		switch {
		case e.err == nil:
		case errors.As(e.err, &r):
			// The pinger refused to send it, for example over the rate cap.
			refusal = e.err
			continue
		case kit.LostReply(e.err):
			// Sent, and no reply came in time.
			res.Sent++
			res.RttUs = append(res.RttUs, 0)
			continue
		default:
			// The send itself failed: nothing left the node.
			sendErr = e.err
			continue
		}
		res.Sent++
		us := kit.SampleMicros(e.reply.RTT)
		res.RttUs = append(res.RttUs, us)
		if len(got) == 0 {
			res.ReplyTtl = ttl(e.reply.TTL)
		}
		got = append(got, us)
	}
	res.Received = uint32(len(got))
	res.MinUs, res.MedianUs, res.MaxUs = kit.Stats(got)

	r := module.Result{TSSource: nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE}
	switch {
	case len(got) > 0:
		r.Outcome = nodev1.Outcome_OUTCOME_OK
		r.TSSource = pg.TimestampSource()
	case errors.Is(ctx.Err(), context.Canceled):
		r.Outcome = nodev1.Outcome_OUTCOME_CANCELLED
	case res.Sent == 0 && refusal != nil:
		r.Outcome, r.Error = kit.RefusalOutcome(refusal)
	case res.Sent == 0 && sendErr != nil:
		r.Outcome, r.Error = kit.ConnectOutcome(sendErr)
	default:
		r.Outcome = nodev1.Outcome_OUTCOME_TIMEOUT
	}
	if r.Data, err = proto.Marshal(res); err != nil {
		r.Data = nil
	}
	return r
}

// send starts echo request i at start + (i-1) × interval and waits for
// every reply or timeout. It stops starting new requests when ctx ends,
// and returns the fate of each request it started, in sequence order.
func (m *pinger) send(ctx context.Context, pg module.Pinger, p params) []echo {
	out := make([]echo, p.packets)
	var wg sync.WaitGroup
	start := m.clock.Now()
	started := 0
	for i := range p.packets {
		if i > 0 {
			due := start.Add(time.Duration(i) * p.interval)
			if err := m.clock.Sleep(ctx, due.Sub(m.clock.Now())); err != nil {
				break
			}
		}
		if ctx.Err() != nil {
			break
		}
		started++
		seq := uint16(i + 1)
		wg.Go(func() {
			reply, err := pg.Echo(ctx, seq, p.timeout)
			out[seq-1] = echo{reply: reply, err: err}
		})
	}
	wg.Wait()
	return out[:started]
}

// ttl clamps a reply TTL to the range an IP header can carry.
func ttl(v int) uint32 {
	return uint32(min(max(v, 0), 255))
}
