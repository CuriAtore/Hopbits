// Package tcpconnect is the node module for kind "tcp_connect", version 1:
// how long a TCP connect to the job's target takes, in one to three
// samples one second apart. Each sample opens a connection through the
// job's TargetNet and closes it at once, sending no data.
package tcpconnect

import (
	"context"
	"errors"
	"slices"
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
	Kind    = "tcp_connect"
	Version = 1
)

// Compiled limits of kind "tcp_connect", version 1.
const (
	// DefaultTimeout applies to each sample when a job names none.
	DefaultTimeout = 5 * time.Second
	// MinTimeout and MaxTimeout bound the per-sample timeout.
	MinTimeout = time.Second
	MaxTimeout = 10 * time.Second
	// DefaultSamples applies when a job names no sample count.
	DefaultSamples = 1
	// MaxSamples bounds the connections one job opens.
	MaxSamples = 3
	// Gap is the pause between samples.
	Gap = time.Second
)

// ports are usable without a target grant.
var ports = [...]uint16{443, 80}

// prober is the tcp_connect module.
type prober struct {
	clock kit.Clock
}

// New returns the tcp_connect module.
func New() module.Module {
	return &prober{clock: kit.RealClock()}
}

// Kind returns "tcp_connect".
func (m *prober) Kind() string { return Kind }

// Version returns 1.
func (m *prober) Version() uint32 { return Version }

// Class returns the measure class.
func (m *prober) Class() nodev1.JobClass { return nodev1.JobClass_JOB_CLASS_MEASURE }

// Needs declares TCP to ports 443 and 80.
func (m *prober) Needs() module.Needs {
	return module.Needs{Transport: module.TransportTCP, Ports: slices.Clone(ports[:])}
}

// SelfTest advertises TCP connect timing over IPv4, and over IPv6 when the
// host has it. It sends nothing.
func (m *prober) SelfTest(_ context.Context, env module.Env) []protocol.Capability {
	q := append(kit.Families(env), kit.QualTSUser)
	return []protocol.Capability{kit.Capability(Kind, Version, q...)}
}

// Check validates a job's params against the compiled limits.
func (m *prober) Check(job *module.Job) error {
	_, err := parse(job, m.clock.Now())
	return err
}

// params are a tcp_connect job's params with defaults applied.
type params struct {
	timeout time.Duration
	samples int
}

// parse decodes a job's params, applies the defaults and refuses anything
// outside the compiled limits.
func parse(job *module.Job, now time.Time) (params, error) {
	var raw measurev1.TcpConnectParams
	if err := kit.Decode(job.Params, &raw); err != nil {
		return params{}, err
	}
	p := params{timeout: DefaultTimeout, samples: DefaultSamples}
	if ms := raw.GetTimeoutMs(); ms != 0 {
		p.timeout = time.Duration(ms) * time.Millisecond
		if p.timeout < MinTimeout || p.timeout > MaxTimeout {
			return params{}, kit.Invalid("timeout %d ms is outside %v to %v", ms, MinTimeout, MaxTimeout)
		}
	}
	if n := raw.GetSamples(); n != 0 {
		if n > MaxSamples {
			return params{}, kit.Invalid("%d samples asked for, at most %d allowed", n, MaxSamples)
		}
		p.samples = int(n)
	}
	need := time.Duration(p.samples) * (p.timeout + Gap)
	if err := kit.CheckWindow(job, need, now); err != nil {
		return params{}, err
	}
	port, ok := kit.Port(job.Target)
	if !ok {
		return params{}, kit.Invalid("target port %d is out of range", job.Target.GetPort())
	}
	if !kit.HasGrant(job.Target) && !slices.Contains(ports[:], port) && !kit.UnsafeTestPort(port) {
		return params{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING, "port %d needs a target grant", port)
	}
	return p, nil
}

// Run opens and closes one connection per sample and reports the connect
// times. The outcome is OK if any sample connected, otherwise the outcome
// of the last sample's error.
func (m *prober) Run(ctx context.Context, job *module.Job, tn module.TargetNet) module.Result {
	ctx, cancel := kit.WithDeadline(ctx, job)
	defer cancel()

	// Check ran before the job was accepted; parse again so that Run never
	// connects outside the compiled limits, whoever calls it.
	p, err := parse(job, m.clock.Now())
	if err != nil {
		return kit.Blocked(err)
	}
	if !tn.Verified() && !slices.Contains(ports[:], tn.Port()) && !kit.UnsafeTestPort(tn.Port()) {
		return kit.Blocked(module.Refuse(nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING,
			"port %d needs a target grant", tn.Port()))
	}

	res := &measurev1.TcpConnectResult{}
	var ok []uint32
	var lastErr error
	for i := range p.samples {
		if i > 0 {
			if err := m.clock.Sleep(ctx, Gap); err != nil {
				break
			}
		}
		us, err := m.sample(ctx, tn, p.timeout)
		res.ConnectUs = append(res.ConnectUs, us)
		if err != nil {
			lastErr = err
			var r *module.Refusal
			if errors.As(err, &r) {
				// The safety layer refused; another sample would be refused too.
				break
			}
			continue
		}
		ok = append(ok, us)
	}
	res.Succeeded = uint32(len(ok))
	res.MinUs, res.MedianUs, _ = kit.Stats(ok)

	r := module.Result{TSSource: nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE}
	switch {
	case len(ok) > 0:
		r.Outcome = nodev1.Outcome_OUTCOME_OK
		r.TSSource = nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO
		r.TxTSSource = nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO
	case errors.Is(ctx.Err(), context.Canceled):
		r.Outcome = nodev1.Outcome_OUTCOME_CANCELLED
	case lastErr != nil:
		r.Outcome, r.Error = kit.ConnectOutcome(lastErr)
	default:
		// No sample ran: the job's deadline passed first.
		r.Outcome = nodev1.Outcome_OUTCOME_TIMEOUT
	}
	if r.Data, err = proto.Marshal(res); err != nil {
		r.Data = nil
	}
	return r
}

// sample times one connect, bounded by the per-sample timeout, and closes
// the connection. A connection that opened is at least 1 µs, because 0
// marks a failed sample.
func (m *prober) sample(ctx context.Context, tn module.TargetNet, timeout time.Duration) (uint32, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := m.clock.Now()
	conn, err := tn.DialTCP(ctx)
	elapsed := m.clock.Now().Sub(start)
	if err != nil {
		return 0, err
	}
	// Only the connect is measured; a close error changes nothing.
	_ = conn.Close()
	return kit.SampleMicros(elapsed), nil
}
