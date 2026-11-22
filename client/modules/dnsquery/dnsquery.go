// Package dnsquery is the node module for kind "dns", version 1: one
// recursive DNS lookup for the job's target name against either the node's
// local ISP resolver or an allowlisted public resolver, over UDP (with
// automatic RFC 1035 TCP retry on TC=1) or TCP. Every byte goes through
// TargetNet.QueryDNS inside the safety layer.
package dnsquery

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/modules/internal/kit"
	"github.com/hopbits/client/protocol"
)

// Kind and Version name the job kind this module runs.
const (
	Kind    = "dns"
	Version = 1
)

// Compiled limits of kind "dns", version 1.
const (
	DefaultTimeout = 3000 * time.Millisecond
	MinTimeout     = 500 * time.Millisecond
	MaxTimeout     = 10000 * time.Millisecond
	MaxAnswers     = 32
)

var (
	allowedQtypes = [...]string{
		"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "PTR",
	}
	allowedResolvers = [...]string{
		"isp", "1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222",
	}
)

type resolverMod struct {
	clock kit.Clock
}

// New returns the dns module.
func New() module.Module {
	return &resolverMod{clock: kit.RealClock()}
}

// Kind returns "dns".
func (m *resolverMod) Kind() string { return Kind }

// Version returns 1.
func (m *resolverMod) Version() uint32 { return Version }

// Class returns the measure class.
func (m *resolverMod) Class() nodev1.JobClass { return nodev1.JobClass_JOB_CLASS_MEASURE }

// Needs declares DNS transport (port 0 or 53, bound inside the safety layer).
func (m *resolverMod) Needs() module.Needs {
	return module.Needs{Transport: module.TransportDNS}
}

// SelfTest advertises DNS timing over IPv4, and over IPv6 when the host has
// a global IPv6 address, excluding Docker Desktop. It sends nothing.
func (m *resolverMod) SelfTest(ctx context.Context, env module.Env) []protocol.Capability {
	if ctx.Err() != nil || env.NetworkMode == nodev1.NetworkMode_NETWORK_MODE_DOCKER_DESKTOP {
		return nil
	}
	q := append(kit.Families(env), kit.QualTSUser)
	return []protocol.Capability{kit.Capability(Kind, Version, q...)}
}

// Check validates a job's params against the compiled limits.
func (m *resolverMod) Check(job *module.Job) error {
	_, err := parse(job, m.clock.Now())
	return err
}

type params struct {
	qtype    string
	resolver string
	protocol string
	timeout  time.Duration
}

func parse(job *module.Job, now time.Time) (params, error) {
	if job == nil || job.Target == nil {
		return params{}, kit.Invalid("job has no target")
	}
	if port := job.Target.GetPort(); port != 0 && port != 53 {
		return params{}, kit.Invalid("DNS target port must be 0 or 53, got %d", port)
	}
	var raw measurev1.DnsParams
	if err := measurev1.UnmarshalWire(job.Params, &raw); err != nil {
		return params{}, kit.Invalid("params do not decode: %v", err)
	}
	p := params{
		qtype:    "A",
		resolver: "isp",
		protocol: "udp",
		timeout:  DefaultTimeout,
	}
	if qt := strings.TrimSpace(raw.Qtype); qt != "" {
		up := strings.ToUpper(qt)
		if !slices.Contains(allowedQtypes[:], up) {
			return params{}, kit.Invalid("unsupported DNS qtype %q", raw.Qtype)
		}
		p.qtype = up
	}
	if res := strings.TrimSpace(raw.Resolver); res != "" {
		lo := strings.ToLower(res)
		if !slices.Contains(allowedResolvers[:], lo) {
			return params{}, kit.Invalid("DNS resolver %q is not on the allowlist", raw.Resolver)
		}
		p.resolver = lo
	}
	if pr := strings.TrimSpace(raw.Protocol); pr != "" {
		lo := strings.ToLower(pr)
		if lo != "udp" && lo != "tcp" {
			return params{}, kit.Invalid("DNS protocol %q must be udp or tcp", raw.Protocol)
		}
		p.protocol = lo
	}
	if ms := raw.TimeoutMs; ms != 0 {
		p.timeout = time.Duration(ms) * time.Millisecond
		if p.timeout < MinTimeout || p.timeout > MaxTimeout {
			return params{}, kit.Invalid("timeout %d ms is outside %v to %v", ms, MinTimeout, MaxTimeout)
		}
	}
	if err := kit.CheckWindow(job, p.timeout, now); err != nil {
		return params{}, err
	}
	return p, nil
}

// Run executes one DNS query through TargetNet.QueryDNS. Outcome is OK
// whenever a valid DNS response arrives (including NXDOMAIN or SERVFAIL,
// since the resolver answered).
func (m *resolverMod) Run(ctx context.Context, job *module.Job, tn module.TargetNet) module.Result {
	ctx, cancel := kit.WithDeadline(ctx, job)
	defer cancel()

	p, err := parse(job, m.clock.Now())
	if err != nil {
		return kit.Blocked(err)
	}

	reply, err := tn.QueryDNS(ctx, module.DNSQuery{
		Qtype:    p.qtype,
		Resolver: p.resolver,
		Protocol: p.protocol,
		Timeout:  p.timeout,
	})
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return module.Result{
				Outcome:  nodev1.Outcome_OUTCOME_CANCELLED,
				TSSource: nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE,
			}
		}
		o, code := kit.ConnectOutcome(err)
		return module.Result{
			Outcome:  o,
			Error:    code,
			TSSource: nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE,
		}
	}

	var answers []measurev1.DnsAnswerRecord
	if len(reply.Answers) > 0 {
		limit := min(len(reply.Answers), MaxAnswers)
		answers = make([]measurev1.DnsAnswerRecord, 0, limit)
		for _, a := range reply.Answers[:limit] {
			answers = append(answers, measurev1.DnsAnswerRecord{
				Name: a.Name,
				Type: a.Type,
				TTL:  a.TTL,
				Data: a.Data,
			})
		}
	}

	res := measurev1.DnsResult{
		Qname:         reply.Qname,
		Qtype:         reply.Qtype,
		Resolver:      reply.Resolver,
		Protocol:      reply.Protocol,
		Rcode:         reply.Rcode,
		RcodeNum:      reply.RcodeNum,
		Authoritative: reply.Authoritative,
		Truncated:     reply.Truncated,
		RttUs:         kit.SampleMicros(reply.RTT),
		Answers:       answers,
	}
	data, merr := measurev1.MarshalWire(&res)
	if merr != nil {
		data = nil
	}
	return module.Result{
		Outcome:    nodev1.Outcome_OUTCOME_OK,
		TSSource:   nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO,
		TxTSSource: nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO,
		Data:       data,
	}
}
