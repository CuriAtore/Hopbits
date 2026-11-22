// Package module is the contract every node module implements.
//
// A module is one kind of job a node can run: icmp_ping, http, tcp_connect
// and, later, traceroute, dns or tls_cert. New business features on the
// server ("ping from a country", "locate this IP") reuse existing modules; a
// new module is needed only for a new kind of network work. Adding one means:
//
//  1. a params and a result message in proto/hopbits/measure/v1,
//  2. a package under modules/ implementing Module,
//  3. one line in modules/all,
//  4. the server half: a kind plugin, a registry row and a price.
//
// Modules never touch the network directly. The runner gives each job a
// TargetNet from the safety layer, bound to that job's validated target and
// charged to the compiled caps, so no module can reach another host, a
// private address or the operator's own network, whatever the server asks.
package module

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"time"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/protocol"
)

// Module is one kind of job a node can run.
type Module interface {
	// Kind is the registry name, such as "icmp_ping".
	Kind() string
	// Version is the kind version this module implements.
	Version() uint32
	// Class is the job class. Version 1 modules are all JOB_CLASS_MEASURE.
	Class() nodev1.JobClass
	// Needs declares what the module uses from the network. The safety
	// layer enforces it and never grants more than the compiled bounds.
	Needs() Needs
	// SelfTest reports which capabilities work on this host. It must not
	// send traffic; capabilities are verified on the server with test jobs.
	SelfTest(ctx context.Context, env Env) []protocol.Capability
	// Check validates a job's params against the module's compiled limits
	// before the job is accepted. It must not do I/O. Return a *Refusal.
	Check(job *Job) error
	// Run executes an accepted job. All network access goes through tn.
	// Run returns when the job is done, failed or ctx ends.
	Run(ctx context.Context, job *Job, tn TargetNet) Result
}

// Transport is the kind of network access a module needs.
type Transport int

// Transports.
const (
	TransportTCP Transport = iota + 1
	TransportICMP
	TransportDNS
)

// Needs is a module's declared network use.
type Needs struct {
	Transport Transport
	// Ports the module may use without a target grant. The safety layer
	// intersects them with the compiled port allowlist and never-list.
	// Empty for ICMP.
	Ports []uint16
}

// Env describes the host to self-tests.
type Env struct {
	ClientKind  nodev1.ClientKind
	NetworkMode nodev1.NetworkMode
	// GOOS of the running binary, such as "linux".
	GOOS  string
	Probe HostProbe
}

// HostProbe answers self-test questions that need sockets the safety layer
// owns. It opens and closes sockets but sends nothing.
type HostProbe interface {
	// ICMP reports whether ICMP echo works for a family, and how it is timed.
	ICMP(family nodev1.AddressFamily) (ok bool, ts nodev1.TimestampSource, detail string)
	// Trace reports whether hop-limited path tracing works for a family, and how it is timed.
	Trace(family nodev1.AddressFamily) (ok bool, ts nodev1.TimestampSource, detail string)
	// HasIPv6 reports whether the host has a global IPv6 address.
	HasIPv6() bool
}

// Job is a verified, decoded job as a module sees it.
type Job struct {
	ID            string
	Attempt       uint32
	Class         nodev1.JobClass
	Kind          string
	KindVersion   uint32
	MeasurementID string
	// Target is exactly as the dispatcher signed it; the safety layer
	// validates it before the module runs.
	Target   *nodev1.Target
	Params   []byte
	Deadline time.Time
	Issued   time.Time
}

// Result is what a module returns. The runner adds the job and node ids,
// the connected address, load, network mode, client version and signature.
type Result struct {
	Outcome    nodev1.Outcome
	Error      nodev1.ErrorCode
	TSSource   nodev1.TimestampSource
	TxTSSource nodev1.TimestampSource
	// Bits from nodev1.ValidityFlag.
	ValidityFlags uint32
	// The kind's result message, serialised.
	Data []byte
}

// TargetNet is a job's only route to the network, bound to its validated
// target. It cannot reach any other host.
type TargetNet interface {
	// Host is the name for TLS SNI and the HTTP Host header.
	Host() string
	// Port is the validated destination port; 0 for ICMP.
	Port() uint16
	// Addr is the validated address the job connects to.
	Addr() netip.Addr
	// Resolution says how Addr was chosen.
	Resolution() nodev1.ResolutionSource
	// Verified reports whether the target carries a valid target grant.
	Verified() bool
	// DialTCP opens a TCP connection to Addr:Port. Each call is checked
	// against the deny ranges and the own-network refusal again.
	DialTCP(ctx context.Context) (net.Conn, error)
	// Pinger returns an ICMP echo sender bound to Addr, under the compiled
	// ICMP rate cap. It fails if the module did not declare TransportICMP
	// or ICMP is unavailable on this host.
	Pinger() (Pinger, error)
	// QueryDNS sends one recursive DNS query for Host to an allowlisted
	// resolver. It fails unless the module declared TransportDNS.
	QueryDNS(ctx context.Context, req DNSQuery) (DNSReply, error)
	// TraceHop sends one TTL-limited probe toward Addr and waits up to
	// timeout for a hop or destination response. Like Pinger.Echo, an error
	// whose Timeout method reports true means a probe left the node and no
	// response arrived in time; any other error means nothing was sent.
	TraceHop(ctx context.Context, proto string, ttl int, seq int, timeout time.Duration) (HopSample, error)
	// CheckHTTP enforces the compiled HTTP request rules for this target:
	// GET or HEAD only, and on unverified targets a short path with no
	// query string or userinfo.
	CheckHTTP(method, path string) error
	// ProbeHeaders are the attribution headers every HTTP request carries:
	// the Hopbits probe User-Agent and X-Hopbits-Probe with the measurement id.
	ProbeHeaders() http.Header
}

// DNSQuery is one recursive DNS query executed through TargetNet.
type DNSQuery struct {
	Qtype    string
	Resolver string
	Protocol string
	Timeout  time.Duration
}

// DNSAnswer is one parsed resource record in a DNS response.
type DNSAnswer struct {
	Name string
	Type string
	TTL  uint32
	Data string
}

// DNSReply is the parsed response of one DNS query.
type DNSReply struct {
	Qname         string
	Qtype         string
	Resolver      string
	Protocol      string
	Rcode         string
	RcodeNum      uint32
	Authoritative bool
	Truncated     bool
	RTT           time.Duration
	Answers       []DNSAnswer
}

// HopSample is the result of one TTL-limited trace probe.
type HopSample struct {
	// Addr is the responder's IP address, or invalid when redacted or lost.
	Addr     netip.Addr
	Redacted bool
	Reached  bool
	RTT      time.Duration
	// Protocol is the effective probe protocol ("udp" or "icmp").
	Protocol string
}

// Pinger sends ICMP echo requests to one address.
type Pinger interface {
	// Echo sends one echo request and waits for its reply, the timeout or ctx.
	Echo(ctx context.Context, seq uint16, timeout time.Duration) (EchoReply, error)
	// TimestampSource says how RTTs are timed.
	TimestampSource() nodev1.TimestampSource
	Close() error
}

// EchoReply is one ICMP echo reply.
type EchoReply struct {
	RTT time.Duration
	TTL int
}

// Lease is an admitted job's network access. The runner closes it when the
// job ends; modules only see the TargetNet.
type Lease interface {
	TargetNet
	Close() error
}

// Gate admits jobs to the network. The safety package's Guard implements it.
type Gate interface {
	// Admit validates the job's target against the compiled rules, charges
	// the compiled caps and returns the job's network access. It refuses
	// with a *Refusal carrying the error code for JobAck.
	Admit(ctx context.Context, job *Job, needs Needs) (Lease, error)
}
