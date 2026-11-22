// Package httpcheck is the node module for kind "http", version 1: one GET
// or HEAD request to the job's target, reporting the status, the timing
// phases, a capped and hashed body read, selected response headers and the
// redirect the response points to. Redirects are never followed, the body
// is discarded and every byte goes through the job's TargetNet.
package httpcheck

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/url"
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
	Kind    = "http"
	Version = 1
)

// Compiled limits of kind "http", version 1.
const (
	// DefaultTimeout applies when a job names no timeout.
	DefaultTimeout = 10 * time.Second
	// MinTimeout and MaxTimeout bound a job's timeout.
	MinTimeout = 2 * time.Second
	MaxTimeout = 30 * time.Second
	// MaxBodyBytes caps the body read. The bytes read are hashed and
	// discarded.
	MaxBodyBytes = 10_000
	// MaxResponseHeaders is how many response headers a job may ask for.
	MaxResponseHeaders = 8
	// MaxPathBytes caps the request path, query string included.
	MaxPathBytes = 2048

	// maxHeaderValueBytes caps each reported header value.
	maxHeaderValueBytes = 1024
	// maxResponseHeaderBytes caps the response header block the transport
	// reads.
	maxResponseHeaderBytes = 64 << 10
)

// allowedHeaders is the compiled allowlist of response headers a job may
// ask for.
var allowedHeaders = [...]string{
	"server", "content-type", "content-length", "cache-control", "age",
	"date", "last-modified", "etag", "via", "x-cache", "cf-cache-status",
	"cf-ray", "x-served-by", "strict-transport-security",
}

// Ports usable without a target grant: HTTPS on 443 and 8443, plain HTTP
// on 80 and 8080.
var (
	httpsPorts = [...]uint16{443, 8443}
	httpPorts  = [...]uint16{80, 8080}
)

// AllowedHeaders returns the compiled allowlist of response headers, in
// lower case.
func AllowedHeaders() []string {
	return slices.Clone(allowedHeaders[:])
}

// checker is the http module.
type checker struct {
	now func() time.Time
	// rootCAs replaces the system roots when set. Only tests set it.
	rootCAs *x509.CertPool
}

// New returns the http module.
func New() module.Module {
	return &checker{now: time.Now}
}

// Kind returns "http".
func (c *checker) Kind() string { return Kind }

// Version returns 1.
func (c *checker) Version() uint32 { return Version }

// Class returns the measure class.
func (c *checker) Class() nodev1.JobClass { return nodev1.JobClass_JOB_CLASS_MEASURE }

// Needs declares TCP to the HTTP and HTTPS ports.
func (c *checker) Needs() module.Needs {
	return module.Needs{Transport: module.TransportTCP, Ports: []uint16{80, 443, 8080, 8443}}
}

// SelfTest advertises HTTP with timing phases over IPv4, and over IPv6
// when the host has it. It sends nothing.
func (c *checker) SelfTest(_ context.Context, env module.Env) []protocol.Capability {
	q := append(kit.Families(env), kit.QualPhases, kit.QualTSUser)
	return []protocol.Capability{kit.Capability(Kind, Version, q...)}
}

// Check validates a job's params against the compiled limits.
func (c *checker) Check(job *module.Job) error {
	_, err := parse(job, c.now())
	return err
}

// params are an http job's params with defaults applied.
type params struct {
	method  string
	https   bool
	path    string
	timeout time.Duration
	// headers are lower-case names from the allowlist, without duplicates.
	headers []string
}

func (p params) scheme() string {
	if p.https {
		return "https"
	}
	return "http"
}

// parse decodes a job's params, applies the defaults and refuses anything
// outside the compiled limits with INVALID_PARAMS.
func parse(job *module.Job, now time.Time) (params, error) {
	var raw measurev1.HttpParams
	if err := kit.Decode(job.Params, &raw); err != nil {
		return params{}, err
	}
	p := params{method: http.MethodGet, https: true, path: "/", timeout: DefaultTimeout}

	switch raw.GetMethod() {
	case measurev1.HttpMethod_HTTP_METHOD_UNSPECIFIED, measurev1.HttpMethod_HTTP_METHOD_GET:
	case measurev1.HttpMethod_HTTP_METHOD_HEAD:
		p.method = http.MethodHead
	default:
		return params{}, kit.Invalid("method %v is neither GET nor HEAD", raw.GetMethod())
	}

	switch raw.GetScheme() {
	case measurev1.HttpScheme_HTTP_SCHEME_UNSPECIFIED, measurev1.HttpScheme_HTTP_SCHEME_HTTPS:
	case measurev1.HttpScheme_HTTP_SCHEME_HTTP:
		p.https = false
	default:
		return params{}, kit.Invalid("scheme %v is neither HTTPS nor HTTP", raw.GetScheme())
	}

	port, ok := kit.Port(job.Target)
	if !ok {
		return params{}, kit.Invalid("target port %d is out of range", job.Target.GetPort())
	}
	granted := kit.HasGrant(job.Target)
	if !granted && !portAllowed(p.https, port) && !kit.UnsafeTestPort(port) {
		return params{}, kit.Invalid("%s on port %d needs a target grant", p.scheme(), port)
	}

	if path := raw.GetPath(); path != "" {
		p.path = path
	}
	if err := checkPath(p.path, granted); err != nil {
		return params{}, err
	}

	if ms := raw.GetTimeoutMs(); ms != 0 {
		p.timeout = time.Duration(ms) * time.Millisecond
		if p.timeout < MinTimeout || p.timeout > MaxTimeout {
			return params{}, kit.Invalid("timeout %d ms is outside %v to %v", ms, MinTimeout, MaxTimeout)
		}
	}
	if err := kit.CheckWindow(job, p.timeout, now); err != nil {
		return params{}, err
	}

	names := raw.GetResponseHeaders()
	if len(names) > MaxResponseHeaders {
		return params{}, kit.Invalid("%d response headers asked for, at most %d allowed", len(names), MaxResponseHeaders)
	}
	for _, name := range names {
		lower := strings.ToLower(name)
		if !slices.Contains(allowedHeaders[:], lower) {
			return params{}, kit.Invalid("response header %q is not on the allowlist", name)
		}
		if !slices.Contains(p.headers, lower) {
			p.headers = append(p.headers, lower)
		}
	}
	return p, nil
}

// checkPath validates a request path. A query string needs a target grant;
// the safety layer's CheckHTTP applies the full rules again at run time.
func checkPath(path string, granted bool) error {
	if !strings.HasPrefix(path, "/") {
		return kit.Invalid("path %q does not start with /", path)
	}
	if len(path) > MaxPathBytes {
		return kit.Invalid("path is %d bytes, at most %d allowed", len(path), MaxPathBytes)
	}
	if _, err := url.ParseRequestURI(path); err != nil {
		return kit.Invalid("path does not parse: %v", err)
	}
	if !granted && strings.Contains(path, "?") {
		return kit.Invalid("a query string needs a target grant")
	}
	return nil
}

// portAllowed reports whether a scheme may use a port without a target
// grant.
func portAllowed(https bool, port uint16) bool {
	if https {
		return slices.Contains(httpsPorts[:], port)
	}
	return slices.Contains(httpPorts[:], port)
}
