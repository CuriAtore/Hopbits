package safety

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
)

// fakeClock is a deterministic clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeResolver answers from a fixed table, filtered by family. A name with
// no answer in the family is "not found".
type fakeResolver struct {
	m   map[string][]netip.Addr
	err error

	mu      sync.Mutex
	lookups int
}

func (r *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	r.lookups++
	r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	var out []netip.Addr
	for _, a := range r.m[host] {
		a = a.Unmap()
		if network == "ip6" && a.Is6() && !a.Is4() {
			out = append(out, a)
		}
		if network == "ip4" && a.Is4() {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

func (r *fakeResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookups
}

// timeoutErr is a net.Error reporting a timeout.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "lookup timed out" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// fakeGrants returns a fixed grant, as a verified signature would.
type fakeGrants struct {
	grant *nodev1.TargetGrant
	err   error
}

func (g *fakeGrants) VerifyGrant(sg *nodev1.SignedTargetGrant, now time.Time) (*nodev1.TargetGrant, error) {
	if g.err != nil {
		return nil, g.err
	}
	return g.grant, nil
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// targetOpt customises a Target.
type targetOpt func(*nodev1.Target)

func pinned(a string) targetOpt {
	return func(t *nodev1.Target) { t.PinnedAddress = a }
}

func proven(as ...string) targetOpt {
	return func(t *nodev1.Target) { t.ProvenAddresses = as }
}

func withGrant() targetOpt {
	return func(t *nodev1.Target) { t.Grant = &nodev1.SignedTargetGrant{Body: []byte("b"), Sig: []byte("s")} }
}

func mkJob(host string, port uint16, fam nodev1.AddressFamily, opts ...targetOpt) *module.Job {
	t := &nodev1.Target{Host: host, Port: uint32(port), Family: fam}
	for _, o := range opts {
		o(t)
	}
	return &module.Job{ID: "j1", MeasurementID: "m1", Target: t}
}

var (
	tcp443 = module.Needs{Transport: module.TransportTCP, Ports: []uint16{80, 443}}
	icmpN  = module.Needs{Transport: module.TransportICMP}
	v4     = nodev1.AddressFamily_ADDRESS_FAMILY_IPV4
	v6     = nodev1.AddressFamily_ADDRESS_FAMILY_IPV6
	unspec = nodev1.AddressFamily_ADDRESS_FAMILY_UNSPECIFIED
)

func wantCode(t *testing.T, err error, code nodev1.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected refusal %s, got nil", code)
	}
	if got := module.CodeOf(err); got != code {
		t.Fatalf("expected code %s, got %s (%v)", code, got, err)
	}
}

// newGuard builds a guard on a fake clock. It never uses the system
// resolver: without res, every lookup answers "not found".
func newGuard(t *testing.T, caps Caps, res *fakeResolver, grants GrantVerifier) (*Guard, *fakeClock) {
	t.Helper()
	clk := newClock()
	if res == nil {
		res = &fakeResolver{}
	}
	return NewGuard(Config{Caps: caps, Now: clk.now, Grants: grants, Resolver: res}), clk
}

// admit admits a job and closes its lease, failing the test on a refusal.
func admit(t *testing.T, g *Guard, job *module.Job, needs module.Needs) module.Lease {
	t.Helper()
	l, err := g.Admit(context.Background(), job, needs)
	if err != nil {
		t.Fatalf("admit %s: %v", job.Target.GetHost(), err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestAdmitPortPolicy(t *testing.T) {
	grantHost := "granted.example.com"
	expires := time.Date(2026, 1, 1, 13, 0, 0, 0, time.UTC).Unix()
	grantRes := &fakeResolver{m: map[string][]netip.Addr{grantHost: {addr("8.8.8.8")}}}
	futureGrant := &fakeGrants{grant: &nodev1.TargetGrant{
		Hostname:        grantHost,
		ProvenAddresses: []string{"8.8.8.8"},
		Ports:           []uint32{8081},
		ExpiresUnix:     expires,
	}}

	tests := []struct {
		name   string
		job    *module.Job
		needs  module.Needs
		grants GrantVerifier
		code   nodev1.ErrorCode // 0 means success
	}{
		{"icmp nonzero port", mkJob("8.8.8.8", 7, v4, pinned("8.8.8.8")), icmpN, nil, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY},
		{"icmp ok", mkJob("8.8.8.8", 0, v4, pinned("8.8.8.8")), icmpN, nil, 0},
		{"tcp allowed port", mkJob("8.8.8.8", 443, v4, pinned("8.8.8.8")), tcp443, nil, 0},
		{"tcp never port", mkJob("8.8.8.8", 22, v4, pinned("8.8.8.8")), module.Needs{Transport: module.TransportTCP, Ports: []uint16{22}}, nil, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY},
		{"tcp never port with grant", mkJob(grantHost, 22, v4, proven("8.8.8.8"), withGrant()), module.Needs{Transport: module.TransportTCP, Ports: []uint16{22}}, &fakeGrants{grant: &nodev1.TargetGrant{Hostname: grantHost, ProvenAddresses: []string{"8.8.8.8"}, Ports: []uint32{22}, ExpiresUnix: expires}}, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY},
		{"tcp unlisted port no grant", mkJob("8.8.8.8", 8081, v4, pinned("8.8.8.8")), module.Needs{Transport: module.TransportTCP, Ports: []uint16{8081}}, nil, nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING},
		{"tcp allowed but not in needs", mkJob("8.8.8.8", 8080, v4, pinned("8.8.8.8")), tcp443, nil, nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING},
		{"tcp unlisted port with grant", mkJob(grantHost, 8081, v4, proven("8.8.8.8"), withGrant()), module.Needs{Transport: module.TransportTCP, Ports: []uint16{8081}}, futureGrant, 0},
		// A grant names its hostname at its proven addresses only: a
		// server-pinned job never gets the grant's ports.
		{"grant on a pinned target", mkJob(grantHost, 8081, v4, pinned("8.8.8.8"), withGrant()), module.Needs{Transport: module.TransportTCP, Ports: []uint16{8081}}, futureGrant, nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := newGuard(t, AgentCaps(), grantRes, tc.grants)
			lease, err := g.Admit(context.Background(), tc.job, tc.needs)
			if tc.code == 0 {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				lease.Close()
				return
			}
			wantCode(t, err, tc.code)
			if lease != nil {
				t.Fatal("expected nil lease on refusal")
			}
		})
	}
}

func TestAdmitPauseHost(t *testing.T) {
	res := &fakeResolver{m: map[string][]netip.Addr{
		PauseHost: {addr("8.8.4.4"), addr("2606:4700::1111")},
	}}
	g, _ := newGuard(t, AgentCaps(), res, nil)
	for _, h := range []string{PauseHost, "PAUSE.ANCHOR.HOPBITS.IO", PauseHost + "."} {
		_, err := g.Admit(context.Background(), mkJob(h, 0, v4, pinned("8.8.8.8")), icmpN)
		wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY)
	}
	// The pause host's addresses are refused under any other name, for
	// every kind of job.
	cases := []struct {
		job   *module.Job
		needs module.Needs
	}{
		{mkJob("other.example.com", 443, v4, pinned("8.8.4.4")), tcp443},
		{mkJob("8.8.4.4", 0, v4, pinned("8.8.4.4")), icmpN},
		{mkJob("other.example.com", 0, v6, pinned("2606:4700::1111")), icmpN},
	}
	for _, c := range cases {
		_, err := g.Admit(context.Background(), c.job, c.needs)
		wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
	}
	admit(t, g, mkJob("other.example.com", 443, v4, pinned("8.8.8.8")), tcp443)
}

func TestAdmitCanonicalHost(t *testing.T) {
	// A trailing dot or upper case is the same name: one domain for the
	// caps, one name on the wire.
	g, clk := newGuard(t, AgentCaps(), nil, nil)
	l := admit(t, g, mkJob("H0.Victim.COM.", 443, v4, pinned("8.8.8.1")), tcp443)
	if got := l.Host(); got != "h0.victim.com" {
		t.Fatalf("lease host %q, want the canonical name", got)
	}
	clk.advance(10 * time.Second)
	_, err := g.Admit(context.Background(), mkJob("h1.victim.com.", 443, v4, pinned("9.9.9.1")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED)

	// Six jobs to one domain in 59 minutes, whatever the spelling; the
	// seventh is refused.
	g, clk = newGuard(t, AgentCaps(), nil, nil)
	for i := range 6 {
		host := fmt.Sprintf("h%d.victim.com", i)
		if i%2 == 1 {
			host += "."
		}
		admit(t, g, mkJob(host, 443, v4, pinned(fmt.Sprintf("8.8.%d.1", i))), tcp443)
		clk.advance(56 * time.Second)
	}
	_, err = g.Admit(context.Background(), mkJob("h7.victim.com.", 443, v4, pinned("8.8.7.1")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED)

	bad := []string{
		"",
		"victim.com..",
		".victim.com",
		"a..b.com",
		"vic tim.com",
		"victim.com/x",
		"vic\x00tim.com",
		"bücher.example",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 127) + "com",
		strings.Repeat("x", 600*1024),
	}
	for _, h := range bad {
		g, _ := newGuard(t, AgentCaps(), nil, nil)
		_, err := g.Admit(context.Background(), mkJob(h, 443, v4, pinned("8.8.8.8")), tcp443)
		wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION)
	}
	for in, want := range map[string]string{
		"Example.COM":   "example.com",
		"example.com.":  "example.com",
		"_srv.ex-1.com": "_srv.ex-1.com",
		"8.8.8.8":       "8.8.8.8",
		"2001:DB8::1":   "2001:db8::1",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + ".": strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61),
	} {
		if got, err := CanonicalHost(in); err != nil || got != want {
			t.Errorf("CanonicalHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	for in, want := range map[string]string{
		"www.example.com":   "example.com",
		"API.Example.COM.":  "example.com",
		"a.b.example.co.uk": "example.co.uk",
		"example.com":       "example.com",
		"localhost":         "localhost",
		"8.8.8.8":           "8.8.8.8",
		"::ffff:8.8.8.8":    "8.8.8.8",
		"2001:db8::1":       "2001:db8::1",
	} {
		if got := RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAdmitMeasurementID(t *testing.T) {
	for _, id := range []string{"", strings.Repeat("m", 65), "m 1", "m.1", "m\n1", strings.Repeat("x", 600*1024)} {
		g, _ := newGuard(t, AgentCaps(), nil, nil)
		job := mkJob("8.8.8.8", 443, v4, pinned("8.8.8.8"))
		job.MeasurementID = id
		_, err := g.Admit(context.Background(), job, tcp443)
		wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION)
	}
	g, _ := newGuard(t, AgentCaps(), nil, nil)
	job := mkJob("8.8.8.8", 443, v4, pinned("8.8.8.8"))
	job.MeasurementID = "0123456789abcdef0123456789ABCDEF_-" + strings.Repeat("z", 29)
	l := admit(t, g, job, tcp443)
	if got := l.ProbeHeaders().Get(ProbeHeader); got != job.MeasurementID {
		t.Fatalf("probe header %q", got)
	}
}

func TestAdmitAnchorDomain(t *testing.T) {
	res := &fakeResolver{m: map[string][]netip.Addr{
		"anchor.hopbits.io":     {addr("8.8.8.8")},
		"sub.anchor.hopbits.io": {addr("1.1.1.1")},
	}}
	g, clk := newGuard(t, AgentCaps(), res, nil)

	// No pinned address needed; resolves locally.
	lease, err := g.Admit(context.Background(), mkJob("anchor.hopbits.io", 443, v4), tcp443)
	if err != nil {
		t.Fatalf("anchor admit: %v", err)
	}
	if lease.Resolution() != nodev1.ResolutionSource_RESOLUTION_SOURCE_LOCAL {
		t.Fatalf("resolution = %v, want LOCAL", lease.Resolution())
	}
	if lease.Addr() != addr("8.8.8.8") {
		t.Fatalf("addr = %v, want 8.8.8.8", lease.Addr())
	}
	lease.Close()

	// Pinned address among the answers is honoured. (Same registrable domain,
	// so honour the 55 s spacing between the two successful admits.)
	clk.advance(55 * time.Second)
	lease, err = g.Admit(context.Background(), mkJob("sub.anchor.hopbits.io", 443, v4, pinned("1.1.1.1")), tcp443)
	if err != nil {
		t.Fatalf("anchor pinned admit: %v", err)
	}
	lease.Close()

	// Pinned address outside the answers is refused.
	_, err = g.Admit(context.Background(), mkJob("anchor.hopbits.io", 443, v4, pinned("9.9.9.9")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY)

	// A label-boundary lookalike is not an anchor domain; without a pinned
	// address it is a protocol violation.
	_, err = g.Admit(context.Background(), mkJob("xanchor.hopbits.io", 443, v4), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION)
}

func TestAdmitProvenSets(t *testing.T) {
	host := "proven.example.com"
	res := &fakeResolver{m: map[string][]netip.Addr{host: {addr("8.8.4.4")}}}
	goodGrant := &fakeGrants{grant: &nodev1.TargetGrant{
		Hostname:        host,
		ProvenAddresses: []string{"8.8.4.4"},
		ExpiresUnix:     time.Date(2026, 1, 1, 13, 0, 0, 0, time.UTC).Unix(),
	}}

	// No grant -> GRANT_MISSING.
	g, _ := newGuard(t, AgentCaps(), res, nil)
	_, err := g.Admit(context.Background(), mkJob(host, 443, v4, proven("8.8.4.4"), withGrant()), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING)

	// Valid grant, answer in both sets -> verified lease.
	g, _ = newGuard(t, AgentCaps(), res, goodGrant)
	lease, err := g.Admit(context.Background(), mkJob(host, 443, v4, proven("8.8.4.4"), withGrant()), tcp443)
	if err != nil {
		t.Fatalf("proven admit: %v", err)
	}
	if !lease.Verified() {
		t.Fatal("expected Verified() true")
	}
	if lease.Resolution() != nodev1.ResolutionSource_RESOLUTION_SOURCE_LOCAL {
		t.Fatalf("resolution = %v, want LOCAL", lease.Resolution())
	}
	lease.Close()

	// Resolver answer not in the proven set -> REFUSED_LOCALLY.
	res2 := &fakeResolver{m: map[string][]netip.Addr{host: {addr("8.8.8.8")}}}
	g, _ = newGuard(t, AgentCaps(), res2, goodGrant)
	_, err = g.Admit(context.Background(), mkJob(host, 443, v4, proven("8.8.4.4"), withGrant()), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY)

	// Expired grant -> GRANT_MISSING.
	expired := &fakeGrants{grant: &nodev1.TargetGrant{
		Hostname:        host,
		ProvenAddresses: []string{"8.8.4.4"},
		ExpiresUnix:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
	}}
	g, _ = newGuard(t, AgentCaps(), res, expired)
	_, err = g.Admit(context.Background(), mkJob(host, 443, v4, proven("8.8.4.4"), withGrant()), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING)

	// More proven addresses than a job may carry -> PROTOCOL_VIOLATION.
	many := make([]string, MaxProvenAddresses+1)
	for i := range many {
		many[i] = fmt.Sprintf("8.8.4.%d", i+1)
	}
	g, _ = newGuard(t, AgentCaps(), res, goodGrant)
	_, err = g.Admit(context.Background(), mkJob(host, 443, v4, proven(many...), withGrant()), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION)
}

func TestGrantLiftsWindowOnlyAtProvenAddresses(t *testing.T) {
	host := "victim.com"
	grant := &fakeGrants{grant: &nodev1.TargetGrant{
		Hostname:        host,
		ProvenAddresses: []string{"9.9.9.9"},
		Ports:           []uint32{8000},
		ExpiresUnix:     time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC).Unix(),
	}}
	g, clk := newGuard(t, AgentCaps(), nil, grant)
	// Pinned outside the proven set: the grant counts for nothing.
	l := admit(t, g, mkJob(host, 443, v4, pinned("8.8.8.8"), withGrant()), tcp443)
	if l.Verified() {
		t.Fatal("a server-pinned target reports Verified")
	}
	for i := 1; i < 6; i++ {
		clk.advance(56 * time.Second)
		admit(t, g, mkJob(host, 443, v4, pinned(fmt.Sprintf("8.8.%d.8", i)), withGrant()), tcp443)
	}
	clk.advance(56 * time.Second)
	_, err := g.Admit(context.Background(), mkJob(host, 443, v4, pinned("8.8.200.8"), withGrant()), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED)

	// At its proven address the grant lifts the window: only the 55 s
	// spacing applies.
	res := &fakeResolver{m: map[string][]netip.Addr{host: {addr("9.9.9.9")}}}
	g, clk = newGuard(t, AgentCaps(), res, grant)
	for range 10 {
		l := admit(t, g, mkJob(host, 8000, v4, proven("9.9.9.9"), withGrant()),
			module.Needs{Transport: module.TransportTCP, Ports: []uint16{443}})
		if !l.Verified() {
			t.Fatal("a proven address is not verified")
		}
		clk.advance(56 * time.Second)
	}
}

func TestAdmitPinnedAndLiteral(t *testing.T) {
	g, clk := newGuard(t, AgentCaps(), nil, nil)

	// Literal host with matching pinned address.
	lease, err := g.Admit(context.Background(), mkJob("8.8.8.8", 443, v4, pinned("8.8.8.8")), tcp443)
	if err != nil {
		t.Fatalf("literal admit: %v", err)
	}
	if lease.Resolution() != nodev1.ResolutionSource_RESOLUTION_SOURCE_SERVER {
		t.Fatalf("resolution = %v, want SERVER", lease.Resolution())
	}
	lease.Close()

	// Literal host, pinned address differs -> REFUSED_LOCALLY.
	_, err = g.Admit(context.Background(), mkJob("8.8.8.8", 443, v4, pinned("1.1.1.1")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY)

	// Hostname with no pinned address -> PROTOCOL_VIOLATION.
	_, err = g.Admit(context.Background(), mkJob("host.example.com", 443, v4), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION)

	// Pinned address of the wrong family -> PROTOCOL_VIOLATION.
	_, err = g.Admit(context.Background(), mkJob("host.example.com", 443, v6, pinned("8.8.8.8")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION)

	// Unspecified family accepts any pinned address. (Reuses 8.8.8.8, so
	// honour the 55 s destination spacing after the first literal admit.)
	clk.advance(55 * time.Second)
	lease, err = g.Admit(context.Background(), mkJob("host.example.com", 443, unspec, pinned("8.8.8.8")), tcp443)
	if err != nil {
		t.Fatalf("unspecified family admit: %v", err)
	}
	lease.Close()
}

func TestAdmitDeniedAddresses(t *testing.T) {
	g, _ := newGuard(t, AgentCaps(), nil, nil)
	for _, a := range []string{"10.0.0.1", "169.254.169.254", "127.0.0.1", "192.168.1.1"} {
		_, err := g.Admit(context.Background(), mkJob(a, 443, v4, pinned(a)), tcp443)
		wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
	}
}

func TestAdmitOwnNetwork(t *testing.T) {
	// Observed IPv4 widened to /24.
	g, _ := newGuard(t, AgentCaps(), nil, nil)
	g.SetOwnNetwork(nil, []netip.Addr{addr("9.9.9.9")})
	_, err := g.Admit(context.Background(), mkJob("9.9.9.200", 443, v4, pinned("9.9.9.200")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
	lease, err := g.Admit(context.Background(), mkJob("9.9.10.1", 443, v4, pinned("9.9.10.1")), tcp443)
	if err != nil {
		t.Fatalf("outside /24 should be allowed: %v", err)
	}
	lease.Close()

	// Interface prefix.
	g, _ = newGuard(t, AgentCaps(), nil, nil)
	g.SetOwnNetwork([]netip.Prefix{netip.MustParsePrefix("45.44.0.0/16")}, nil)
	_, err = g.Admit(context.Background(), mkJob("45.44.1.1", 443, v4, pinned("45.44.1.1")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)

	// Observed IPv6 widened to /48.
	g, _ = newGuard(t, AgentCaps(), nil, nil)
	g.SetOwnNetwork(nil, []netip.Addr{addr("2606:4700:4700::1")})
	_, err = g.Admit(context.Background(), mkJob("host.example.com", 443, v6, pinned("2606:4700:4700:1::9")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
	lease, err = g.Admit(context.Background(), mkJob("host.example.com", 443, v6, pinned("2606:4700:4701::9")), tcp443)
	if err != nil {
		t.Fatalf("outside /48 should be allowed: %v", err)
	}
	lease.Close()
}

func TestRefuseFamilies(t *testing.T) {
	g, clk := newGuard(t, AgentCaps(), nil, nil)
	g.RefuseFamilies(true, false)
	_, err := g.Admit(context.Background(), mkJob("a.example.com", 443, v4, pinned("8.8.8.8")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
	_, err = g.Admit(context.Background(), mkJob("8.8.8.8", 0, v4, pinned("8.8.8.8")), icmpN)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
	admit(t, g, mkJob("b.example.com", 443, v6, pinned("2606:4700::6810:1")), tcp443)

	g.RefuseFamilies(false, true)
	clk.advance(time.Minute)
	_, err = g.Admit(context.Background(), mkJob("c.example.com", 443, v6, pinned("2606:4700::6810:2")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
	admit(t, g, mkJob("d.example.com", 443, v4, pinned("8.8.8.8")), tcp443)

	g.RefuseFamilies(false, false)
	clk.advance(time.Minute)
	admit(t, g, mkJob("e.example.com", 443, v6, pinned("2606:4700::6810:3")), tcp443)
}

func TestAdmitAddDenyAndDoNotProbe(t *testing.T) {
	g, _ := newGuard(t, AgentCaps(), nil, nil)
	g.AddDenyPrefixes([]netip.Prefix{netip.MustParsePrefix("45.45.0.0/16")})
	_, err := g.Admit(context.Background(), mkJob("45.45.1.1", 443, v4, pinned("45.45.1.1")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)

	g.SetDoNotProbe([]string{"46.46.0.0/16", "example.net", ".dnptest.com", "Opted-Out.example."})
	cases := []struct {
		host, pin string
	}{
		{"46.46.1.1", "46.46.1.1"},          // CIDR
		{"example.net", "8.8.8.8"},          // exact host
		{"EXAMPLE.NET.", "8.8.8.8"},         // exact host, another spelling
		{"x.dnptest.com", "8.8.8.8"},        // suffix subdomain
		{"x.dnptest.com.", "8.8.8.8"},       // suffix subdomain, trailing dot
		{"dnptest.com", "8.8.8.8"},          // suffix apex
		{"opted-out.example", "8.8.8.8"},    // entry with case and a dot
		{"other.example.org", "46.46.9.9"},  // CIDR under another name
		{"opted-out.example.", "46.47.1.1"}, // exact under its trailing dot
	}
	for _, c := range cases {
		_, err := g.Admit(context.Background(), mkJob(c.host, 443, v4, pinned(c.pin)), tcp443)
		wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
	}

	// A different host is allowed.
	lease, err := g.Admit(context.Background(), mkJob("allowed.example.org", 443, v4, pinned("8.8.8.8")), tcp443)
	if err != nil {
		t.Fatalf("unrelated host should be allowed: %v", err)
	}
	lease.Close()
}

func TestNAT64(t *testing.T) {
	// RFC 6052 section 2.4 examples: 192.0.2.33 under each prefix length.
	examples := []struct {
		addr string
		bits int
	}{
		{"2001:db8:c000:221::", 32},
		{"2001:db8:1c0:2:21::", 40},
		{"2001:db8:122:c000:2:2100::", 48},
		{"2001:db8:122:3c0:0:221::", 56},
		{"2001:db8:122:344:c0:2:2100:0", 64},
		{"2001:db8:122:344::192.0.2.33", 96},
	}
	for _, e := range examples {
		got, ok := embeddedIPv4(addr(e.addr), e.bits)
		if !ok || got != addr("192.0.2.33") {
			t.Errorf("embeddedIPv4(%s, %d) = %v, %v", e.addr, e.bits, got, ok)
		}
	}
	if _, ok := embeddedIPv4(addr("2001:db8::1"), 80); ok {
		t.Error("an 80-bit prefix is not a NAT64 prefix")
	}

	// Discovery from ipv4only.arpa answers, longest prefix first.
	got := nat64Prefixes([]netip.Addr{
		addr("2001:db8:aaaa::c000:aa"),         // /96 with 192.0.0.170
		addr("2001:db8:aaaa::c000:ab"),         // the same /96 with 192.0.0.171
		addr("2001:db8:bbbb:cccc:c0:0:aa00:0"), // /64 with 192.0.0.170
		addr("2001:db8::1"),                    // no well-known address
	})
	want := []netip.Prefix{netip.MustParsePrefix("2001:db8:aaaa::/96"), netip.MustParsePrefix("2001:db8:bbbb:cccc::/64")}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("nat64Prefixes = %v, want %v", got, want)
	}

	// A network-specific NAT64 prefix outside the node's networks: an
	// address under it is judged by the IPv4 address it reaches.
	res := &fakeResolver{m: map[string][]netip.Addr{
		ipv4OnlyARPA: {addr("2a01:4f8:aaaa::c000:aa"), addr("2a01:4f8:aaaa::c000:ab")},
	}}
	g, clk := newGuard(t, AgentCaps(), res, nil)
	for _, a := range []string{"2a01:4f8:aaaa::a00:1", "2a01:4f8:aaaa::a9fe:a9fe", "2a01:4f8:aaaa::7f00:1"} {
		_, err := g.Admit(context.Background(), mkJob("nat.example.com", 443, v6, pinned(a)), tcp443)
		wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
		_, err = g.Admit(context.Background(), mkJob(a, 0, v6, pinned(a)), icmpN)
		wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
	}
	// The own IPv4 network counts through the NAT64 too.
	g.SetOwnNetwork(nil, []netip.Addr{addr("8.8.8.8")})
	_, err := g.Admit(context.Background(), mkJob("nat.example.com", 443, v6, pinned("2a01:4f8:aaaa::808:801")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
	// A public IPv4 address through the NAT64 is fine.
	l, err := g.Admit(context.Background(), mkJob("nat.example.com", 443, v6, pinned("2a01:4f8:aaaa::101:101")), tcp443)
	if err != nil {
		t.Fatalf("NAT64 of a public address: %v", err)
	}
	// The dial re-check judges the embedded address with the rules in force.
	g.AddDenyPrefixes([]netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")})
	if _, err := l.DialTCP(context.Background()); module.CodeOf(err) != nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL {
		t.Fatalf("dial through the NAT64 to a denied prefix: %v", err)
	}
	l.Close()

	// The prefixes are learnt once per window, not per job.
	before := res.count()
	clk.advance(time.Minute)
	admit(t, g, mkJob("nat2.example.org", 443, v6, pinned("2a01:4f8:aaaa::909:909")), tcp443)
	if res.count() != before {
		t.Fatalf("the guard looked up its local names again within %v", localTTL)
	}
	clk.advance(localTTL)
	admit(t, g, mkJob("nat3.example.net", 443, v6, pinned("2a01:4f8:aaaa::909:a09")), tcp443)
	if res.count() == before {
		t.Fatal("the guard never looked up its local names again")
	}
}

// TestAgentCapsCompiled pins every compiled cap of the native node. The docs
// for operators (landing/lib/docs/content/nodes.ts), the README, the server's
// pacing copy (server/internal/dispatch/select.go) and architecture section 12
// state the same numbers: change them together or not at all.
func TestAgentCapsCompiled(t *testing.T) {
	want := Caps{
		JobsPerMinute:        300,
		MaxConcurrency:       16,
		DomainSpacing:        55 * time.Second,
		DomainJobsPerWindow:  6,
		DomainWindow:         59 * time.Minute,
		ICMPPacketsPerSecond: 50,
		MaxPingPackets:       16,
		MaxTraceroutePackets: 90,
		DailyTrafficBytes:    200 << 20,
	}
	if got := AgentCaps(); got != want {
		t.Fatalf("compiled agent caps = %+v, want %+v", got, want)
	}
}

func TestAdmitConcurrencyCap(t *testing.T) {
	g, _ := newGuard(t, AgentCaps(), nil, nil)
	// As many leases as the compiled cap allows, each to its own domain and its own /24.
	var leases []module.Lease
	for i := range AgentCaps().MaxConcurrency {
		host, address := fmt.Sprintf("h.cap%d.com", i), fmt.Sprintf("8.%d.8.8", i+1)
		l, err := g.Admit(context.Background(), mkJob(host, 443, v4, pinned(address)), tcp443)
		if err != nil {
			t.Fatalf("admit %s: %v", host, err)
		}
		leases = append(leases, l)
	}
	// One more exceeds concurrency.
	_, err := g.Admit(context.Background(), mkJob("e.eee.com", 443, v4, pinned("45.45.45.45")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_CAPACITY)

	// Close one and retry; Close is idempotent.
	leases[0].Close()
	leases[0].Close()
	l, err := g.Admit(context.Background(), mkJob("e.eee.com", 443, v4, pinned("45.45.45.45")), tcp443)
	if err != nil {
		t.Fatalf("after close: %v", err)
	}
	l.Close()
	for _, l := range leases[1:] {
		l.Close()
	}
}

func TestAdmitJobsPerMinute(t *testing.T) {
	caps := Caps{JobsPerMinute: 3, MaxConcurrency: 100, MaxPingPackets: 16}
	g, clk := newGuard(t, caps, nil, nil)
	for i := 0; i < 3; i++ {
		admit(t, g, mkJob("8.8.8.8", 443, v4, pinned("8.8.8.8")), tcp443)
	}
	_, err := g.Admit(context.Background(), mkJob("8.8.8.8", 443, v4, pinned("8.8.8.8")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED)

	clk.advance(61 * time.Second)
	admit(t, g, mkJob("8.8.8.8", 443, v4, pinned("8.8.8.8")), tcp443)
}

func TestAdmitSpacing(t *testing.T) {
	caps := Caps{JobsPerMinute: 100, MaxConcurrency: 100, DomainSpacing: 55 * time.Second, MaxPingPackets: 16}

	// Per-domain spacing: same registrable domain, different /24.
	g, clk := newGuard(t, caps, nil, nil)
	admit(t, g, mkJob("a.spacetest.com", 443, v4, pinned("8.8.8.8")), tcp443)
	_, err := g.Admit(context.Background(), mkJob("b.spacetest.com", 443, v4, pinned("1.1.1.1")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED)
	clk.advance(55 * time.Second)
	admit(t, g, mkJob("b.spacetest.com", 443, v4, pinned("1.1.1.1")), tcp443)

	// Per-/24 spacing: different registrable domain, same /24.
	g, clk = newGuard(t, caps, nil, nil)
	admit(t, g, mkJob("a.alpha-dom.com", 443, v4, pinned("11.12.13.1")), tcp443)
	_, err = g.Admit(context.Background(), mkJob("b.beta-dom.com", 443, v4, pinned("11.12.13.2")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED)
	clk.advance(55 * time.Second)
	admit(t, g, mkJob("b.beta-dom.com", 443, v4, pinned("11.12.13.2")), tcp443)
}

func TestAdmitDomainWindow(t *testing.T) {
	// Agent caps: 6 jobs per 59 minutes per domain, 55 s spacing.
	g, clk := newGuard(t, AgentCaps(), nil, nil)
	for i := 0; i < 6; i++ {
		admit(t, g, mkJob("win.example.com", 443, v4, pinned("8.8.8.8")), tcp443)
		clk.advance(55 * time.Second)
	}
	_, err := g.Admit(context.Background(), mkJob("win.example.com", 443, v4, pinned("8.8.8.8")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED)
}

func TestAdmitAnchorDomainWindowExempt(t *testing.T) {
	res := &fakeResolver{m: map[string][]netip.Addr{"anchor.hopbits.io": {addr("8.8.8.8")}}}
	g, clk := newGuard(t, AgentCaps(), res, nil)
	for i := 0; i < 8; i++ {
		admit(t, g, mkJob("anchor.hopbits.io", 443, v4), tcp443)
		clk.advance(55 * time.Second)
	}
}

func TestGuardMapsShrink(t *testing.T) {
	caps := AgentCaps()
	caps.JobsPerMinute = 1000
	caps.MaxConcurrency = 1000
	caps.DailyTrafficBytes = 1000
	g, clk := newGuard(t, caps, nil, nil)

	// Refused jobs leave nothing behind.
	g.addTraffic(1000)
	for i := range 200 {
		_, err := g.Admit(context.Background(), mkJob(fmt.Sprintf("h%d.refused%d.com", i, i), 443, v4,
			pinned(fmt.Sprintf("8.%d.%d.1", i/200+1, i%200))), tcp443)
		wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_BUDGET_EXHAUSTED)
		clk.advance(time.Second)
	}
	g.mu.Lock()
	n := len(g.lastDomain) + len(g.lastPrefix) + len(g.domainHits)
	g.mu.Unlock()
	if n != 0 {
		t.Fatalf("refused jobs left %d map entries", n)
	}

	// Admitted jobs are forgotten once they can no longer refuse a job.
	clk.advance(24 * time.Hour)
	for i := range 100 {
		admit(t, g, mkJob(fmt.Sprintf("h.admitted%d.com", i), 443, v4,
			pinned(fmt.Sprintf("9.%d.%d.1", i/200+1, i%200))), tcp443)
		clk.advance(time.Second)
	}
	clk.advance(caps.DomainWindow + sweepEvery)
	admit(t, g, mkJob("last.example.org", 443, v4, pinned("8.8.8.8")), tcp443)
	g.mu.Lock()
	sizes := []int{len(g.lastDomain), len(g.lastPrefix), len(g.domainHits)}
	g.mu.Unlock()
	if sizes[0] != 1 || sizes[1] != 1 || sizes[2] != 1 {
		t.Fatalf("maps hold %v entries after the window passed, want only the last job", sizes)
	}
}

func TestAdmitDailyTraffic(t *testing.T) {
	caps := Caps{JobsPerMinute: 100, MaxConcurrency: 100, DailyTrafficBytes: 1000, MaxPingPackets: 16}

	// Budget exhausted.
	g, _ := newGuard(t, caps, nil, nil)
	g.addTraffic(1000)
	_, err := g.Admit(context.Background(), mkJob("8.8.8.8", 443, v4, pinned("8.8.8.8")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_BUDGET_EXHAUSTED)

	// Under budget.
	g, _ = newGuard(t, caps, nil, nil)
	g.addTraffic(500)
	admit(t, g, mkJob("8.8.8.8", 443, v4, pinned("8.8.8.8")), tcp443)

	// Rolls over at the UTC day boundary.
	g, clk := newGuard(t, caps, nil, nil)
	g.addTraffic(1000)
	clk.advance(24 * time.Hour)
	admit(t, g, mkJob("8.8.8.8", 443, v4, pinned("8.8.8.8")), tcp443)

	// Anchor caps never exhaust (DailyTrafficBytes 0).
	g, _ = newGuard(t, AnchorCaps(), nil, nil)
	g.addTraffic(1 << 40)
	admit(t, g, mkJob("8.8.8.8", 443, v4, pinned("8.8.8.8")), tcp443)
}

func TestTrafficSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	caps := Caps{JobsPerMinute: 100, MaxConcurrency: 100, DailyTrafficBytes: 3 << 20, MaxPingPackets: 16}
	clk := newClock()
	cfg := Config{Caps: caps, Now: clk.now, Resolver: &fakeResolver{}, TrafficFile: path}

	g := NewGuard(cfg)
	g.addTraffic(3 << 20)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("no traffic file after 3 MiB: %v", err)
	}
	// A restart the same day resumes the count.
	g = NewGuard(cfg)
	_, err := g.Admit(context.Background(), mkJob("8.8.8.8", 443, v4, pinned("8.8.8.8")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_BUDGET_EXHAUSTED)

	// A restart on the next day starts fresh.
	clk.advance(24 * time.Hour)
	g = NewGuard(cfg)
	admit(t, g, mkJob("8.8.8.8", 443, v4, pinned("8.8.8.8")), tcp443)

	// A damaged file counts nothing.
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Minute)
	g = NewGuard(cfg)
	admit(t, g, mkJob("1.1.1.1", 443, v4, pinned("1.1.1.1")), tcp443)
}

func TestAdmitRefusesAnEndedJob(t *testing.T) {
	g, _ := newGuard(t, AgentCaps(), nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := g.Admit(ctx, mkJob("a.example.com", 443, v4, pinned("8.8.8.8")), tcp443)
	if err == nil {
		t.Fatal("a cancelled job was admitted")
	}
	// Nothing was charged: the same destination is admitted at once.
	admit(t, g, mkJob("a.example.com", 443, v4, pinned("8.8.8.8")), tcp443)
}

func TestCheckHTTP(t *testing.T) {
	tests := []struct {
		name     string
		verified bool
		method   string
		path     string
		ok       bool
	}{
		{"get root", false, "GET", "/", true},
		{"head root", false, "HEAD", "/", true},
		{"post", false, "POST", "/", false},
		{"no leading slash", false, "GET", "x", false},
		{"double slash", false, "GET", "//evil", false},
		{"space", false, "GET", "/a b", false},
		{"control char", false, "GET", "/a\x01b", false},
		{"query unverified", false, "GET", "/a?b=1", false},
		{"query verified", true, "GET", "/a?b=1", true},
		{"fragment unverified", false, "GET", "/a#b", false},
		{"fragment verified", true, "GET", "/a#b", true},
		{"long unverified", false, "GET", "/" + longString(200), false},
		{"long verified", true, "GET", "/" + longString(200), true},
		{"too long verified", true, "GET", "/" + longString(3000), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := &guardLease{verified: tc.verified}
			err := l.CheckHTTP(tc.method, tc.path)
			if tc.ok && err != nil {
				t.Fatalf("expected ok, got %v", err)
			}
			if !tc.ok {
				wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY)
			}
		})
	}
}

func longString(n int) string {
	return strings.Repeat("a", n)
}

func TestProbeHeaders(t *testing.T) {
	l := &guardLease{measurementID: "mid-123"}
	h := l.ProbeHeaders()
	if got := h.Get("User-Agent"); got != ProbeUserAgent {
		t.Fatalf("User-Agent = %q", got)
	}
	if got := h.Get(ProbeHeader); got != "mid-123" {
		t.Fatalf("%s = %q", ProbeHeader, got)
	}
}

func TestApplyLimits(t *testing.T) {
	type fields struct{ jobs, conc, icmp int }
	get := func(g *Guard) fields {
		e := g.Effective()
		return fields{e.JobsPerMinute, e.MaxConcurrency, e.ICMPPacketsPerSecond}
	}
	g, _ := newGuard(t, AgentCaps(), nil, nil) // 300 jobs, 16 at a time, 50 ICMP/s
	steps := []struct {
		name   string
		limits *nodev1.Limits
		want   fields
		daily  int64
	}{
		{"a higher value is ignored", &nodev1.Limits{JobsPerMinute: 500}, fields{300, 16, 50}, 200 << 20},
		{"lower values apply", &nodev1.Limits{JobsPerMinute: 5, MaxConcurrency: 2, IcmpPacketsPerSecond: 5, DailyTrafficBytes: 1000}, fields{5, 2, 5}, 1000},
		{"a later higher value lifts the earlier one", &nodev1.Limits{JobsPerMinute: 20, MaxConcurrency: 3, IcmpPacketsPerSecond: 8, DailyTrafficBytes: 5000}, fields{20, 3, 8}, 5000},
		{"never above the compiled cap", &nodev1.Limits{JobsPerMinute: 301, MaxConcurrency: 99, IcmpPacketsPerSecond: 51, DailyTrafficBytes: 1 << 40}, fields{300, 16, 50}, 200 << 20},
		{"zero fields mean the compiled caps", &nodev1.Limits{JobsPerMinute: 7}, fields{7, 16, 50}, 200 << 20},
		{"no limits restore the compiled caps", nil, fields{300, 16, 50}, 200 << 20},
	}
	for _, s := range steps {
		g.ApplyLimits(s.limits)
		if got := get(g); got != s.want || g.Effective().DailyTrafficBytes != s.daily {
			t.Fatalf("%s: caps %+v daily %d, want %+v daily %d", s.name, got, g.Effective().DailyTrafficBytes, s.want, s.daily)
		}
	}

	// A compiled cap of zero allows nothing and no limit opens it.
	none := AgentCaps()
	none.ICMPPacketsPerSecond = 0
	gn, _ := newGuard(t, none, nil, nil)
	gn.ApplyLimits(&nodev1.Limits{IcmpPacketsPerSecond: 50, JobsPerMinute: 1})
	if e := gn.Effective(); e.ICMPPacketsPerSecond != 0 || e.JobsPerMinute != 1 {
		t.Fatalf("limits raised a zero cap: %+v", e)
	}
	if err := gn.icmp.take(context.Background()); err == nil {
		t.Fatal("ICMP sends with a compiled rate of zero")
	}

	// Unlimited daily traffic (anchor) can be lowered to a finite value,
	// and returns to unlimited without limits.
	ga, _ := newGuard(t, AnchorCaps(), nil, nil)
	ga.ApplyLimits(&nodev1.Limits{DailyTrafficBytes: 2000})
	if ga.Effective().DailyTrafficBytes != 2000 {
		t.Fatalf("anchor traffic not lowered: %d", ga.Effective().DailyTrafficBytes)
	}
	ga.ApplyLimits(nil)
	if ga.Effective().DailyTrafficBytes != 0 {
		t.Fatalf("anchor traffic not restored: %d", ga.Effective().DailyTrafficBytes)
	}
}

func TestTokenBucket(t *testing.T) {
	clk := newClock()
	b := newTokenBucket(clk.now, 5)
	ctx := context.Background()
	// Burst of five.
	for i := 0; i < 5; i++ {
		if err := b.take(ctx); err != nil {
			t.Fatalf("take %d: %v", i, err)
		}
	}
	// Sixth has no token; a cancelled context returns promptly.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := b.take(cctx); err == nil {
		t.Fatal("expected context error with no tokens")
	}
	// After a second the bucket refills.
	clk.advance(time.Second)
	if err := b.take(ctx); err != nil {
		t.Fatalf("after refill: %v", err)
	}
}

func TestNewGuardPanicsWithoutTag(t *testing.T) {
	if testHooksEnabled {
		t.Skip("test hooks are enabled in this build")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("expected NewGuard to panic with a Test field set")
		}
	}()
	NewGuard(Config{Caps: AgentCaps(), TestAllowPorts: []uint16{12345}})
}

func TestCompiledPolicyIsCopied(t *testing.T) {
	AllowedPorts()[0] = 22
	NeverPorts()[1] = 443
	AnchorDomains()[0] = "evil.example"
	if !IsNeverPort(22) || IsNeverPort(443) || AllowedPorts()[0] != 80 || AnchorDomains()[0] != "anchor.hopbits.io" {
		t.Fatal("a caller changed the compiled port policy or anchor domains")
	}
}

// pingLease admits an ICMP job whose pingers use fake sockets from conns.
func pingLease(t *testing.T, g *Guard, conns ...*fakeICMPConn) module.Lease {
	t.Helper()
	next := 0
	g.dialICMP = func(netip.Addr) (icmpConn, error) {
		if next >= len(conns) {
			return nil, errors.New("no more fake sockets")
		}
		c := conns[next]
		next++
		return c, nil
	}
	l, err := g.Admit(context.Background(), mkJob("8.8.8.8", 0, v4, pinned("8.8.8.8")), icmpN)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestICMPPacketCapIsPerLease(t *testing.T) {
	caps := AgentCaps()
	caps.MaxPingPackets = 3
	caps.ICMPPacketsPerSecond = 100
	g, _ := newGuard(t, caps, nil, nil)
	c1, c2 := newFakeICMPConn(), newFakeICMPConn()
	l := pingLease(t, g, c1, c2)
	defer l.Close()

	p1, err := l.Pinger()
	if err != nil {
		t.Fatal(err)
	}
	for seq := range 2 {
		if _, err := p1.Echo(context.Background(), uint16(seq+1), time.Millisecond); !errors.Is(err, ErrEchoTimeout) {
			t.Fatalf("echo %d: %v", seq+1, err)
		}
	}
	// A second pinger of the same lease shares its packet cap.
	p2, err := l.Pinger()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p2.Echo(context.Background(), 1, time.Millisecond); !errors.Is(err, ErrEchoTimeout) {
		t.Fatalf("third echo: %v", err)
	}
	_, err = p2.Echo(context.Background(), 2, time.Millisecond)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY)
	_, err = p1.Echo(context.Background(), 9, time.Millisecond)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY)
	if got := len(c1.written) + len(c2.written); got != 3 {
		t.Fatalf("%d echoes left the node, want the lease's cap of 3", got)
	}
}

func TestLeaseOwnsWhatItHandsOut(t *testing.T) {
	g, _ := newGuard(t, AgentCaps(), nil, nil)
	conn := newFakeICMPConn()
	l := pingLease(t, g, conn)
	p, err := l.Pinger()
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("closing the lease left its pinger's socket open")
	}
	if _, err := p.Echo(context.Background(), 1, time.Millisecond); module.CodeOf(err) != nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY {
		t.Fatalf("echo after the lease closed: %v", err)
	}
	if _, err := l.Pinger(); module.CodeOf(err) != nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY {
		t.Fatalf("Pinger after Close: %v", err)
	}
	// The closed lease's slot is free again.
	g.mu.Lock()
	open := g.open
	g.mu.Unlock()
	if open != 0 {
		t.Fatalf("%d leases counted open", open)
	}

	tl, err := g.Admit(context.Background(), mkJob("tcp.example.com", 443, v4, pinned("1.1.1.1")), tcp443)
	if err != nil {
		t.Fatal(err)
	}
	tl.Close()
	if _, err := tl.DialTCP(context.Background()); module.CodeOf(err) != nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY {
		t.Fatalf("DialTCP after Close: %v", err)
	}
}

func TestPingerRechecksTheTarget(t *testing.T) {
	caps := AgentCaps()
	caps.ICMPPacketsPerSecond = 100
	g, _ := newGuard(t, caps, nil, nil)
	conn := newFakeICMPConn()
	l := pingLease(t, g, conn, newFakeICMPConn())
	defer l.Close()
	p, err := l.Pinger()
	if err != nil {
		t.Fatal(err)
	}
	// The network changes while the job runs: the target is now in the
	// node's own network.
	g.SetOwnNetwork(nil, []netip.Addr{addr("8.8.8.1")})
	_, err = p.Echo(context.Background(), 1, time.Millisecond)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
	if len(conn.written) != 0 {
		t.Fatal("an echo went into the node's own network")
	}
	_, err = l.Pinger()
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
}
