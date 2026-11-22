package dnsquery

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
)

type fakeNet struct {
	query func(ctx context.Context, req module.DNSQuery) (module.DNSReply, error)
}

func (f *fakeNet) Host() string     { return "hopbits.io" }
func (f *fakeNet) Port() uint16     { return 0 }
func (f *fakeNet) Addr() netip.Addr { return netip.MustParseAddr("1.1.1.1") }
func (f *fakeNet) Resolution() nodev1.ResolutionSource {
	return nodev1.ResolutionSource_RESOLUTION_SOURCE_SERVER
}
func (f *fakeNet) Verified() bool { return false }
func (f *fakeNet) DialTCP(context.Context) (net.Conn, error) {
	return nil, errors.New("fake: no TCP")
}
func (f *fakeNet) Pinger() (module.Pinger, error) { return nil, errors.New("fake: no ICMP") }
func (f *fakeNet) QueryDNS(ctx context.Context, req module.DNSQuery) (module.DNSReply, error) {
	return f.query(ctx, req)
}
func (f *fakeNet) TraceHop(context.Context, string, int, int, time.Duration) (module.HopSample, error) {
	return module.HopSample{}, errors.New("fake: no trace")
}
func (f *fakeNet) CheckHTTP(string, string) error { return errors.New("fake: no HTTP") }
func (f *fakeNet) ProbeHeaders() http.Header      { return http.Header{} }

type fakeProbe struct{ ipv6 bool }

func (fakeProbe) ICMP(nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	return false, nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE, ""
}
func (fakeProbe) Trace(nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	return false, nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE, ""
}
func (p fakeProbe) HasIPv6() bool { return p.ipv6 }

func newJob(t *testing.T, port uint32, p *measurev1.DnsParams, window time.Duration) *module.Job {
	t.Helper()
	b, err := measurev1.MarshalWire(p)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	return &module.Job{
		ID:          "job-dns-1",
		Attempt:     1,
		Class:       nodev1.JobClass_JOB_CLASS_MEASURE,
		Kind:        Kind,
		KindVersion: Version,
		Target:      &nodev1.Target{Host: "hopbits.io", Port: port, PinnedAddress: "1.1.1.1"},
		Params:      b,
		Issued:      now,
		Deadline:    now.Add(window),
	}
}

func TestSelfTest(t *testing.T) {
	m := New()
	c4 := m.SelfTest(context.Background(), module.Env{Probe: fakeProbe{ipv6: false}})
	if len(c4) != 1 || c4[0].String() != "measure.dns.v1:ipv4:ts.user" {
		t.Fatalf("got %v", c4)
	}
	c6 := m.SelfTest(context.Background(), module.Env{Probe: fakeProbe{ipv6: true}})
	if len(c6) != 1 || c6[0].String() != "measure.dns.v1:ipv4:ipv6:ts.user" {
		t.Fatalf("got %v", c6)
	}
	cd := m.SelfTest(context.Background(), module.Env{
		NetworkMode: nodev1.NetworkMode_NETWORK_MODE_DOCKER_DESKTOP,
		Probe:       fakeProbe{ipv6: true},
	})
	if len(cd) != 0 {
		t.Fatalf("Docker Desktop advertised %v", cd)
	}
}

func TestCheckValidation(t *testing.T) {
	m := New()
	for _, qt := range []string{"A", "aaaa", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "PTR"} {
		if err := m.Check(newJob(t, 0, &measurev1.DnsParams{Qtype: qt}, time.Minute)); err != nil {
			t.Fatalf("qtype %s refused: %v", qt, err)
		}
	}
	for _, res := range []string{"isp", "1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"} {
		if err := m.Check(newJob(t, 53, &measurev1.DnsParams{Resolver: res}, time.Minute)); err != nil {
			t.Fatalf("resolver %s refused: %v", res, err)
		}
	}
	bad := []*measurev1.DnsParams{
		{Qtype: "AXFR"},
		{Qtype: "ANY"},
		{Resolver: "4.2.2.1"},
		{Resolver: "192.168.1.1"},
		{Protocol: "doh"},
		{TimeoutMs: 499},
		{TimeoutMs: 10001},
	}
	for _, p := range bad {
		if err := m.Check(newJob(t, 0, p, time.Minute)); module.CodeOf(err) != nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS {
			t.Fatalf("expected INVALID_PARAMS for %+v, got %v", p, err)
		}
	}
	if err := m.Check(newJob(t, 443, &measurev1.DnsParams{}, time.Minute)); module.CodeOf(err) != nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS {
		t.Fatalf("port 443 should be refused, got %v", err)
	}
}

func TestRunNXDomainAndTimeout(t *testing.T) {
	m := New()

	// NXDOMAIN is still OUTCOME_OK because the DNS resolver answered.
	tnNX := &fakeNet{query: func(_ context.Context, req module.DNSQuery) (module.DNSReply, error) {
		return module.DNSReply{
			Qname:    "missing.hopbits.io",
			Qtype:    req.Qtype,
			Resolver: req.Resolver,
			Protocol: "udp",
			Rcode:    "NXDOMAIN",
			RcodeNum: 3,
			RTT:      12400 * time.Microsecond,
		}, nil
	}}
	r := m.Run(context.Background(), newJob(t, 0, &measurev1.DnsParams{}, time.Minute), tnNX)
	if r.Outcome != nodev1.Outcome_OUTCOME_OK {
		t.Fatalf("NXDOMAIN outcome = %v, want OUTCOME_OK", r.Outcome)
	}
	var decoded measurev1.DnsResult
	if err := measurev1.UnmarshalWire(r.Data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Rcode != "NXDOMAIN" || decoded.RcodeNum != 3 || decoded.RttUs != 12400 || decoded.Resolver != "isp" {
		t.Fatalf("decoded = %+v", decoded)
	}

	// Timeout maps to OUTCOME_TIMEOUT.
	tnTimeout := &fakeNet{query: func(context.Context, module.DNSQuery) (module.DNSReply, error) {
		return module.DNSReply{}, context.DeadlineExceeded
	}}
	rt := m.Run(context.Background(), newJob(t, 0, &measurev1.DnsParams{}, time.Minute), tnTimeout)
	if rt.Outcome != nodev1.Outcome_OUTCOME_TIMEOUT {
		t.Fatalf("timeout outcome = %v, want OUTCOME_TIMEOUT", rt.Outcome)
	}
}
