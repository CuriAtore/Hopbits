package httpcheck

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/protocol"
)

func TestModuleIdentity(t *testing.T) {
	m := New()
	if m.Kind() != "http" || m.Version() != 1 || m.Class() != nodev1.JobClass_JOB_CLASS_MEASURE {
		t.Fatalf("identity %s v%d %v", m.Kind(), m.Version(), m.Class())
	}
	n := m.Needs()
	if n.Transport != module.TransportTCP || !slices.Equal(n.Ports, []uint16{80, 443, 8080, 8443}) {
		t.Fatalf("needs %+v", n)
	}
}

func TestParseDefaults(t *testing.T) {
	p, err := parse(newJob(t, 443, &measurev1.HttpParams{}, time.Minute), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.method != http.MethodGet || !p.https || p.path != "/" || p.timeout != DefaultTimeout || len(p.headers) != 0 {
		t.Fatalf("defaults %+v", p)
	}
}

func TestParseNormalisesHeaders(t *testing.T) {
	job := newJob(t, 443, &measurev1.HttpParams{ResponseHeaders: []string{"Server", "server", "CF-Ray"}}, time.Minute)
	p, err := parse(job, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.headers, []string{"server", "cf-ray"}) {
		t.Fatalf("headers %q", p.headers)
	}
}

func TestCheckLimits(t *testing.T) {
	nine := []string{"server", "content-type", "content-length", "cache-control", "age", "date", "etag", "via", "x-cache"}
	cases := []struct {
		name    string
		port    uint32
		params  *measurev1.HttpParams
		window  time.Duration
		granted bool
		ok      bool
	}{
		{"defaults", 443, &measurev1.HttpParams{}, time.Minute, false, true},
		{"get", 443, &measurev1.HttpParams{Method: measurev1.HttpMethod_HTTP_METHOD_GET}, time.Minute, false, true},
		{"head", 443, &measurev1.HttpParams{Method: measurev1.HttpMethod_HTTP_METHOD_HEAD}, time.Minute, false, true},
		{"unknown method", 443, &measurev1.HttpParams{Method: measurev1.HttpMethod(3)}, time.Minute, false, false},
		{"unknown scheme", 443, &measurev1.HttpParams{Scheme: measurev1.HttpScheme(7)}, time.Minute, false, false},
		{"https on 8443", 8443, &measurev1.HttpParams{Scheme: measurev1.HttpScheme_HTTP_SCHEME_HTTPS}, time.Minute, false, true},
		{"https on 80", 80, &measurev1.HttpParams{}, time.Minute, false, false},
		{"https on 8080", 8080, &measurev1.HttpParams{}, time.Minute, false, false},
		{"http on 80", 80, &measurev1.HttpParams{Scheme: measurev1.HttpScheme_HTTP_SCHEME_HTTP}, time.Minute, false, true},
		{"http on 8080", 8080, &measurev1.HttpParams{Scheme: measurev1.HttpScheme_HTTP_SCHEME_HTTP}, time.Minute, false, true},
		{"http on 443", 443, &measurev1.HttpParams{Scheme: measurev1.HttpScheme_HTTP_SCHEME_HTTP}, time.Minute, false, false},
		{"https on 22", 22, &measurev1.HttpParams{}, time.Minute, false, false},
		{"https on 9443 granted", 9443, &measurev1.HttpParams{}, time.Minute, true, true},
		{"http on 443 granted", 443, &measurev1.HttpParams{Scheme: measurev1.HttpScheme_HTTP_SCHEME_HTTP}, time.Minute, true, true},
		{"port 0", 0, &measurev1.HttpParams{}, time.Minute, true, false},
		{"port above 65535", 70000, &measurev1.HttpParams{}, time.Minute, true, false},
		{"path", 443, &measurev1.HttpParams{Path: "/status"}, time.Minute, false, true},
		{"path without slash", 443, &measurev1.HttpParams{Path: "status"}, time.Minute, false, false},
		{"absolute URL as path", 443, &measurev1.HttpParams{Path: "http://other.test/"}, time.Minute, false, false},
		{"bad escape", 443, &measurev1.HttpParams{Path: "/%zz"}, time.Minute, false, false},
		{"control character", 443, &measurev1.HttpParams{Path: "/a\r\nX-Injected: 1"}, time.Minute, false, false},
		{"long path", 443, &measurev1.HttpParams{Path: "/" + strings.Repeat("a", MaxPathBytes)}, time.Minute, true, false},
		{"query without grant", 443, &measurev1.HttpParams{Path: "/search?q=1"}, time.Minute, false, false},
		{"query with grant", 443, &measurev1.HttpParams{Path: "/search?q=1"}, time.Minute, true, true},
		{"timeout below minimum", 443, &measurev1.HttpParams{TimeoutMs: 1999}, time.Minute, false, false},
		{"timeout minimum", 443, &measurev1.HttpParams{TimeoutMs: 2000}, time.Minute, false, true},
		{"timeout maximum", 443, &measurev1.HttpParams{TimeoutMs: 30000}, time.Minute, false, true},
		{"timeout above maximum", 443, &measurev1.HttpParams{TimeoutMs: 30001}, time.Minute, false, false},
		{"deadline fits default timeout", 443, &measurev1.HttpParams{}, 10 * time.Second, false, true},
		{"deadline short of default timeout", 443, &measurev1.HttpParams{}, 9999 * time.Millisecond, false, false},
		{"deadline short of timeout", 443, &measurev1.HttpParams{TimeoutMs: 20000}, 15 * time.Second, false, false},
		{"eight headers", 443, &measurev1.HttpParams{ResponseHeaders: nine[:8]}, time.Minute, false, true},
		{"nine headers", 443, &measurev1.HttpParams{ResponseHeaders: nine}, time.Minute, false, false},
		{"header off the allowlist", 443, &measurev1.HttpParams{ResponseHeaders: []string{"set-cookie"}}, time.Minute, false, false},
		{"every allowed header is accepted", 443, &measurev1.HttpParams{ResponseHeaders: AllowedHeaders()[:8]}, time.Minute, false, true},
	}
	m := New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := newJob(t, tc.port, tc.params, tc.window)
			if tc.granted {
				grant(job)
			}
			err := m.Check(job)
			if tc.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("accepted")
				}
				if module.CodeOf(err) != nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS {
					t.Fatalf("code %v, want INVALID_PARAMS", module.CodeOf(err))
				}
			}
		})
	}
}

func TestAllowedHeadersAreAccepted(t *testing.T) {
	all := AllowedHeaders()
	if len(all) != 14 {
		t.Fatalf("allowlist has %d entries", len(all))
	}
	for _, h := range all {
		job := newJob(t, 443, &measurev1.HttpParams{ResponseHeaders: []string{h}}, time.Minute)
		if err := New().Check(job); err != nil {
			t.Errorf("%s refused: %v", h, err)
		}
	}
	// The returned list is a copy.
	all[0] = "set-cookie"
	if AllowedHeaders()[0] != "server" {
		t.Fatal("allowlist changed through its copy")
	}
}

func TestCheckRefusesUndecodableParamsAndMissingDeadline(t *testing.T) {
	job := newJob(t, 443, &measurev1.HttpParams{}, time.Minute)
	job.Params = []byte{0xff, 0xff, 0xff}
	if module.CodeOf(New().Check(job)) != nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS {
		t.Fatal("undecodable params accepted")
	}
	job = newJob(t, 443, &measurev1.HttpParams{}, time.Minute)
	job.Deadline = time.Time{}
	if module.CodeOf(New().Check(job)) != nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS {
		t.Fatal("job without a deadline accepted")
	}
}

type fakeProbe struct{ ipv6 bool }

func (p fakeProbe) ICMP(nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	return false, nodev1.TimestampSource_TIMESTAMP_SOURCE_UNSPECIFIED, "not asked"
}
func (p fakeProbe) Trace(nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	return false, nodev1.TimestampSource_TIMESTAMP_SOURCE_UNSPECIFIED, "not asked"
}
func (p fakeProbe) HasIPv6() bool { return p.ipv6 }

func TestSelfTest(t *testing.T) {
	cases := []struct {
		env  module.Env
		want string
	}{
		{module.Env{Probe: fakeProbe{ipv6: false}}, "measure.http.v1:ipv4:phases:ts.user"},
		{module.Env{Probe: fakeProbe{ipv6: true}}, "measure.http.v1:ipv4:ipv6:phases:ts.user"},
		{module.Env{}, "measure.http.v1:ipv4:phases:ts.user"},
	}
	for _, tc := range cases {
		caps := New().SelfTest(context.Background(), tc.env)
		if len(caps) != 1 || caps[0].String() != tc.want {
			t.Fatalf("got %v, want %s", caps, tc.want)
		}
		if _, err := protocol.ParseCapability(caps[0].String()); err != nil {
			t.Fatal(err)
		}
	}
}
