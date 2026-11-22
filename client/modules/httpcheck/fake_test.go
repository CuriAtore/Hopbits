package httpcheck

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
)

const (
	testUA          = "HopbitsProbe/1 (+https://hopbits.io/probe)"
	testMeasurement = "m-test"
)

// fakeNet is a TargetNet that dials a local test server directly.
type fakeNet struct {
	host     string
	port     uint16
	verified bool
	dial     func(ctx context.Context) (net.Conn, error)
	checkErr error
	headers  http.Header

	mu      sync.Mutex
	dials   int
	checked []string
}

func (f *fakeNet) Host() string     { return f.host }
func (f *fakeNet) Port() uint16     { return f.port }
func (f *fakeNet) Addr() netip.Addr { return netip.MustParseAddr("127.0.0.1") }
func (f *fakeNet) Resolution() nodev1.ResolutionSource {
	return nodev1.ResolutionSource_RESOLUTION_SOURCE_SERVER
}
func (f *fakeNet) Verified() bool { return f.verified }

func (f *fakeNet) DialTCP(ctx context.Context) (net.Conn, error) {
	f.mu.Lock()
	f.dials++
	f.mu.Unlock()
	if f.dial == nil {
		return nil, errors.New("fake: no dialer")
	}
	return f.dial(ctx)
}

func (f *fakeNet) Pinger() (module.Pinger, error) { return nil, errors.New("fake: no ICMP") }
func (f *fakeNet) QueryDNS(context.Context, module.DNSQuery) (module.DNSReply, error) {
	return module.DNSReply{}, errors.New("fake: no DNS")
}
func (f *fakeNet) TraceHop(context.Context, string, int, int, time.Duration) (module.HopSample, error) {
	return module.HopSample{}, errors.New("fake: no trace")
}

func (f *fakeNet) CheckHTTP(method, path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checked = append(f.checked, method+" "+path)
	return f.checkErr
}

func (f *fakeNet) ProbeHeaders() http.Header {
	if f.headers != nil {
		return f.headers.Clone()
	}
	return http.Header{
		"User-Agent":      {testUA},
		"X-Hopbits-Probe": {testMeasurement},
	}
}

func (f *fakeNet) dialCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dials
}

func (f *fakeNet) checks() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.checked...)
}

// dialAddr dials addr on the loopback interface, as the safety layer would
// dial the validated target.
func dialAddr(addr string) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

// netFor returns a fakeNet that reaches srv, posing as host on port.
func netFor(srv *httptest.Server, host string, port uint16) *fakeNet {
	return &fakeNet{host: host, port: port, dial: dialAddr(srv.Listener.Addr().String())}
}

// newJob builds a job for p with the given target port and a deadline
// window from its issue time.
func newJob(t *testing.T, port uint32, p *measurev1.HttpParams, window time.Duration) *module.Job {
	t.Helper()
	b, err := proto.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now()
	return &module.Job{
		ID:            "job-1",
		Attempt:       1,
		Class:         nodev1.JobClass_JOB_CLASS_MEASURE,
		Kind:          Kind,
		KindVersion:   Version,
		MeasurementID: testMeasurement,
		Target:        &nodev1.Target{Host: "example.com", Port: port, PinnedAddress: "127.0.0.1"},
		Params:        b,
		Issued:        issued,
		Deadline:      issued.Add(window),
	}
}

// grant gives a job's target a target grant, as a granted job carries.
func grant(job *module.Job) *module.Job {
	job.Target.Grant = &nodev1.SignedTargetGrant{Body: []byte("grant"), Sig: []byte("sig"), KeyId: "k-test"}
	return job
}

// trusting returns a module that trusts srv's certificate.
func trusting(srv *httptest.Server) *checker {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &checker{now: time.Now, rootCAs: pool}
}

// decode parses a result's data.
func decode(t *testing.T, r module.Result) *measurev1.HttpResult {
	t.Helper()
	if r.Data == nil {
		t.Fatalf("result has no data: %+v", r)
	}
	var res measurev1.HttpResult
	if err := proto.Unmarshal(r.Data, &res); err != nil {
		t.Fatal(err)
	}
	return &res
}

// wantOutcome fails the test unless r has the outcome and error code.
func wantOutcome(t *testing.T, r module.Result, o nodev1.Outcome, code nodev1.ErrorCode) {
	t.Helper()
	if r.Outcome != o || r.Error != code {
		t.Fatalf("got outcome %v error %v, want %v %v", r.Outcome, r.Error, o, code)
	}
}

// silentListener accepts connections and never answers on them.
func silentListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	return ln
}

// closedPort returns a loopback address on which nothing listens.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}
