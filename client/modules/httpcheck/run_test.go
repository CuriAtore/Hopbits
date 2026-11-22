package httpcheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/modules/internal/kittest"
)

var (
	okOutcome   = nodev1.Outcome_OUTCOME_OK
	noCode      = nodev1.ErrorCode_ERROR_CODE_UNSPECIFIED
	plainHTTP   = measurev1.HttpScheme_HTTP_SCHEME_HTTP
	freshFlags  = uint32(nodev1.ValidityFlag_VALIDITY_FLAG_FRESH_CONNECTION | nodev1.ValidityFlag_VALIDITY_FLAG_NOT_HTTP3)
	tsUserspace = nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO
	tsNone      = nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE
)

// seenRequest is what a test server saw of one request.
type seenRequest struct {
	method, uri, host string
	header            http.Header
	close             bool
	contentLength     int64
}

// recorder is a test server handler that records requests and answers
// with handle.
type recorder struct {
	mu     sync.Mutex
	seen   []seenRequest
	handle func(w http.ResponseWriter, r *http.Request)
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec.mu.Lock()
	rec.seen = append(rec.seen, seenRequest{r.Method, r.RequestURI, r.Host, r.Header.Clone(), r.Close, r.ContentLength})
	rec.mu.Unlock()
	if rec.handle != nil {
		rec.handle(w, r)
	}
}

func (rec *recorder) requests() []seenRequest {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]seenRequest(nil), rec.seen...)
}

func TestRunSendsOneAttributedRequest(t *testing.T) {
	rec := &recorder{handle: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test-origin")
		io.WriteString(w, "hello")
	}}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	tn := netFor(srv, "example.com", 8080)
	job := grant(newJob(t, 8080, &measurev1.HttpParams{
		Scheme:          plainHTTP,
		Path:            "/status?x=1",
		ResponseHeaders: []string{"server"},
	}, time.Minute))
	// A clock that moves 1 ms per reading makes the phases exact: request
	// start, dial start, dial done, headers written, first byte, end.
	m := &checker{now: kittest.Ticker(time.Millisecond)}
	r := m.Run(context.Background(), job, tn)
	wantOutcome(t, r, okOutcome, noCode)
	if r.TSSource != tsUserspace || r.TxTSSource != tsUserspace || r.ValidityFlags != freshFlags {
		t.Fatalf("timing fields %v %v %b", r.TSSource, r.TxTSSource, r.ValidityFlags)
	}

	reqs := rec.requests()
	if len(reqs) != 1 {
		t.Fatalf("server saw %d requests", len(reqs))
	}
	got := reqs[0]
	if got.method != http.MethodGet || got.uri != "/status?x=1" || got.host != "example.com:8080" {
		t.Fatalf("request %s %s Host %s", got.method, got.uri, got.host)
	}
	if got.header.Get("User-Agent") != testUA || got.header.Get("X-Hopbits-Probe") != testMeasurement {
		t.Fatalf("attribution headers missing: %v", got.header)
	}
	for _, h := range []string{"Accept-Encoding", "Cookie", "Authorization"} {
		if v := got.header.Get(h); v != "" {
			t.Errorf("request carries %s: %q", h, v)
		}
	}
	if !got.close || got.contentLength != 0 {
		t.Fatalf("close %v, content length %d", got.close, got.contentLength)
	}
	if checks := tn.checks(); len(checks) != 1 || checks[0] != "GET /status?x=1" {
		t.Fatalf("CheckHTTP calls %q", checks)
	}
	if tn.dialCount() != 1 {
		t.Fatalf("%d dials", tn.dialCount())
	}

	res := decode(t, r)
	want := sha256.Sum256([]byte("hello"))
	if res.GetStatusCode() != 200 || res.GetBodyBytesRead() != 5 || res.GetBodyTruncated() || !bytes.Equal(res.GetBodySha256(), want[:]) {
		t.Fatalf("result %v", res)
	}
	if res.GetRedirect() != measurev1.HttpRedirect_HTTP_REDIRECT_NONE || res.GetTlsVersion() != "" || res.GetProtocol() != "HTTP/1.1" {
		t.Fatalf("result %v", res)
	}
	if hs := res.GetHeaders(); len(hs) != 1 || hs[0].GetName() != "server" || hs[0].GetValue() != "test-origin" {
		t.Fatalf("headers %v", hs)
	}
	ph := res.GetPhases()
	if ph.GetDnsUs() != 0 || ph.GetConnectUs() != 1000 || ph.GetTlsUs() != 0 ||
		ph.GetFirstByteUs() != 1000 || ph.GetTotalUs() != 5000 {
		t.Fatalf("phases %v", ph)
	}
}

func TestRunPhasesWithRealClock(t *testing.T) {
	srv := httptest.NewServer(&recorder{})
	defer srv.Close()
	r := New().Run(context.Background(), newJob(t, 8080, &measurev1.HttpParams{Scheme: plainHTTP}, time.Minute), netFor(srv, "example.com", 8080))
	wantOutcome(t, r, okOutcome, noCode)
	// The host clock may be too coarse to see a loopback request at all
	// (about 0.5 ms on Windows), so only the order of the phases is fixed.
	ph := decode(t, r).GetPhases()
	if ph.GetDnsUs() != 0 || ph.GetConnectUs() > ph.GetTotalUs() || ph.GetFirstByteUs() > ph.GetTotalUs() {
		t.Fatalf("phases %v", ph)
	}
}

func TestRunHostHeader(t *testing.T) {
	cases := []struct {
		host string
		port uint16
		want string
	}{
		{"example.com", 80, "example.com"},
		{"example.com", 8080, "example.com:8080"},
		{"2001:db8::1", 80, "[2001:db8::1]"},
		{"2001:db8::1", 8080, "[2001:db8::1]:8080"},
	}
	for _, tc := range cases {
		rec := &recorder{}
		srv := httptest.NewServer(rec)
		tn := netFor(srv, tc.host, tc.port)
		job := newJob(t, uint32(tc.port), &measurev1.HttpParams{Scheme: plainHTTP}, time.Minute)
		r := New().Run(context.Background(), job, tn)
		srv.Close()
		wantOutcome(t, r, okOutcome, noCode)
		if reqs := rec.requests(); len(reqs) != 1 || reqs[0].host != tc.want {
			t.Fatalf("%s port %d: Host %v, want %s", tc.host, tc.port, reqs, tc.want)
		}
	}
}

func TestRunHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(&recorder{handle: func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "secure")
	}})
	defer srv.Close()

	m := trusting(srv)
	// 1 ms per clock reading: request start, dial start, dial done, TLS
	// start, TLS done, headers written, first byte, end.
	m.now = kittest.Ticker(time.Millisecond)
	r := m.Run(context.Background(), newJob(t, 8443, &measurev1.HttpParams{}, time.Minute), netFor(srv, "example.com", 8443))
	wantOutcome(t, r, okOutcome, noCode)
	res := decode(t, r)
	if res.GetTlsVersion() != "TLS 1.3" || res.GetProtocol() != "HTTP/1.1" || res.GetStatusCode() != 200 {
		t.Fatalf("result %v", res)
	}
	if ph := res.GetPhases(); ph.GetConnectUs() != 1000 || ph.GetTlsUs() != 1000 || ph.GetFirstByteUs() != 1000 || ph.GetTotalUs() != 7000 {
		t.Fatalf("phases %v", ph)
	}
	if r.ValidityFlags != freshFlags {
		t.Fatalf("flags %b", r.ValidityFlags)
	}
}

// quietTLSServer starts a TLS test server that does not log the handshake
// failures these tests cause on purpose.
func quietTLSServer(t *testing.T, cfg *tls.Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(&recorder{})
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestRunTLSFailures(t *testing.T) {
	modern := quietTLSServer(t, nil)
	old := quietTLSServer(t, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	plain := httptest.NewServer(&recorder{})
	defer plain.Close()

	cases := []struct {
		name string
		mod  *checker
		tn   *fakeNet
	}{
		{"untrusted certificate", New().(*checker), netFor(modern, "example.com", 443)},
		{"certificate for another name", trusting(modern), netFor(modern, "wrong.test", 443)},
		{"TLS below 1.2", trusting(old), netFor(old, "example.com", 443)},
		{"plain HTTP server", trusting(modern), netFor(plain, "example.com", 443)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.mod.Run(context.Background(), newJob(t, 443, &measurev1.HttpParams{}, time.Minute), tc.tn)
			wantOutcome(t, r, nodev1.Outcome_OUTCOME_TLS_FAIL, noCode)
			if r.Data != nil || r.TSSource != tsNone || r.ValidityFlags != 0 {
				t.Fatalf("a failure carries data or timing: %+v", r)
			}
		})
	}
}

func TestRunCapsAndHashesBody(t *testing.T) {
	cases := []struct {
		name      string
		size      int
		chunked   bool
		truncated bool
	}{
		{"empty", 0, false, false},
		{"under the cap", 9_999, false, false},
		{"at the cap", 10_000, false, false},
		{"one byte over", 10_001, false, true},
		{"well over", 25_000, false, true},
		{"chunked at the cap", 10_000, true, false},
		{"chunked over", 25_000, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := bytes.Repeat([]byte("0123456789"), tc.size/10+1)[:tc.size]
			srv := httptest.NewServer(&recorder{handle: func(w http.ResponseWriter, r *http.Request) {
				if !tc.chunked {
					w.Write(body)
					return
				}
				for chunk := range pieces(body, 1000) {
					w.Write(chunk)
					w.(http.Flusher).Flush()
				}
			}})
			defer srv.Close()
			r := New().Run(context.Background(), newJob(t, 8080, &measurev1.HttpParams{Scheme: plainHTTP}, time.Minute), netFor(srv, "example.com", 8080))
			wantOutcome(t, r, okOutcome, noCode)
			res := decode(t, r)
			n := min(tc.size, MaxBodyBytes)
			want := sha256.Sum256(body[:n])
			if int(res.GetBodyBytesRead()) != n || res.GetBodyTruncated() != tc.truncated || !bytes.Equal(res.GetBodySha256(), want[:]) {
				t.Fatalf("read %d truncated %v, want %d %v", res.GetBodyBytesRead(), res.GetBodyTruncated(), n, tc.truncated)
			}
		})
	}
}

// pieces yields b in pieces of at most n bytes.
func pieces(b []byte, n int) func(yield func([]byte) bool) {
	return func(yield func([]byte) bool) {
		for len(b) > 0 {
			k := min(n, len(b))
			if !yield(b[:k]) {
				return
			}
			b = b[k:]
		}
	}
}

func TestRunHead(t *testing.T) {
	rec := &recorder{handle: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5000")
	}}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	job := newJob(t, 80, &measurev1.HttpParams{Scheme: plainHTTP, Method: measurev1.HttpMethod_HTTP_METHOD_HEAD}, time.Minute)
	tn := netFor(srv, "example.com", 80)
	r := New().Run(context.Background(), job, tn)
	wantOutcome(t, r, okOutcome, noCode)
	res := decode(t, r)
	empty := sha256.Sum256(nil)
	if res.GetBodyBytesRead() != 0 || res.GetBodyTruncated() || !bytes.Equal(res.GetBodySha256(), empty[:]) {
		t.Fatalf("result %v", res)
	}
	if reqs := rec.requests(); len(reqs) != 1 || reqs[0].method != http.MethodHead {
		t.Fatalf("requests %v", reqs)
	}
	if checks := tn.checks(); len(checks) != 1 || checks[0] != "HEAD /" {
		t.Fatalf("CheckHTTP calls %q", checks)
	}
}

func TestRunReportsRedirectsWithoutFollowing(t *testing.T) {
	cases := []struct {
		status   int
		location string
		want     measurev1.HttpRedirect
	}{
		{http.StatusFound, "/next", measurev1.HttpRedirect_HTTP_REDIRECT_SAME_HOST},
		{http.StatusMovedPermanently, "https://example.com/next", measurev1.HttpRedirect_HTTP_REDIRECT_SAME_HOST},
		{http.StatusTemporaryRedirect, "//EXAMPLE.com./x", measurev1.HttpRedirect_HTTP_REDIRECT_SAME_HOST},
		{http.StatusPermanentRedirect, "https://other.example/", measurev1.HttpRedirect_HTTP_REDIRECT_OTHER_HOST},
		{http.StatusSeeOther, "http://[::1", measurev1.HttpRedirect_HTTP_REDIRECT_OTHER_HOST},
		{http.StatusFound, "", measurev1.HttpRedirect_HTTP_REDIRECT_NONE},
		{http.StatusNotModified, "", measurev1.HttpRedirect_HTTP_REDIRECT_NONE},
		{http.StatusOK, "/next", measurev1.HttpRedirect_HTTP_REDIRECT_NONE},
	}
	for _, tc := range cases {
		rec := &recorder{handle: func(w http.ResponseWriter, r *http.Request) {
			if tc.location != "" {
				w.Header().Set("Location", tc.location)
			}
			w.WriteHeader(tc.status)
		}}
		srv := httptest.NewServer(rec)
		r := New().Run(context.Background(), newJob(t, 8080, &measurev1.HttpParams{Scheme: plainHTTP}, time.Minute), netFor(srv, "example.com", 8080))
		srv.Close()
		wantOutcome(t, r, okOutcome, noCode)
		res := decode(t, r)
		if int(res.GetStatusCode()) != tc.status || res.GetRedirect() != tc.want {
			t.Errorf("%d %q: status %d redirect %v, want %v", tc.status, tc.location, res.GetStatusCode(), res.GetRedirect(), tc.want)
		}
		if n := len(rec.requests()); n != 1 {
			t.Errorf("%d %q: server saw %d requests", tc.status, tc.location, n)
		}
	}
}

func TestRunReturnsOnlyAllowlistedAskedHeaders(t *testing.T) {
	srv := httptest.NewServer(&recorder{handle: func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Server", "origin")
		h.Set("Content-Type", "text/plain")
		h.Set("CF-Ray", "abc123")
		h.Add("Via", "1.1 a")
		h.Add("Via", "1.1 b")
		h.Set("Set-Cookie", "session=secret")
		h.Set("X-Secret", "do not leak")
		h.Set("Etag", `"v1"`)
	}})
	defer srv.Close()
	params := &measurev1.HttpParams{Scheme: plainHTTP, ResponseHeaders: []string{"via", "Server", "age", "cf-ray", "content-type"}}
	r := New().Run(context.Background(), newJob(t, 8080, params, time.Minute), netFor(srv, "example.com", 8080))
	wantOutcome(t, r, okOutcome, noCode)
	var got []string
	for _, h := range decode(t, r).GetHeaders() {
		got = append(got, h.GetName()+"="+h.GetValue())
	}
	want := []string{"via=1.1 a, 1.1 b", "server=origin", "cf-ray=abc123", "content-type=text/plain"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("headers %q, want %q", got, want)
	}
}

func TestCleanValue(t *testing.T) {
	if got := cleanValue("a\xffb"); got != "a"+string(utf8.RuneError)+"b" {
		t.Fatalf("invalid UTF-8 kept: %q", got)
	}
	// One ASCII byte, then two-byte characters: the cap falls inside one.
	long := "a" + strings.Repeat("é", maxHeaderValueBytes)
	got := cleanValue(long)
	if len(got) != maxHeaderValueBytes-1 || !strings.HasPrefix(long, got) || !utf8.ValidString(got) {
		t.Fatalf("cut to %d bytes", len(got))
	}
	if got := cleanValue("short"); got != "short" {
		t.Fatalf("changed a short value: %q", got)
	}
}

// earlyDeadline gives a job a window that fits its params but a deadline
// that ends after d, as if the job had spent most of its window queued.
func earlyDeadline(job *module.Job, window, d time.Duration) *module.Job {
	job.Deadline = time.Now().Add(d)
	job.Issued = job.Deadline.Add(-window)
	return job
}

func TestRunTimeout(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scheme measurev1.HttpScheme
		port   uint16
	}{
		{"no response", plainHTTP, 8080},
		{"no TLS handshake", measurev1.HttpScheme_HTTP_SCHEME_HTTPS, 443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln := silentListener(t)
			tn := &fakeNet{host: "example.com", port: tc.port, dial: dialAddr(ln.Addr().String())}
			job := earlyDeadline(newJob(t, uint32(tc.port), &measurev1.HttpParams{Scheme: tc.scheme}, 10*time.Second), 10*time.Second, 300*time.Millisecond)
			start := time.Now()
			r := New().Run(context.Background(), job, tn)
			wantOutcome(t, r, nodev1.Outcome_OUTCOME_TIMEOUT, noCode)
			if took := time.Since(start); took > 5*time.Second {
				t.Fatalf("took %v", took)
			}
			if r.Data != nil || r.TSSource != tsNone {
				t.Fatalf("a failure carries data or timing: %+v", r)
			}
		})
	}
}

func TestRunLeavesNoGoroutines(t *testing.T) {
	for _, scheme := range []measurev1.HttpScheme{plainHTTP, measurev1.HttpScheme_HTTP_SCHEME_HTTPS} {
		ln := silentListener(t)
		port := uint16(8080)
		if scheme != plainHTTP {
			port = 8443
		}
		tn := &fakeNet{host: "example.com", port: port, dial: dialAddr(ln.Addr().String())}
		job := earlyDeadline(newJob(t, uint32(port), &measurev1.HttpParams{Scheme: scheme}, 10*time.Second), 10*time.Second, 100*time.Millisecond)
		before := runtime.NumGoroutine()
		r := New().Run(context.Background(), job, tn)
		wantOutcome(t, r, nodev1.Outcome_OUTCOME_TIMEOUT, noCode)
		// The transport's goroutines end once Run has closed the connection.
		deadline := time.Now().Add(5 * time.Second)
		for runtime.NumGoroutine() > before {
			if time.Now().After(deadline) {
				t.Fatalf("%v: %d goroutines before, %d after", scheme, before, runtime.NumGoroutine())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestRunRefusedOnClosedPort(t *testing.T) {
	tn := &fakeNet{host: "example.com", port: 8080, dial: dialAddr(closedPort(t))}
	r := New().Run(context.Background(), newJob(t, 8080, &measurev1.HttpParams{Scheme: plainHTTP}, time.Minute), tn)
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_REFUSED, noCode)
	if r.Data != nil || r.TSSource != tsNone {
		t.Fatalf("a failure carries data or timing: %+v", r)
	}
}

func TestRunMapsDialErrors(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		outcome nodev1.Outcome
		code    nodev1.ErrorCode
	}{
		{"denied target", module.Refuse(nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL, "own network"),
			nodev1.Outcome_OUTCOME_DENIED_LOCAL, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL},
		{"rate limited", module.Refuse(nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED, "cap"),
			nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE, nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED},
		{"no route", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("no route to host")},
			nodev1.Outcome_OUTCOME_UNREACHABLE, noCode},
		{"timed out", &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded},
			nodev1.Outcome_OUTCOME_TIMEOUT, noCode},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tn := &fakeNet{host: "example.com", port: 443, dial: func(context.Context) (net.Conn, error) { return nil, tc.err }}
			r := New().Run(context.Background(), newJob(t, 443, &measurev1.HttpParams{}, time.Minute), tn)
			wantOutcome(t, r, tc.outcome, tc.code)
			if tn.dialCount() != 1 {
				t.Fatalf("%d dials", tn.dialCount())
			}
		})
	}
}

func TestRunGarbageResponseFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Read(make([]byte, 4096))
		io.WriteString(c, "garbage\r\n\r\n")
	}()
	tn := &fakeNet{host: "example.com", port: 80, dial: dialAddr(ln.Addr().String())}
	r := New().Run(context.Background(), newJob(t, 80, &measurev1.HttpParams{Scheme: plainHTTP}, time.Minute), tn)
	wantOutcome(t, r, nodev1.Outcome_OUTCOME_FAIL, noCode)
}

func TestRunBlocksWithoutSending(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	cases := []struct {
		name    string
		job     func() *module.Job
		tn      func() *fakeNet
		ctx     func() context.Context
		outcome nodev1.Outcome
		code    nodev1.ErrorCode
	}{
		{
			name: "CheckHTTP refuses",
			job:  func() *module.Job { return newJob(t, 8080, &measurev1.HttpParams{Scheme: plainHTTP}, time.Minute) },
			tn: func() *fakeNet {
				f := netFor(srv, "example.com", 8080)
				f.checkErr = module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "path too long")
				return f
			},
			outcome: nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE,
			code:    nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY,
		},
		{
			name:    "grant did not verify",
			job:     func() *module.Job { return grant(newJob(t, 9443, &measurev1.HttpParams{}, time.Minute)) },
			tn:      func() *fakeNet { return netFor(srv, "example.com", 9443) },
			outcome: nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE,
			code:    nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING,
		},
		{
			name: "params over the limits",
			job: func() *module.Job {
				return newJob(t, 8080, &measurev1.HttpParams{Scheme: plainHTTP, TimeoutMs: 60_000}, time.Hour)
			},
			tn:      func() *fakeNet { return netFor(srv, "example.com", 8080) },
			outcome: nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE,
			code:    nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS,
		},
		{
			name: "no User-Agent to attribute the request",
			job:  func() *module.Job { return newJob(t, 8080, &measurev1.HttpParams{Scheme: plainHTTP}, time.Minute) },
			tn: func() *fakeNet {
				f := netFor(srv, "example.com", 8080)
				f.headers = http.Header{"X-Hopbits-Probe": {testMeasurement}}
				return f
			},
			outcome: nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE,
			code:    nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY,
		},
		{
			name: "cancelled",
			job:  func() *module.Job { return newJob(t, 8080, &measurev1.HttpParams{Scheme: plainHTTP}, time.Minute) },
			tn:   func() *fakeNet { return netFor(srv, "example.com", 8080) },
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			outcome: nodev1.Outcome_OUTCOME_CANCELLED,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.ctx != nil {
				ctx = tc.ctx()
			}
			tn := tc.tn()
			r := New().Run(ctx, tc.job(), tn)
			wantOutcome(t, r, tc.outcome, tc.code)
			if r.Data != nil || tn.dialCount() != 0 {
				t.Fatalf("data %v, %d dials", r.Data, tn.dialCount())
			}
		})
	}
	if n := len(rec.requests()); n != 0 {
		t.Fatalf("server saw %d requests", n)
	}
}

func TestRunVerifiedTargetMayUseOtherPorts(t *testing.T) {
	srv := httptest.NewTLSServer(&recorder{})
	defer srv.Close()
	tn := netFor(srv, "example.com", 9443)
	tn.verified = true
	r := trusting(srv).Run(context.Background(), grant(newJob(t, 9443, &measurev1.HttpParams{}, time.Minute)), tn)
	wantOutcome(t, r, okOutcome, noCode)
}

func TestDialerOpensOneConnection(t *testing.T) {
	ln := silentListener(t)
	tn := &fakeNet{dial: dialAddr(ln.Addr().String())}
	ctx, cancel := context.WithCancel(context.Background())
	d := &dialer{tn: tn, job: ctx, now: time.Now}

	conn, err := d.dial(context.Background(), "tcp", "203.0.113.9:443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.dial(context.Background(), "tcp", "203.0.113.9:443"); !errors.Is(err, errSecondDial) {
		t.Fatalf("second dial: %v", err)
	}
	if tn.dialCount() != 1 {
		t.Fatalf("%d dials", tn.dialCount())
	}
	cancel()
	d.close()
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("connection still open after close")
	}
	if _, err := d.dial(context.Background(), "tcp", "x"); !errors.Is(err, errJobOver) {
		t.Fatalf("dial after close: %v", err)
	}
	start, done := d.times()
	if start.IsZero() || done.Before(start) {
		t.Fatalf("dial times %v %v", start, done)
	}
}

func TestDialerEndsWithTheJob(t *testing.T) {
	entered := make(chan struct{})
	tn := &fakeNet{dial: func(ctx context.Context) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	job, cancel := context.WithCancel(context.Background())
	d := &dialer{tn: tn, job: job, now: time.Now}
	errc := make(chan error, 1)
	// The transport's own context never ends here; the job's does.
	go func() {
		_, err := d.dial(context.Background(), "tcp", "x")
		errc <- err
	}()
	<-entered
	cancel()
	d.close()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("dial returned %v", err)
	}
}
