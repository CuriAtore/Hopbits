package httpcheck

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/modules/internal/kit"
)

// Run sends the job's request through tn and reports the response. Any
// HTTP response is outcome OK; failures carry no timing and no data.
func (c *checker) Run(ctx context.Context, job *module.Job, tn module.TargetNet) module.Result {
	ctx, cancel := kit.WithDeadline(ctx, job)
	defer cancel()

	// Check ran before the job was accepted; parse again so that Run never
	// sends a request outside the compiled limits, whoever calls it.
	p, err := parse(job, c.now())
	if err != nil {
		return kit.Blocked(err)
	}
	if !tn.Verified() && !portAllowed(p.https, tn.Port()) && !kit.UnsafeTestPort(tn.Port()) {
		return kit.Blocked(module.Refuse(nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING,
			"%s on port %d needs a target grant", p.scheme(), tn.Port()))
	}
	if err := tn.CheckHTTP(p.method, p.path); err != nil {
		return kit.Blocked(err)
	}
	if tn.Host() == "" {
		return kit.Blocked(module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "target has no host name"))
	}
	probe := tn.ProbeHeaders()
	if probe.Get("User-Agent") == "" {
		return kit.Blocked(module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "probe headers carry no User-Agent"))
	}

	reqCtx, cancelReq := context.WithTimeout(ctx, p.timeout)
	d := &dialer{tn: tn, job: reqCtx, now: c.now}
	defer func() {
		// End the request first, so a dial still in progress returns, then
		// close the connection and wait for the dial.
		cancelReq()
		d.close()
	}()

	tl := &timeline{now: c.now}
	req, err := newRequest(httptrace.WithClientTrace(reqCtx, tl.trace()), p, tn, probe)
	if err != nil {
		return kit.Blocked(err)
	}
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	tr := &http.Transport{
		// The transport's address is ignored: the dial goes to the job's
		// validated target through the safety layer.
		DialContext: d.dial,
		TLSClientConfig: &tls.Config{
			ServerName: tn.Host(),
			MinVersion: tls.VersionTLS12,
			RootCAs:    c.rootCAs,
		},
		TLSHandshakeTimeout:    p.timeout,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		Protocols:              &protocols,
	}
	defer tr.CloseIdleConnections()

	t0 := c.now()
	// RoundTrip sends exactly one request and never follows a redirect.
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return failure(reqCtx, err, d, tl)
	}
	body, truncated, err := readBody(resp.Body)
	resp.Body.Close()
	end := c.now()
	if err != nil {
		return failure(reqCtx, err, d, tl)
	}

	sum := sha256.Sum256(body)
	res := &measurev1.HttpResult{
		StatusCode:    uint32(max(resp.StatusCode, 0)),
		Phases:        tl.phases(d, t0, end),
		BodyBytesRead: uint32(len(body)),
		BodyTruncated: truncated,
		BodySha256:    sum[:],
		Headers:       selectHeaders(resp.Header, p.headers),
		Redirect:      redirectKind(resp.StatusCode, resp.Header.Get("Location"), req.URL, tn.Host()),
		TlsVersion:    tlsVersion(resp.TLS),
		Protocol:      strings.ToValidUTF8(resp.Proto, string(utf8.RuneError)),
	}
	data, err := proto.Marshal(res)
	if err != nil {
		return module.Result{
			Outcome:  nodev1.Outcome_OUTCOME_FAIL,
			TSSource: nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE,
		}
	}
	flags := uint32(nodev1.ValidityFlag_VALIDITY_FLAG_NOT_HTTP3)
	if tl.reusedConn() {
		flags |= uint32(nodev1.ValidityFlag_VALIDITY_FLAG_REUSED_CONNECTION)
	} else {
		flags |= uint32(nodev1.ValidityFlag_VALIDITY_FLAG_FRESH_CONNECTION)
	}
	return module.Result{
		Outcome:       nodev1.Outcome_OUTCOME_OK,
		TSSource:      nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO,
		TxTSSource:    nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO,
		ValidityFlags: flags,
		Data:          data,
	}
}

// failure maps a request that got no complete response to its outcome:
// the dial's outcome if the connect failed, then CANCELLED, TIMEOUT,
// TLS_FAIL for a failed handshake, and FAIL for anything else after the
// connection was open.
func failure(reqCtx context.Context, err error, d *dialer, tl *timeline) module.Result {
	r := module.Result{TSSource: nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE}
	if dialErr := d.failed(); dialErr != nil {
		r.Outcome, r.Error = kit.ConnectOutcome(dialErr)
		// The dialer ends a connect still in progress by cancelling it when
		// the request's time runs out, so a site that never answers the
		// connect can come back cancelled: that is a timeout.
		if r.Outcome == nodev1.Outcome_OUTCOME_CANCELLED && errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			r.Outcome, r.Error = nodev1.Outcome_OUTCOME_TIMEOUT, nodev1.ErrorCode_ERROR_CODE_UNSPECIFIED
		}
		return r
	}
	switch {
	case errors.Is(reqCtx.Err(), context.Canceled):
		r.Outcome = nodev1.Outcome_OUTCOME_CANCELLED
	case reqCtx.Err() != nil || kit.IsTimeout(err):
		r.Outcome = nodev1.Outcome_OUTCOME_TIMEOUT
	case tl.tlsFailed() || isTLSError(err):
		r.Outcome = nodev1.Outcome_OUTCOME_TLS_FAIL
	default:
		r.Outcome = nodev1.Outcome_OUTCOME_FAIL
	}
	return r
}

// isTLSError reports whether err comes from TLS or certificate checks.
func isTLSError(err error) bool {
	var (
		header    tls.RecordHeaderError
		alert     tls.AlertError
		verify    *tls.CertificateVerificationError
		authority x509.UnknownAuthorityError
		hostname  x509.HostnameError
		invalid   x509.CertificateInvalidError
	)
	return errors.As(err, &header) || errors.As(err, &alert) || errors.As(err, &verify) ||
		errors.As(err, &authority) || errors.As(err, &hostname) || errors.As(err, &invalid)
}

// newRequest builds the job's request: scheme://host[:port]/path with the
// probe headers and nothing else, no body, cookies or credentials.
func newRequest(ctx context.Context, p params, tn module.TargetNet, probe http.Header) (*http.Request, error) {
	ref, err := url.ParseRequestURI(p.path)
	if err != nil {
		return nil, kit.Invalid("path does not parse: %v", err)
	}
	host := authority(tn.Host(), tn.Port(), p.https)
	u := &url.URL{
		Scheme:     p.scheme(),
		Host:       host,
		Path:       ref.Path,
		RawPath:    ref.RawPath,
		RawQuery:   ref.RawQuery,
		ForceQuery: ref.ForceQuery,
	}
	req, err := http.NewRequestWithContext(ctx, p.method, u.String(), nil)
	if err != nil {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "build request: %v", err)
	}
	if req.URL.Host != host || req.URL.User != nil {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "target host %q does not form a URL", tn.Host())
	}
	for k, vs := range probe {
		req.Header[k] = slices.Clone(vs)
	}
	req.Close = true
	return req, nil
}

// authority is the URL host and the Host header: the target name, with the
// port only when it is not the scheme's default.
func authority(host string, port uint16, https bool) string {
	def := uint16(80)
	if https {
		def = 443
	}
	if port != def {
		return net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// readBody reads at most MaxBodyBytes of a body. It reads one byte past
// the cap, which it neither keeps nor hashes, to tell whether there was
// more.
func readBody(r io.Reader) (body []byte, truncated bool, err error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBodyBytes+1))
	if len(b) > MaxBodyBytes {
		return b[:MaxBodyBytes], true, err
	}
	return b, false, err
}

// selectHeaders returns the asked-for headers the response carries, in the
// order asked, each with its values joined by ", ".
func selectHeaders(h http.Header, names []string) []*measurev1.HttpHeader {
	var out []*measurev1.HttpHeader
	for _, name := range names {
		vals := h.Values(name)
		if len(vals) == 0 {
			continue
		}
		out = append(out, &measurev1.HttpHeader{Name: name, Value: cleanValue(strings.Join(vals, ", "))})
	}
	return out
}

// cleanValue makes a header value safe to report: valid UTF-8 and at most
// maxHeaderValueBytes, cut at a character boundary.
func cleanValue(v string) string {
	v = strings.ToValidUTF8(v, string(utf8.RuneError))
	if len(v) <= maxHeaderValueBytes {
		return v
	}
	cut := maxHeaderValueBytes
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut]
}

// redirectKind classifies where a 3xx response with a Location points. It
// only reports the redirect; nothing follows it.
func redirectKind(status int, location string, base *url.URL, host string) measurev1.HttpRedirect {
	if status < 300 || status > 399 || location == "" {
		return measurev1.HttpRedirect_HTTP_REDIRECT_NONE
	}
	loc, err := base.Parse(location)
	if err != nil || loc.Host == "" {
		return measurev1.HttpRedirect_HTTP_REDIRECT_OTHER_HOST
	}
	if sameHost(loc.Hostname(), host) {
		return measurev1.HttpRedirect_HTTP_REDIRECT_SAME_HOST
	}
	return measurev1.HttpRedirect_HTTP_REDIRECT_OTHER_HOST
}

func sameHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// tlsVersion names the negotiated TLS version, such as "TLS 1.3".
func tlsVersion(cs *tls.ConnectionState) string {
	if cs == nil {
		return ""
	}
	return tls.VersionName(cs.Version)
}
