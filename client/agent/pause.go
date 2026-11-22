package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/protocol"
	"github.com/hopbits/client/safety"
)

const (
	// DefaultPauseURL is the off-core pause file endpoint under the compiled
	// anchor domain.
	DefaultPauseURL = "https://" + safety.PauseHost + "/pause.json"

	defaultPausePollInterval = 5 * time.Minute
	// pauseFetchTimeout bounds one fetch of the pause file or the release
	// manifest: a whole dial (connect, TLS, headers) and a small body, so a
	// node on a slow link can still learn of a pause or an update.
	pauseFetchTimeout = dialTimeout + 30*time.Second
	maxPauseFileBytes = 1 << 20 // 1 MiB
)

// PauseFetcher retrieves raw signed pause-file bytes from the off-core host.
type PauseFetcher interface {
	FetchPause(ctx context.Context) ([]byte, error)
}

// SignedRevocationEntry is the JSON representation of a root-signed key
// revocation carried inside a pause file or release manifest.
type SignedRevocationEntry struct {
	Body      []byte `json:"body"`
	Sig       []byte `json:"sig"`
	RootIndex uint32 `json:"root_index"`
}

func (e SignedRevocationEntry) toProto() *nodev1.SignedRevocation {
	return &nodev1.SignedRevocation{
		Body:      e.Body,
		Sig:       e.Sig,
		RootIndex: e.RootIndex,
	}
}

// SignedPauseFile wraps raw PauseDocument bytes and the compiled working root's
// Ed25519 signature for protocol.PurposePauseFile.
type SignedPauseFile struct {
	Body []byte `json:"body"`
	Sig  []byte `json:"sig"`
}

// PauseDocument is the authenticated body of the off-core pause file.
type PauseDocument struct {
	Paused      bool                    `json:"paused"`
	IssuedUnix  int64                   `json:"issued_unix"`
	ExpiresUnix int64                   `json:"expires_unix"`
	Reason      string                  `json:"reason,omitempty"`
	Revocations []SignedRevocationEntry `json:"revocations,omitempty"`
}

// HTTPPauseFetcher fetches the signed pause file over HTTPS (or HTTP to a
// loopback host in local tests).
type HTTPPauseFetcher struct {
	URL    string
	Client *http.Client
}

// NewHTTPPauseFetcher returns a PauseFetcher pointing at u (defaulting to
// DefaultPauseURL) using client (or a bounded default control HTTP client that
// enforces safety.Denied on resolved addresses).
func NewHTTPPauseFetcher(u string, client *http.Client) *HTTPPauseFetcher {
	if u == "" {
		u = DefaultPauseURL
	}
	if client == nil {
		client = newControlHTTPClient(nil)
	}
	return &HTTPPauseFetcher{URL: u, Client: client}
}

// FetchPause downloads the signed pause file from f.URL.
func (f *HTTPPauseFetcher) FetchPause(ctx context.Context) ([]byte, error) {
	return fetchSignedJSON(ctx, f.Client, f.URL, maxPauseFileBytes)
}

// fetchSignedJSON validates u and performs a bounded GET request.
func fetchSignedJSON(ctx context.Context, client *http.Client, rawURL string, maxBytes int64) ([]byte, error) {
	if err := validateControlURL(rawURL); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, pauseFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: fetch %s returned HTTP %d", rawURL, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("agent: %s exceeds %d bytes", rawURL, maxBytes)
	}
	return b, nil
}

// validateControlURL enforces strict URL rules on off-core pause and release
// fetches: no credentials or fragments, never-ports always refused, and for
// non-loopback hosts HTTPS on port 443 to non-denied addresses only.
func validateControlURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("agent: invalid control URL %q: %w", rawURL, err)
	}
	if u.Opaque != "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("agent: control URL %q must have no credentials or fragment", rawURL)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("agent: control URL %q has no host", rawURL)
	}
	portStr := u.Port()
	if portStr != "" {
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || p == 0 {
			return fmt.Errorf("agent: control URL %q has invalid port %q", rawURL, portStr)
		}
		if safety.IsNeverPort(uint16(p)) {
			return fmt.Errorf("agent: control URL %q uses forbidden port %d", rawURL, p)
		}
	}
	if isLoopbackHost(host) {
		if u.Scheme == "https" || u.Scheme == "http" {
			return nil
		}
		return fmt.Errorf("agent: control URL %q must use https:// or loopback http://", rawURL)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("agent: non-loopback control URL %q must use https://", rawURL)
	}
	if portStr != "" && portStr != "443" {
		return fmt.Errorf("agent: non-loopback control URL %q must use port 443", rawURL)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if denied, why := safety.Denied(ip); denied {
			return fmt.Errorf("agent: control URL %q targets denied address (%s)", rawURL, why)
		}
	}
	return nil
}

type ipLookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func defaultLookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// newControlHTTPClient builds the HTTP client for off-core pause and release
// artifact fetches: HTTP/1.1, TLS 1.3+, no redirects, no ambient proxy, and a
// DialContext that resolves and validates target IPs against safety.Denied.
func newControlHTTPClient(base *tls.Config) *http.Client {
	return newControlHTTPClientWithLookup(base, nil)
}

func newControlHTTPClientWithLookup(base *tls.Config, lookup ipLookupFunc) *http.Client {
	if lookup == nil {
		lookup = defaultLookupNetIP
	}
	c := newHTTPClient(base)
	tr := c.Transport.(*http.Transport)
	tr.Proxy = nil
	dialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("agent: invalid control dial address %q: %w", addr, err)
		}
		portNum, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || portNum == 0 {
			return nil, fmt.Errorf("agent: invalid control dial port %q", portStr)
		}
		port := uint16(portNum)
		if safety.IsNeverPort(port) {
			return nil, fmt.Errorf("agent: control dial to forbidden port %d", port)
		}
		loopbackHost := isLoopbackHost(host)
		if !loopbackHost && port != 443 {
			return nil, fmt.Errorf("agent: non-loopback control dial to %q must use port 443, got %d", host, port)
		}

		var candidates []netip.Addr
		if ip, perr := netip.ParseAddr(host); perr == nil {
			candidates = []netip.Addr{ip}
		} else {
			ips, lerr := lookup(ctx, host)
			if lerr != nil {
				return nil, lerr
			}
			candidates = ips
		}
		if len(candidates) == 0 {
			return nil, fmt.Errorf("agent: control host %q resolved to no addresses", host)
		}

		var allowed []netip.Addr
		var lastReason string
		for _, rawIP := range candidates {
			ip := rawIP.Unmap()
			if loopbackHost {
				if ip == netip.AddrFrom4([4]byte{127, 0, 0, 1}) || ip == netip.IPv6Loopback() {
					allowed = append(allowed, ip)
					continue
				}
				lastReason = "loopback host resolved to non-loopback address"
				continue
			}
			if denied, why := safety.Denied(rawIP); denied {
				lastReason = why
				continue
			}
			allowed = append(allowed, ip)
		}
		if len(allowed) == 0 {
			return nil, fmt.Errorf("agent: control address for %q refused (%s)", host, lastReason)
		}

		var firstErr error
		for _, ip := range allowed {
			conn, derr := dialer.DialContext(ctx, network, netip.AddrPortFrom(ip, port).String())
			if derr == nil {
				return conn, nil
			}
			if firstErr == nil {
				firstErr = derr
			}
		}
		return nil, firstErr
	}
	return c
}

// IsAnchorDomainHost reports whether host belongs to one of the compiled anchor
// domains (either an exact match or a subdomain label match), excluding the
// compiled off-core PauseHost which is never a measurement target.
func IsAnchorDomainHost(host string) bool {
	canon, err := safety.CanonicalHost(host)
	if err != nil {
		return false
	}
	if canon == safety.PauseHost || strings.HasSuffix(canon, "."+safety.PauseHost) {
		return false
	}
	if _, err := netip.ParseAddr(canon); err == nil {
		return false
	}
	for _, domain := range safety.AnchorDomains() {
		if canon == domain || strings.HasSuffix(canon, "."+domain) {
			return true
		}
	}
	return false
}

// ApplyPauseFile verifies a raw signed pause file against the compiled working
// root, applies any root-signed revocations, updates the pause state when
// monotonic and unexpired, and cancels active non-anchor jobs when entering a
// paused state.
func (a *Agent) ApplyPauseFile(raw []byte) (bool, error) {
	var spf SignedPauseFile
	if err := json.Unmarshal(raw, &spf); err != nil {
		return false, fmt.Errorf("agent: decode signed pause file: %w", err)
	}
	if len(spf.Body) == 0 {
		return false, errors.New("agent: pause file has an empty body")
	}
	if err := a.ring.VerifyWorkingRoot(protocol.PurposePauseFile, spf.Body, spf.Sig); err != nil {
		return false, fmt.Errorf("agent: pause file signature: %w", err)
	}
	var doc PauseDocument
	if err := json.Unmarshal(spf.Body, &doc); err != nil {
		return false, fmt.Errorf("agent: decode pause document: %w", err)
	}
	now := a.now().Unix()
	if doc.IssuedUnix <= 0 || doc.ExpiresUnix <= doc.IssuedUnix {
		return false, errors.New("agent: pause file has invalid validity timestamps")
	}
	if now >= doc.ExpiresUnix {
		return false, errors.New("agent: pause file is expired")
	}

	a.pauseMu.Lock()
	if doc.IssuedUnix < a.pauseLastIssuedUnix {
		a.pauseMu.Unlock()
		return false, errors.New("agent: pause file is older than an already accepted file")
	}
	a.pauseLastIssuedUnix = doc.IssuedUnix
	prevPaused := a.pauseActive
	a.pauseActive = doc.Paused
	if doc.Paused {
		a.pauseExpiresUnix = doc.ExpiresUnix
		a.pauseReason = doc.Reason
	} else {
		a.pauseExpiresUnix = 0
		a.pauseReason = ""
	}
	a.pauseMu.Unlock()

	for _, rev := range doc.Revocations {
		a.applyRevocation(rev.toProto())
	}
	if doc.Paused && !prevPaused {
		a.log.Warn("fleet pause active from off-core pause file; halting non-anchor work",
			"reason", doc.Reason, "expires_unix", doc.ExpiresUnix)
	} else if !doc.Paused && prevPaused {
		a.log.Info("fleet pause cleared by off-core pause file")
	}
	if doc.Paused {
		a.cancelNonAnchorJobs()
	}
	return doc.Paused, nil
}

// IsPaused reports whether a valid, unexpired off-core pause is currently active.
func (a *Agent) IsPaused() bool {
	return a.isPaused(a.now())
}

func (a *Agent) isPaused(now time.Time) bool {
	a.pauseMu.Lock()
	defer a.pauseMu.Unlock()
	if !a.pauseActive {
		return false
	}
	if now.Unix() >= a.pauseExpiresUnix {
		a.pauseActive = false
		a.pauseExpiresUnix = 0
		a.pauseReason = ""
		return false
	}
	return true
}

func (a *Agent) pollPauseOnce(ctx context.Context) {
	if a.cfg.PauseFetcher == nil {
		return
	}
	raw, err := a.cfg.PauseFetcher.FetchPause(ctx)
	if err != nil {
		if ctx.Err() == nil && !isNotExistOrConnRefused(err) {
			a.log.Warn("pause file fetch failed", "err", err)
		} else {
			a.log.Debug("pause file fetch failed", "err", err)
		}
		return
	}
	if _, err := a.ApplyPauseFile(raw); err != nil {
		a.log.Warn("rejected invalid pause file", "err", err)
	}
}

func isNotExistOrConnRefused(err error) bool {
	var ne net.Error
	return errors.As(err, &ne)
}

func (a *Agent) runPauseLoop(ctx context.Context) {
	if a.cfg.PauseFetcher == nil || a.cfg.PausePollInterval <= 0 {
		return
	}
	a.pollPauseOnce(ctx)
	ticker := time.NewTicker(a.cfg.PausePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.pollPauseOnce(ctx)
		}
	}
}
