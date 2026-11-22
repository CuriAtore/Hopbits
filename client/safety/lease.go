package safety

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
)

// errLeaseClosed refuses network access through a lease that has ended.
var errLeaseClosed = module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "the job's network access has ended")

// guardLease is an admitted job's bounded network access. It implements
// module.Lease and, through it, module.TargetNet. It owns what it hands
// out: one ICMP packet budget for every pinger, and every connection and
// pinger, which Close closes.
type guardLease struct {
	g             *Guard
	host          string
	port          uint16
	addr          netip.Addr
	resolution    nodev1.ResolutionSource
	verified      bool
	transport     module.Transport
	measurementID string
	// echoes is the lease's cap on echo requests, shared by every pinger
	// it hands out.
	echoes *echoBudget
	// traces is the lease's cap on hop-limited trace probes.
	traces *echoBudget
	// dnsQueries bounds QueryDNS calls per lease.
	dnsQueries *echoBudget

	mu     sync.Mutex
	closed bool
	// opened are the connections and pingers handed out, for Close.
	opened []io.Closer
}

// Host returns the hostname for TLS SNI and the HTTP Host header, in the
// canonical form the guard judged.
func (l *guardLease) Host() string { return l.host }

// Port returns the validated destination port, 0 for ICMP.
func (l *guardLease) Port() uint16 { return l.port }

// Addr returns the validated address the job connects to.
func (l *guardLease) Addr() netip.Addr { return l.addr }

// Resolution reports how Addr was chosen.
func (l *guardLease) Resolution() nodev1.ResolutionSource { return l.resolution }

// Verified reports whether the target carries a valid target grant and the
// address lies in its proven set.
func (l *guardLease) Verified() bool { return l.verified }

// DialTCP opens a TCP connection to Addr:Port, re-checking the address
// rules first and counting bytes against the daily budget. It refuses once
// the lease is closed.
func (l *guardLease) DialTCP(ctx context.Context) (net.Conn, error) {
	if l.transport != module.TransportTCP {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "lease is not a TCP lease")
	}
	if l.isClosed() {
		return nil, errLeaseClosed
	}
	if err := l.g.recheckDial(l.addr); err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(l.addr, l.port).String())
	if err != nil {
		return nil, fmt.Errorf("safety: dial %s: %w", netip.AddrPortFrom(l.addr, l.port), err)
	}
	cc := &countingConn{Conn: conn, g: l.g}
	if !l.track(cc) {
		_ = conn.Close()
		return nil, errLeaseClosed
	}
	return cc, nil
}

// Pinger returns an ICMP echo sender bound to Addr, under the shared ICMP
// rate cap and the lease's packet cap, which every pinger of the lease
// draws from. It re-checks the address rules first and refuses once the
// lease is closed.
func (l *guardLease) Pinger() (module.Pinger, error) {
	if l.transport != module.TransportICMP {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "lease is not an ICMP lease")
	}
	if l.isClosed() {
		return nil, errLeaseClosed
	}
	if err := l.g.recheckDial(l.addr); err != nil {
		return nil, err
	}
	p, err := l.g.newPinger(l.addr, l.echoes)
	if err != nil {
		return nil, err
	}
	if !l.track(p) {
		_ = p.Close()
		return nil, errLeaseClosed
	}
	return p, nil
}

// CheckHTTP enforces the compiled HTTP request rules for this target.
func (l *guardLease) CheckHTTP(method, path string) error {
	if method != http.MethodGet && method != http.MethodHead {
		return module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "method %q is not GET or HEAD", method)
	}
	if len(path) == 0 || path[0] != '/' {
		return module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "path must start with /")
	}
	if len(path) >= 2 && path[1] == '/' {
		return module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "path must not start with //")
	}
	if len(path) > 2048 {
		return module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "path exceeds 2048 bytes")
	}
	for i := 0; i < len(path); i++ {
		if c := path[i]; c < 0x20 || c == 0x7f || c == ' ' {
			return module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "path has a control character or space")
		}
	}
	if !l.verified {
		for i := 0; i < len(path); i++ {
			if c := path[i]; c == '?' || c == '#' {
				return module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "query or fragment not allowed on an unverified target")
			}
		}
		if len(path) > 128 {
			return module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "path exceeds 128 bytes on an unverified target")
		}
	}
	return nil
}

// ProbeHeaders returns the attribution headers every HTTP probe carries.
// Admit has checked that the measurement id is short and plain.
func (l *guardLease) ProbeHeaders() http.Header {
	h := make(http.Header, 2)
	h.Set("User-Agent", ProbeUserAgent)
	h.Set(ProbeHeader, l.measurementID)
	return h
}

// Close releases the concurrency slot and closes every connection and
// pinger the lease handed out that is still open. It is idempotent; after
// it, DialTCP and Pinger refuse.
func (l *guardLease) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	opened := l.opened
	l.opened = nil
	l.mu.Unlock()
	for _, c := range opened {
		// The module usually closed it already; closing again is harmless.
		_ = c.Close()
	}
	l.g.release()
	return nil
}

func (l *guardLease) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// track records c for Close, unless the lease has closed meanwhile.
func (l *guardLease) track(c io.Closer) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	l.opened = append(l.opened, c)
	return true
}

// recheckDial checks addr again right before a connection or an echo
// request, with the rules in force now: the deny ranges, a refused family,
// the own network, the added deny prefixes, the do-not-probe prefixes, the
// pause host's addresses and, for an address under a NAT64 prefix, the
// IPv4 address it reaches.
func (g *Guard) recheckDial(addr netip.Addr) error {
	g.mu.Lock()
	p := g.policyLocked()
	g.mu.Unlock()
	a := addr.Unmap()
	if why, ok := g.destAllowed(a, &p); !ok {
		return module.Refuse(nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL, "target denied locally: %s", why)
	}
	if v4, ok := nat64Destination(a, p.local.nat64); ok {
		if why, ok := g.destAllowed(v4, &p); !ok {
			return module.Refuse(nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL, "target denied locally: NAT64 of %s", why)
		}
	}
	return nil
}

// countingConn charges bytes read and written to the daily traffic counter.
type countingConn struct {
	net.Conn
	g *Guard
}

// Read reads from the connection and charges the bytes.
func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.g.addTraffic(int64(n))
	}
	return n, err
}

// Write writes to the connection and charges the bytes.
func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.g.addTraffic(int64(n))
	}
	return n, err
}
