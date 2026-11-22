package safety

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// How long the guard trusts its own lookups of the pause host and of
// ipv4only.arpa: localTTL after an answer, localRetry after a lookup that
// failed.
const (
	localTTL   = 10 * time.Minute
	localRetry = time.Minute
)

// localNames is what the guard learns from its own resolver: the addresses
// of the pause host, which no job may reach under any name, and the NAT64
// prefixes of the node's network, whose addresses are judged by the IPv4
// address they reach.
type localNames struct {
	pause []netip.Addr
	nat64 []netip.Prefix
}

// refreshLocal returns what the guard knows of the pause host and the NAT64
// prefixes, looking both up again first when the last lookup is old or the
// network changed. The lookups run at once, each bounded by the resolve
// timeout. A lookup that fails keeps what an earlier one learnt and is
// tried again after localRetry; a name with no address in a family learns
// that it has none.
func (g *Guard) refreshLocal(ctx context.Context) localNames {
	g.localMu.Lock()
	defer g.localMu.Unlock()
	g.mu.Lock()
	cur, next, gen := g.local, g.localNext, g.localGen
	g.mu.Unlock()
	now := g.now()
	if !next.IsZero() && now.Before(next) {
		return cur
	}

	var (
		wg              sync.WaitGroup
		p4, p6, n64     []netip.Addr
		e4, e6, eLookup error
	)
	wg.Go(func() { p4, e4 = g.lookup(ctx, PauseHost, "ip4") })
	wg.Go(func() { p6, e6 = g.lookup(ctx, PauseHost, "ip6") })
	wg.Go(func() { n64, eLookup = g.lookup(ctx, ipv4OnlyARPA, "ip6") })
	wg.Wait()
	if ctx.Err() != nil {
		// The job ended while the guard looked; the next admission looks again.
		return cur
	}

	failed := false
	pause4, pause6 := familyOf(cur.pause, true), familyOf(cur.pause, false)
	switch {
	case e4 == nil:
		pause4 = familyOf(p4, true)
	case noAddress(e4):
		pause4 = nil
	default:
		failed = true
	}
	switch {
	case e6 == nil:
		pause6 = familyOf(p6, false)
	case noAddress(e6):
		pause6 = nil
	default:
		failed = true
	}
	upd := localNames{pause: append(pause4, pause6...), nat64: cur.nat64}
	switch {
	case eLookup == nil:
		upd.nat64 = nat64Prefixes(n64)
	case noAddress(eLookup):
		upd.nat64 = nil
	default:
		failed = true
	}

	wait := localTTL
	if failed {
		wait = localRetry
	}
	g.mu.Lock()
	g.local = upd
	if g.localGen == gen {
		g.localNext = now.Add(wait)
	}
	g.mu.Unlock()
	return upd
}

// familyOf returns the IPv4 (v4 true) or IPv6 addresses of addrs.
func familyOf(addrs []netip.Addr, v4 bool) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if a.IsValid() && a.Is4() == v4 {
			out = append(out, a)
		}
	}
	return out
}

// noAddress reports whether a lookup error says the name has no address in
// the family asked for, as opposed to a lookup that could not finish.
func noAddress(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	var addrErr *net.AddrError
	return errors.As(err, &addrErr)
}
