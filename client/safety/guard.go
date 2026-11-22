package safety

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
)

// Resolver resolves names to addresses. *net.Resolver satisfies it.
type Resolver interface {
	// LookupNetIP resolves host for network "ip4" or "ip6".
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Contract assertions: the safety types satisfy the module contracts and
// net.DefaultResolver satisfies Resolver.
var (
	_ module.Gate      = (*Guard)(nil)
	_ module.Lease     = (*guardLease)(nil)
	_ module.Pinger    = (*icmpPinger)(nil)
	_ module.HostProbe = (*hostProbe)(nil)
	_ Resolver         = (*net.Resolver)(nil)
)

// GrantVerifier verifies a signed target grant against the root-certified
// grant key and the current time.
type GrantVerifier interface {
	// VerifyGrant returns the grant's body when its signature verifies and it
	// is valid at now, or an error.
	VerifyGrant(g *nodev1.SignedTargetGrant, now time.Time) (*nodev1.TargetGrant, error)
}

// Config configures a Guard.
type Config struct {
	// Caps are the compiled caps the guard starts with. Session limits can
	// only lower them, and a session without limits returns to them.
	Caps Caps
	// Now is the guard's clock; defaults to time.Now.
	Now func() time.Time
	// Resolver resolves anchor and proven targets, the pause host and
	// ipv4only.arpa; defaults to net.DefaultResolver.
	Resolver Resolver
	// Grants verifies target grants; nil means no grant is ever valid.
	Grants GrantVerifier
	// ResolveTimeout bounds one local resolution; defaults to 1500 ms.
	ResolveTimeout time.Duration
	// TrafficFile, if set, is where the guard keeps the current UTC day's
	// traffic count, so a restart does not start a fresh daily budget.
	TrafficFile string
	// TestAllowPrefixes exempts matching addresses from Denied and the
	// own-network refusal. Honoured only under the hopbits_unsafe_testing
	// build tag; otherwise NewGuard panics when it is set.
	TestAllowPrefixes []netip.Prefix
	// TestAllowPorts are allowed for any kind. Honoured only under the
	// hopbits_unsafe_testing build tag; otherwise NewGuard panics when set.
	TestAllowPorts []uint16
}

// Fixed limits of the guard.
const (
	// MaxProvenAddresses is the most addresses a job's proven set may hold.
	MaxProvenAddresses = 16
	// sweepEvery is how often Admit drops the per-destination entries that
	// can no longer refuse a job, so memory follows the recent jobs.
	sweepEvery = 5 * time.Minute
)

type dnpKind int

const (
	dnpExact dnpKind = iota
	dnpSuffix
	dnpPrefix
)

type dnpEntry struct {
	kind   dnpKind
	host   string
	prefix netip.Prefix
}

// Guard admits jobs to the network under the compiled caps and owns every
// socket a module uses. It is safe for concurrent use and implements
// module.Gate.
type Guard struct {
	now            func() time.Time
	resolver       Resolver
	grants         GrantVerifier
	resolveTimeout time.Duration
	testPrefixes   []netip.Prefix
	testPorts      []uint16
	// compiled are the caps the guard was built with; session limits are
	// applied to them, never to the last limits.
	compiled Caps
	// traffic keeps the daily traffic count across restarts; nil when no
	// file is configured.
	traffic *trafficStore
	// dialICMP opens an ICMP socket. Tests replace it with a fake socket.
	dialICMP func(dst netip.Addr) (icmpConn, error)
	// dialDNS opens a UDP or TCP DNS connection. Tests replace it.
	dialDNS func(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error)
	// resolvConf overrides /etc/resolv.conf in tests.
	resolvConf string
	// traceHop sends one hop-limited probe. Tests replace it.
	traceHop func(ctx context.Context, g *Guard, dst netip.Addr, proto string, ttl, seq int, timeout time.Duration) (rawHopSample, error)

	// localMu serialises the guard's own lookups of the pause host and of
	// ipv4only.arpa.
	localMu sync.Mutex

	mu         sync.Mutex
	caps       Caps
	open       int
	admits     []time.Time
	lastDomain map[string]time.Time
	lastPrefix map[netip.Prefix]time.Time
	domainHits map[string][]time.Time
	lastSweep  time.Time
	ownNet     []netip.Prefix
	refuse4    bool
	refuse6    bool
	addDeny    []netip.Prefix
	dnp        []dnpEntry
	// local is what the guard's own lookups learnt; localNext is when to
	// look again (zero: before the next admission), and localGen counts
	// network changes, so a lookup that raced one is not trusted for long.
	local        localNames
	localNext    time.Time
	localGen     uint64
	trafficDay   string
	trafficUsed  int64
	trafficSaved int64

	icmp *tokenBucket
}

// NewGuard builds a Guard from cfg, applying the documented defaults. With
// a TrafficFile it resumes the day's traffic count from that file.
func NewGuard(cfg Config) *Guard {
	if !testHooksEnabled && (len(cfg.TestAllowPrefixes) > 0 || len(cfg.TestAllowPorts) > 0) {
		panic("safety: Config.TestAllow* set without the hopbits_unsafe_testing build tag")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	res := cfg.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	rt := cfg.ResolveTimeout
	if rt == 0 {
		rt = 1500 * time.Millisecond
	}
	g := &Guard{
		now:            now,
		resolver:       res,
		grants:         cfg.Grants,
		resolveTimeout: rt,
		compiled:       cfg.Caps,
		dialICMP:       dialICMP,
		dialDNS:        defaultDialDNS,
		resolvConf:     defaultResolvConf,
		traceHop:       defaultTraceHop,
		caps:           cfg.Caps,
		lastDomain:     make(map[string]time.Time),
		lastPrefix:     make(map[netip.Prefix]time.Time),
		domainHits:     make(map[string][]time.Time),
	}
	if testHooksEnabled {
		g.testPrefixes = append([]netip.Prefix(nil), cfg.TestAllowPrefixes...)
		g.testPorts = append([]uint16(nil), cfg.TestAllowPorts...)
	}
	if cfg.TrafficFile != "" {
		g.traffic = &trafficStore{path: cfg.TrafficFile}
		if r, ok := g.traffic.load(); ok && r.Day == utcDay(now()) {
			g.trafficDay, g.trafficUsed, g.trafficSaved = r.Day, r.UsedBytes, r.UsedBytes
		}
	}
	g.icmp = newTokenBucket(now, cfg.Caps.ICMPPacketsPerSecond)
	return g
}

// Admit validates job's target against the compiled rules, charges the
// compiled caps and returns the job's network access, or a *module.Refusal.
func (g *Guard) Admit(ctx context.Context, job *module.Job, needs module.Needs) (module.Lease, error) {
	if job == nil || job.Target == nil {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "job has no target")
	}
	now := g.now()
	target := job.Target
	// Every rule below judges the one form of the host the network sees.
	host, err := CanonicalHost(target.GetHost())
	if err != nil {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "%v", err)
	}
	if !ValidMeasurementID(job.MeasurementID) {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION,
			"the measurement id must be 1 to %d letters, digits, hyphens or underscores", MaxMeasurementIDBytes)
	}
	proven := target.GetProvenAddresses()
	if len(proven) > MaxProvenAddresses {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION,
			"the proven set holds %d addresses, at most %d allowed", len(proven), MaxProvenAddresses)
	}

	// Step 1: the pause host is never a target. Its name is refused here and
	// the addresses it resolves to in step 4.
	if host == PauseHost {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "the pause host is never a target")
	}
	literal, perr := netip.ParseAddr(host)
	isLiteral := perr == nil
	if isLiteral {
		literal = literal.Unmap()
	}
	fam := target.GetFamily()
	anchorHost := !isLiteral && hostUnderAnchorDomain(host)

	// A grant lifts the port list and the domain window only for its
	// hostname at its proven addresses, so only an address-proven target
	// may use one.
	var grant *nodev1.TargetGrant
	if !anchorHost && len(proven) > 0 {
		grant = g.verifyGrant(target, host, now)
	}

	// Step 2: port policy.
	port := uint16(target.GetPort())
	isDNS := needs.Transport == module.TransportDNS
	switch needs.Transport {
	case module.TransportICMP:
		if port != 0 {
			return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "ICMP target must have port 0, got %d", port)
		}
	case module.TransportDNS:
		if port != 0 && port != 53 {
			return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "DNS target must have port 0 or 53, got %d", port)
		}
	case module.TransportTCP:
		if err := g.checkPort(port, needs.Ports, grant); err != nil {
			return nil, err
		}
	default:
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "unknown transport %d", int(needs.Transport))
	}

	// Step 3: address selection.
	var (
		candidates []netip.Addr
		resolution nodev1.ResolutionSource
		verified   bool
	)
	switch {
	case anchorHost && !isDNS:
		answers, err := g.resolve(ctx, host, fam)
		if err != nil {
			return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "anchor resolution failed: %v", err)
		}
		if pin := target.GetPinnedAddress(); pin != "" {
			pa, perr := netip.ParseAddr(pin)
			if perr != nil {
				return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "bad pinned address")
			}
			pa = pa.Unmap()
			if !containsAddr(answers, pa) {
				return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "pinned address not in anchor resolution")
			}
			candidates = []netip.Addr{pa}
		} else {
			candidates = answers
		}
		resolution = nodev1.ResolutionSource_RESOLUTION_SOURCE_LOCAL

	case len(proven) > 0 && !isDNS:
		if grant == nil {
			return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING, "address-proven target needs a target grant")
		}
		answers, err := g.resolve(ctx, host, fam)
		if err != nil {
			return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "resolution failed: %v", err)
		}
		jobSet := parseAddrs(proven)
		grantSet := parseAddrs(grant.GetProvenAddresses())
		for _, a := range answers {
			if containsAddr(jobSet, a) && containsAddr(grantSet, a) {
				candidates = append(candidates, a)
			}
		}
		if len(candidates) == 0 {
			return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "no resolved address lies in both proven sets")
		}
		resolution = nodev1.ResolutionSource_RESOLUTION_SOURCE_LOCAL
		verified = true

	default:
		pin := target.GetPinnedAddress()
		if pin == "" {
			return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "target carries no pinned address")
		}
		pa, perr := netip.ParseAddr(pin)
		if perr != nil {
			return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "bad pinned address")
		}
		pa = pa.Unmap()
		if !familyMatches(pa, fam) {
			return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "pinned address has the wrong family")
		}
		if isLiteral && !isDNS && pa != literal {
			return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "pinned address does not equal the IP-literal target")
		}
		candidates = []netip.Addr{pa}
		resolution = nodev1.ResolutionSource_RESOLUTION_SOURCE_SERVER
		if isDNS && grant != nil {
			verified = true
		}
	}

	if len(candidates) == 0 {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "no candidate address")
	}

	// Step 4: the chosen address must pass the deny ranges, a refused
	// family, the own network, the added deny prefixes, the do-not-probe
	// list and the pause host's addresses, and an address under a NAT64
	// prefix the IPv4 address it reaches must pass them too.
	local := g.refreshLocal(ctx)
	g.mu.Lock()
	policy := g.policyLocked()
	g.mu.Unlock()
	policy.local = local

	if isDNS {
		if reason, ok := g.dnsHostAllowed(host, &policy); !ok {
			return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL, "target denied locally: %s", reason)
		}
	}

	var (
		chosen     netip.Addr
		found      bool
		lastReason string
	)
	for _, a := range candidates {
		reason, ok := g.addressAllowed(host, a, &policy)
		if ok {
			chosen, found = a, true
			break
		}
		lastReason = reason
	}
	if !found {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL, "target denied locally: %s", lastReason)
	}

	// A job that ended while its target was checked is never charged.
	if err := ctx.Err(); err != nil {
		code := nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY
		if errors.Is(err, context.DeadlineExceeded) {
			code = nodev1.ErrorCode_ERROR_CODE_JOB_EXPIRED
		}
		return nil, module.Refuse(code, "the job ended before it was admitted")
	}

	// Steps 5 and 6: caps, then charge. A grant lifts the domain window
	// only when the chosen address lies in both proven sets.
	dom := RegistrableDomain(host)
	enforcePrefix := !isDNS || isLiteral
	pfx := destPrefix(chosen)
	if isDNS && isLiteral {
		pfx = destPrefix(literal)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	caps := g.caps
	g.sweepLocked(now, caps)

	if g.open >= caps.MaxConcurrency {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_CAPACITY, "concurrency cap %d reached", caps.MaxConcurrency)
	}
	g.pruneAdmits(now)
	if len(g.admits) >= caps.JobsPerMinute {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED, "jobs-per-minute cap %d reached", caps.JobsPerMinute)
	}
	if caps.DomainSpacing > 0 {
		if t, ok := g.lastDomain[dom]; ok && now.Sub(t) < caps.DomainSpacing {
			return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED, "domain spacing not met for %s", dom)
		}
		if enforcePrefix {
			if t, ok := g.lastPrefix[pfx]; ok && now.Sub(t) < caps.DomainSpacing {
				return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED, "destination spacing not met for %s", pfx)
			}
		}
	}
	windowEnforced := caps.DomainJobsPerWindow > 0 && caps.DomainWindow > 0 && !verified && !anchorHost
	if windowEnforced && countHits(g.domainHits[dom], now, caps.DomainWindow) >= caps.DomainJobsPerWindow {
		return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED, "domain window cap %d reached for %s", caps.DomainJobsPerWindow, dom)
	}
	if caps.DailyTrafficBytes != 0 {
		g.rollTrafficDay(now)
		if g.trafficUsed >= caps.DailyTrafficBytes {
			return nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_BUDGET_EXHAUSTED, "daily traffic budget exhausted")
		}
	}

	// Charge.
	g.admits = append(g.admits, now)
	g.lastDomain[dom] = now
	if enforcePrefix {
		g.lastPrefix[pfx] = now
	}
	if windowEnforced {
		g.domainHits[dom] = append(pruneHits(g.domainHits[dom], now, caps.DomainWindow), now)
	}
	g.open++

	return &guardLease{
		g:             g,
		host:          host,
		port:          port,
		addr:          chosen,
		resolution:    resolution,
		verified:      verified,
		transport:     needs.Transport,
		measurementID: job.MeasurementID,
		echoes:        &echoBudget{max: caps.MaxPingPackets},
		traces:        &echoBudget{max: maxTracePackets},
		dnsQueries:    &echoBudget{max: maxDNSQueriesPerLease},
	}, nil
}

// SetOwnNetwork records the node's own network: its interface prefixes, each
// observed IPv4 address widened to /24, and each observed IPv6 address and
// each global interface IPv6 address widened to /48. A new own network
// means the node's network may have changed, so the guard also looks up the
// pause host and its NAT64 prefixes again before the next admission.
func (g *Guard) SetOwnNetwork(interfacePrefixes []netip.Prefix, observed []netip.Addr) {
	var own []netip.Prefix
	for _, p := range interfacePrefixes {
		if !p.IsValid() {
			continue
		}
		pp := p.Masked()
		own = append(own, pp)
		a := pp.Addr()
		if a.Is6() && !a.Is4() && globalUnicastV6.Contains(a) && pp.Bits() >= 48 {
			if w, err := a.Prefix(48); err == nil {
				own = append(own, w)
			}
		}
	}
	for _, a := range observed {
		a = a.Unmap()
		if !a.IsValid() {
			continue
		}
		bits := 24
		if a.Is6() {
			bits = 48
		}
		if w, err := a.Prefix(bits); err == nil {
			own = append(own, w)
		}
	}
	g.mu.Lock()
	g.ownNet = own
	g.localGen++
	g.localNext = time.Time{}
	g.mu.Unlock()
}

// RefuseFamilies sets the address families the guard refuses outright
// because the node's own network in them is unknown: IPv4 when the gateway
// saw no IPv4 address of the node, IPv6 in a container network mode when it
// saw no IPv6 address. Each call replaces the previous setting.
func (g *Guard) RefuseFamilies(ipv4, ipv6 bool) {
	g.mu.Lock()
	g.refuse4, g.refuse6 = ipv4, ipv6
	g.mu.Unlock()
}

// ApplyLimits sets the session limits a Welcome or ConfigUpdate carries.
// Each field can only lower its compiled cap, and is applied to the
// compiled cap, not to an earlier limit: a higher later value (never above
// the compiled cap) lifts an earlier lower one, and a zero field or a nil l
// restores the compiled value. A compiled cap of zero allows nothing and
// stays so, except the daily traffic budget, where zero means no budget and
// a limit sets one.
func (g *Guard) ApplyLimits(l *nodev1.Limits) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.compiled
	c.JobsPerMinute = lowerCap(c.JobsPerMinute, l.GetJobsPerMinute())
	c.MaxConcurrency = lowerCap(c.MaxConcurrency, l.GetMaxConcurrency())
	c.ICMPPacketsPerSecond = lowerCap(c.ICMPPacketsPerSecond, l.GetIcmpPacketsPerSecond())
	if v := l.GetDailyTrafficBytes(); v != 0 && v <= uint64(1<<63-1) {
		if b := int64(v); c.DailyTrafficBytes == 0 || b < c.DailyTrafficBytes {
			c.DailyTrafficBytes = b
		}
	}
	g.caps = c
	g.icmp.setRate(c.ICMPPacketsPerSecond)
}

// lowerCap applies a session limit to a compiled count cap: a limit only
// ever lowers it, and zero means no limit.
func lowerCap(compiled int, limit uint32) int {
	if limit == 0 || compiled <= 0 || int64(limit) >= int64(compiled) {
		return compiled
	}
	return int(limit)
}

// AddDenyPrefixes adds server-supplied deny prefixes to the compiled ranges.
func (g *Guard) AddDenyPrefixes(p []netip.Prefix) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range p {
		if x.IsValid() {
			g.addDeny = append(g.addDeny, x.Masked())
		}
	}
}

// SetDoNotProbe sets the do-not-probe list: CIDR prefixes, exact hostnames or
// ".suffix" domain suffixes.
func (g *Guard) SetDoNotProbe(entries []string) {
	var out []dnpEntry
	for _, s := range entries {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.ContainsRune(s, '/') {
			if p, err := netip.ParsePrefix(s); err == nil {
				out = append(out, dnpEntry{kind: dnpPrefix, prefix: p.Masked()})
			}
			continue
		}
		s = strings.ToLower(strings.TrimSuffix(s, "."))
		if strings.HasPrefix(s, ".") {
			out = append(out, dnpEntry{kind: dnpSuffix, host: s})
			continue
		}
		out = append(out, dnpEntry{kind: dnpExact, host: s})
	}
	g.mu.Lock()
	g.dnp = out
	g.mu.Unlock()
}

// HostProbe returns a self-test probe bound to this guard's sockets.
func (g *Guard) HostProbe() module.HostProbe {
	return &hostProbe{g: g}
}

// Effective returns the caps now in force.
func (g *Guard) Effective() Caps {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.caps
}

// checkPort applies the compiled TCP port policy. grant is nil unless the
// target is address-proven.
func (g *Guard) checkPort(port uint16, modPorts []uint16, grant *nodev1.TargetGrant) error {
	if testHooksEnabled && containsU16(g.testPorts, port) {
		return nil
	}
	if IsNeverPort(port) {
		return module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "port %d is on the never-list", port)
	}
	if containsU16(modPorts, port) && containsU16(allowedPorts[:], port) {
		return nil
	}
	if grant != nil && grantHasPort(grant, port) {
		return nil
	}
	return module.Refuse(nodev1.ErrorCode_ERROR_CODE_GRANT_MISSING, "port %d needs a target grant", port)
}

// netPolicy is a snapshot of the address rules the server and the network
// can change, taken for one decision.
type netPolicy struct {
	ownNet  []netip.Prefix
	addDeny []netip.Prefix
	dnp     []dnpEntry
	refuse4 bool
	refuse6 bool
	local   localNames
}

// policyLocked snapshots the address rules. g.mu must be held.
func (g *Guard) policyLocked() netPolicy {
	return netPolicy{
		ownNet:  g.ownNet,
		addDeny: g.addDeny,
		dnp:     g.dnp,
		refuse4: g.refuse4,
		refuse6: g.refuse6,
		local:   g.local,
	}
}

// addressAllowed reports whether a candidate address passes step 4 for
// host, and why not.
func (g *Guard) addressAllowed(host string, addr netip.Addr, p *netPolicy) (string, bool) {
	a := addr.Unmap()
	if why, ok := g.destAllowed(a, p); !ok {
		return why, false
	}
	if v4, ok := nat64Destination(a, p.local.nat64); ok {
		if why, ok := g.destAllowed(v4, p); !ok {
			return "NAT64 of " + why, false
		}
	}
	for _, e := range p.dnp {
		switch e.kind {
		case dnpSuffix:
			if host == e.host[1:] || strings.HasSuffix(host, e.host) {
				return "do-not-probe " + e.host, false
			}
		case dnpExact:
			if host == e.host {
				return "do-not-probe " + e.host, false
			}
		}
	}
	return "", true
}

// destAllowed applies the address rules to one destination address: the
// compiled deny ranges, a refused family and the own network (all of which
// the unsafe test hooks may exempt), then the added deny prefixes, the
// do-not-probe prefixes and the pause host's addresses.
func (g *Guard) destAllowed(a netip.Addr, p *netPolicy) (string, bool) {
	a = a.Unmap()
	if !(testHooksEnabled && prefixesContain(g.testPrefixes, a)) {
		if denied, why := Denied(a); denied {
			return why, false
		}
		if a.Is4() && p.refuse4 {
			return "IPv4 target while the node's own IPv4 network is unknown", false
		}
		if a.Is6() && p.refuse6 {
			return "IPv6 target while the node's own IPv6 network is unknown", false
		}
		for _, n := range p.ownNet {
			if n.Contains(a) {
				return "own network", false
			}
		}
	}
	for _, d := range p.addDeny {
		if d.Contains(a) {
			return "deny prefix " + d.String(), false
		}
	}
	for _, e := range p.dnp {
		if e.kind == dnpPrefix && e.prefix.Contains(a) {
			return "do-not-probe " + e.prefix.String(), false
		}
	}
	if containsAddr(p.local.pause, a) {
		return "an address of the pause host", false
	}
	return "", true
}

// verifyGrant returns target's grant when it verifies, names host and has not
// expired, or nil.
func (g *Guard) verifyGrant(target *nodev1.Target, host string, now time.Time) *nodev1.TargetGrant {
	sg := target.GetGrant()
	if sg == nil || g.grants == nil {
		return nil
	}
	tg, err := g.grants.VerifyGrant(sg, now)
	if err != nil || tg == nil {
		return nil
	}
	if !strings.EqualFold(strings.TrimSuffix(tg.GetHostname(), "."), host) {
		return nil
	}
	if exp := tg.GetExpiresUnix(); exp != 0 && now.Unix() >= exp {
		return nil
	}
	return tg
}

// resolve performs one local resolution of host for the target's family.
func (g *Guard) resolve(ctx context.Context, host string, fam nodev1.AddressFamily) ([]netip.Addr, error) {
	network := "ip4"
	if fam == nodev1.AddressFamily_ADDRESS_FAMILY_IPV6 {
		network = "ip6"
	}
	return g.lookup(ctx, host, network)
}

// lookup resolves host for network ("ip4" or "ip6") under the resolve
// timeout and returns the answers un-mapped.
func (g *Guard) lookup(ctx context.Context, host, network string) ([]netip.Addr, error) {
	rctx, cancel := context.WithTimeout(ctx, g.resolveTimeout)
	defer cancel()
	addrs, err := g.resolver.LookupNetIP(rctx, network, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap())
	}
	return out, nil
}

func (g *Guard) pruneAdmits(now time.Time) {
	cutoff := now.Add(-60 * time.Second)
	i := 0
	for _, t := range g.admits {
		if t.After(cutoff) {
			g.admits[i] = t
			i++
		}
	}
	g.admits = g.admits[:i]
}

// countHits counts the hits inside the window ending at now, without
// changing anything, so a refused job leaves no trace.
func countHits(hits []time.Time, now time.Time, window time.Duration) int {
	cutoff := now.Add(-window)
	n := 0
	for _, t := range hits {
		if t.After(cutoff) {
			n++
		}
	}
	return n
}

// pruneHits returns the hits inside the window ending at now, reusing hits.
func pruneHits(hits []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	i := 0
	for _, t := range hits {
		if t.After(cutoff) {
			hits[i] = t
			i++
		}
	}
	return hits[:i]
}

// sweepLocked drops, every sweepEvery, the spacing entries older than the
// spacing and the domains with no hit left in the window, so the maps hold
// only destinations that can still refuse a job. g.mu must be held.
func (g *Guard) sweepLocked(now time.Time, caps Caps) {
	if now.Sub(g.lastSweep) < sweepEvery {
		return
	}
	g.lastSweep = now
	for d, t := range g.lastDomain {
		if now.Sub(t) >= caps.DomainSpacing {
			delete(g.lastDomain, d)
		}
	}
	for p, t := range g.lastPrefix {
		if now.Sub(t) >= caps.DomainSpacing {
			delete(g.lastPrefix, p)
		}
	}
	for d, hits := range g.domainHits {
		if kept := pruneHits(hits, now, caps.DomainWindow); len(kept) > 0 {
			g.domainHits[d] = kept
		} else {
			delete(g.domainHits, d)
		}
	}
}

// release returns a concurrency slot to the pool.
func (g *Guard) release() {
	g.mu.Lock()
	if g.open > 0 {
		g.open--
	}
	g.mu.Unlock()
}

// hostUnderAnchorDomain reports whether host, in CanonicalHost form, equals a
// compiled anchor domain or is a subdomain of it on a label boundary.
func hostUnderAnchorDomain(host string) bool {
	for _, d := range anchorDomains {
		d = strings.ToLower(d)
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func destPrefix(addr netip.Addr) netip.Prefix {
	a := addr.Unmap()
	bits := 24
	if a.Is6() {
		bits = 48
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return netip.PrefixFrom(a, a.BitLen())
	}
	return p
}

func familyMatches(a netip.Addr, fam nodev1.AddressFamily) bool {
	switch fam {
	case nodev1.AddressFamily_ADDRESS_FAMILY_IPV4:
		return a.Is4()
	case nodev1.AddressFamily_ADDRESS_FAMILY_IPV6:
		return a.Is6() && !a.Is4()
	default:
		return true
	}
}

func parseAddrs(ss []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}

func containsAddr(set []netip.Addr, a netip.Addr) bool {
	a = a.Unmap()
	for _, x := range set {
		if x.Unmap() == a {
			return true
		}
	}
	return false
}

func containsU16(set []uint16, v uint16) bool {
	for _, x := range set {
		if x == v {
			return true
		}
	}
	return false
}

func grantHasPort(g *nodev1.TargetGrant, port uint16) bool {
	for _, p := range g.GetPorts() {
		if p == uint32(port) {
			return true
		}
	}
	return false
}

func prefixesContain(prefixes []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
