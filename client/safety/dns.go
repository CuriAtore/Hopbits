package safety

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
)

const (
	// dnsTypeCAA is the IANA RR type code for CAA (RFC 8659).
	dnsTypeCAA dnsmessage.Type = 257

	// maxDNSAnswers bounds how many answer records one DNS result carries.
	maxDNSAnswers = 32
	// maxDNSUDPBytes is the largest UDP DNS response buffer read.
	maxDNSUDPBytes = 4096
	// maxDNSTCPBytes is the largest TCP DNS response message read.
	maxDNSTCPBytes = 65535
	// maxDNSQueriesPerLease caps QueryDNS calls on a single lease.
	maxDNSQueriesPerLease = 2
	// defaultResolvConf is the system resolver file read for "isp".
	defaultResolvConf = "/etc/resolv.conf"
)

type publicResolverAddrs struct {
	v4 string
	v6 string
}

// allowedPublicResolvers is the compiled allowlist of public recursive DNS
// resolvers a job may select, paired with their IPv6 equivalents.
var allowedPublicResolvers = map[string]publicResolverAddrs{
	"1.1.1.1":        {v4: "1.1.1.1:53", v6: "[2606:4700:4700::1111]:53"},
	"8.8.8.8":        {v4: "8.8.8.8:53", v6: "[2001:4860:4860::8888]:53"},
	"9.9.9.9":        {v4: "9.9.9.9:53", v6: "[2620:fe::fe]:53"},
	"208.67.222.222": {v4: "208.67.222.222:53", v6: "[2620:119:35::35]:53"},
}

// localOnlyDNSSuffixes are non-public domain suffixes that must never be
// queried against an operator's local ISP/router resolver.
var localOnlyDNSSuffixes = [...]string{
	".localhost",
	".local",
	".internal",
	".home.arpa",
	".localdomain",
	".lan",
	".home",
	".corp",
	".intranet",
	".private",
}

// defaultDialDNS dials a UDP or TCP connection to an allowlisted DNS server.
func defaultDialDNS(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, address)
}

// ParseQtype maps a supported DNS query type name to its wire code.
func parseQtype(q string) (string, dnsmessage.Type, bool) {
	norm := strings.ToUpper(strings.TrimSpace(q))
	if norm == "" {
		norm = "A"
	}
	switch norm {
	case "A":
		return "A", dnsmessage.TypeA, true
	case "AAAA":
		return "AAAA", dnsmessage.TypeAAAA, true
	case "CNAME":
		return "CNAME", dnsmessage.TypeCNAME, true
	case "MX":
		return "MX", dnsmessage.TypeMX, true
	case "TXT":
		return "TXT", dnsmessage.TypeTXT, true
	case "NS":
		return "NS", dnsmessage.TypeNS, true
	case "SOA":
		return "SOA", dnsmessage.TypeSOA, true
	case "CAA":
		return "CAA", dnsTypeCAA, true
	case "SRV":
		return "SRV", dnsmessage.TypeSRV, true
	case "PTR":
		return "PTR", dnsmessage.TypePTR, true
	default:
		return "", 0, false
	}
}

// rrTypeName names a DNS wire type for presentation.
func rrTypeName(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeSOA:
		return "SOA"
	case dnsTypeCAA:
		return "CAA"
	case dnsmessage.TypeSRV:
		return "SRV"
	case dnsmessage.TypePTR:
		return "PTR"
	default:
		return fmt.Sprintf("TYPE%d", uint16(t))
	}
}

// rcodeName formats a DNS response code in standard uppercase notation.
func rcodeName(rc dnsmessage.RCode) string {
	switch rc {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE_%d", uint16(rc))
	}
}

// QueryDNS executes one recursive DNS query for the lease's validated host
// against an allowlisted resolver.
func (l *guardLease) QueryDNS(ctx context.Context, req module.DNSQuery) (module.DNSReply, error) {
	if l.transport != module.TransportDNS {
		return module.DNSReply{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "lease is not a DNS lease")
	}
	if l.isClosed() {
		return module.DNSReply{}, errLeaseClosed
	}
	if l.dnsQueries != nil && !l.dnsQueries.take() {
		return module.DNSReply{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "DNS query cap %d reached", l.dnsQueries.max)
	}

	qtype, wireType, ok := parseQtype(req.Qtype)
	if !ok {
		if l.dnsQueries != nil {
			l.dnsQueries.refund()
		}
		return module.DNSReply{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS, "unsupported DNS qtype %q", req.Qtype)
	}

	proto := strings.ToLower(strings.TrimSpace(req.Protocol))
	if proto == "" {
		proto = "udp"
	}
	if proto != "udp" && proto != "tcp" {
		if l.dnsQueries != nil {
			l.dnsQueries.refund()
		}
		return module.DNSReply{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS, "DNS protocol %q must be udp or tcp", req.Protocol)
	}

	resolverLabel, nsCandidates, err := l.g.resolveDNSServers(req.Resolver)
	if err != nil {
		if l.dnsQueries != nil {
			l.dnsQueries.refund()
		}
		return module.DNSReply{}, err
	}

	// Re-check the target host against the guard's current policy right before sending.
	if err := l.g.recheckDNSHost(l.host); err != nil {
		if l.dnsQueries != nil {
			l.dnsQueries.refund()
		}
		return module.DNSReply{}, err
	}

	qname := l.host
	if ip, perr := netip.ParseAddr(l.host); perr == nil {
		ip = ip.Unmap()
		if qtype == "PTR" {
			rev, rerr := reversePTRName(ip)
			if rerr != nil {
				if l.dnsQueries != nil {
					l.dnsQueries.refund()
				}
				return module.DNSReply{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS, "%v", rerr)
			}
			qname = rev
		}
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return module.DNSReply{}, fmt.Errorf("safety: draw DNS query id: %w", err)
	}
	queryID := binary.BigEndian.Uint16(idBytes[:])
	wireQuery, err := packDNSQuery(queryID, qname, wireType)
	if err != nil {
		if l.dnsQueries != nil {
			l.dnsQueries.refund()
		}
		return module.DNSReply{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS, "invalid DNS qname %q: %v", qname, err)
	}

	var lastErr error
	for _, nsAddr := range nsCandidates {
		usedProto := proto
		rawResp, rtt, qerr := l.g.exchangeDNS(qctx, usedProto, nsAddr, queryID, wireQuery, timeout)
		if qerr != nil {
			lastErr = sanitizeDNSError(resolverLabel, qerr)
			continue
		}
		hdr, answers, perr := parseDNSResponse(rawResp, queryID)
		if perr != nil {
			lastErr = sanitizeDNSError(resolverLabel, perr)
			continue
		}
		// Automatic RFC 1035 TCP retry when UDP response has TC=1.
		if usedProto == "udp" && hdr.Truncated {
			tcpResp, tcpRTT, terr := l.g.exchangeDNS(qctx, "tcp", nsAddr, queryID, wireQuery, timeout)
			if terr == nil {
				if tcpHdr, tcpAns, tperr := parseDNSResponse(tcpResp, queryID); tperr == nil {
					hdr = tcpHdr
					answers = tcpAns
					rtt = tcpRTT
					usedProto = "tcp"
				}
			}
		}
		return module.DNSReply{
			Qname:         qname,
			Qtype:         qtype,
			Resolver:      resolverLabel, // Always "isp" for resolv.conf; never leaks resolver IP.
			Protocol:      usedProto,
			Rcode:         rcodeName(hdr.RCode),
			RcodeNum:      uint32(hdr.RCode),
			Authoritative: hdr.Authoritative,
			Truncated:     hdr.Truncated,
			RTT:           rtt,
			Answers:       answers,
		}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("safety: no DNS nameserver available")
	}
	return module.DNSReply{}, lastErr
}

// resolveDNSServers validates the requested resolver against the strict
// allowlist and returns the canonical label ("isp" or public IP) and the
// candidate host:port addresses to query.
func (g *Guard) resolveDNSServers(raw string) (label string, addrs []string, err error) {
	r := strings.ToLower(strings.TrimSpace(raw))
	if r == "" || r == "isp" {
		v6Only := g.isIPv6Only()
		path := g.resolvConf
		if path == "" {
			path = defaultResolvConf
		}
		parsed := parseResolvConfFile(path, v6Only)
		if len(parsed) == 0 {
			if v6Only {
				parsed = []string{"[2606:4700:4700::1111]:53"}
			} else {
				parsed = []string{"1.1.1.1:53"}
			}
		}
		return "isp", parsed, nil
	}
	pub, ok := allowedPublicResolvers[r]
	if !ok {
		return "", nil, module.Refuse(nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS, "DNS resolver %q is not on the allowlist", raw)
	}
	if g.isIPv6Only() {
		return r, []string{pub.v6, pub.v4}, nil
	}
	return r, []string{pub.v4, pub.v6}, nil
}

func (g *Guard) isIPv6Only() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.refuse4 && !g.refuse6
}

// parseResolvConfFile extracts usable nameserver host:port entries from a
// resolv.conf file. At most 3 nameservers are returned (matching POSIX MAXNS).
func parseResolvConfFile(path string, v6Only bool) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseResolvConfBytes(b, v6Only)
}

func parseResolvConfBytes(b []byte, v6Only bool) []string {
	var primary, secondary []string
	for line := range strings.SplitSeq(string(b), "\n") {
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "nameserver") {
			continue
		}
		ipStr := fields[1]
		addr, err := netip.ParseAddr(ipStr)
		if err != nil || !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
			continue
		}
		// Preserve zone if link-local IPv6 carries one, unmap IPv4-in-IPv6 otherwise.
		if addr.Zone() == "" {
			addr = addr.Unmap()
			ipStr = addr.String()
		}
		hostPort := net.JoinHostPort(ipStr, "53")
		if v6Only && addr.Is4() && !addr.IsLoopback() {
			secondary = append(secondary, hostPort)
		} else {
			primary = append(primary, hostPort)
		}
	}
	all := append(primary, secondary...)
	if len(all) > 3 {
		all = all[:3]
	}
	return all
}

// packDNSQuery builds a standard recursive DNS query packet.
func packDNSQuery(id uint16, qname string, qtype dnsmessage.Type) ([]byte, error) {
	fqdn := strings.TrimSuffix(qname, ".") + "."
	name, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               id,
		RecursionDesired: true,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{
		Name:  name,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// exchangeDNS sends wireQuery over udp or tcp to nsAddr and returns the raw
// DNS message bytes and the monotonic round-trip duration.
func (g *Guard) exchangeDNS(ctx context.Context, proto, nsAddr string, queryID uint16, wireQuery []byte, timeout time.Duration) ([]byte, time.Duration, error) {
	dial := g.dialDNS
	if dial == nil {
		dial = defaultDialDNS
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	start := time.Now()
	conn, err := dial(ctx, proto, nsAddr, timeout)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	if proto == "tcp" {
		frame := make([]byte, 2+len(wireQuery))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(wireQuery)))
		copy(frame[2:], wireQuery)
		n, err := conn.Write(frame)
		if n > 0 {
			g.addTraffic(int64(n))
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			return nil, 0, err
		}
		var lenBuf [2]byte
		rn, err := io.ReadFull(conn, lenBuf[:])
		if rn > 0 {
			g.addTraffic(int64(rn))
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			return nil, 0, err
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen == 0 || msgLen > maxDNSTCPBytes {
			return nil, 0, errors.New("safety: invalid TCP DNS response length")
		}
		resp := make([]byte, msgLen)
		rn, err = io.ReadFull(conn, resp)
		elapsed := time.Since(start)
		if rn > 0 {
			g.addTraffic(int64(rn))
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			return nil, 0, err
		}
		return resp, elapsed, nil
	}

	// UDP exchange: ignore mismatched query IDs until deadline.
	n, err := conn.Write(wireQuery)
	if n > 0 {
		g.addTraffic(int64(n))
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		return nil, 0, err
	}
	buf := make([]byte, maxDNSUDPBytes)
	for {
		rn, err := conn.Read(buf)
		elapsed := time.Since(start)
		if rn > 0 {
			g.addTraffic(int64(rn))
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			return nil, 0, err
		}
		if rn < 12 {
			continue
		}
		gotID := binary.BigEndian.Uint16(buf[:2])
		isResp := buf[2]&0x80 != 0
		if gotID != queryID || !isResp {
			continue
		}
		out := make([]byte, rn)
		copy(out, buf[:rn])
		return out, elapsed, nil
	}
}

// parseDNSResponse unpacks a DNS response packet, verifies queryID and
// formats up to maxDNSAnswers answer records.
func parseDNSResponse(pkt []byte, queryID uint16) (dnsmessage.Header, []module.DNSAnswer, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(pkt)
	if err != nil {
		return dnsmessage.Header{}, nil, fmt.Errorf("safety: malformed DNS header: %w", err)
	}
	if !hdr.Response || hdr.ID != queryID {
		return dnsmessage.Header{}, nil, errors.New("safety: mismatched DNS response header")
	}
	if err := p.SkipAllQuestions(); err != nil {
		return dnsmessage.Header{}, nil, fmt.Errorf("safety: malformed DNS questions: %w", err)
	}
	if hdr.Truncated {
		return hdr, nil, nil
	}

	var answers []module.DNSAnswer
	for len(answers) < maxDNSAnswers {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			break
		}
		data, ok := readResourceData(&p, rh.Type)
		if !ok {
			continue
		}
		answers = append(answers, module.DNSAnswer{
			Name: trimDNSDot(rh.Name.String()),
			Type: rrTypeName(rh.Type),
			TTL:  rh.TTL,
			Data: data,
		})
	}
	return hdr, answers, nil
}

// readResourceData reads one resource body from p and formats its RDATA in
// standard DNS presentation syntax.
func readResourceData(p *dnsmessage.Parser, t dnsmessage.Type) (string, bool) {
	switch t {
	case dnsmessage.TypeA:
		r, err := p.AResource()
		if err != nil {
			return "", false
		}
		return netip.AddrFrom4(r.A).String(), true
	case dnsmessage.TypeAAAA:
		r, err := p.AAAAResource()
		if err != nil {
			return "", false
		}
		return netip.AddrFrom16(r.AAAA).String(), true
	case dnsmessage.TypeCNAME:
		r, err := p.CNAMEResource()
		if err != nil {
			return "", false
		}
		return trimDNSDot(r.CNAME.String()), true
	case dnsmessage.TypeNS:
		r, err := p.NSResource()
		if err != nil {
			return "", false
		}
		return trimDNSDot(r.NS.String()), true
	case dnsmessage.TypePTR:
		r, err := p.PTRResource()
		if err != nil {
			return "", false
		}
		return trimDNSDot(r.PTR.String()), true
	case dnsmessage.TypeMX:
		r, err := p.MXResource()
		if err != nil {
			return "", false
		}
		return fmt.Sprintf("%d %s", r.Pref, trimDNSDot(r.MX.String())), true
	case dnsmessage.TypeTXT:
		r, err := p.TXTResource()
		if err != nil {
			return "", false
		}
		return strings.Join(r.TXT, ""), true
	case dnsmessage.TypeSOA:
		r, err := p.SOAResource()
		if err != nil {
			return "", false
		}
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			trimDNSDot(r.NS.String()),
			trimDNSDot(r.MBox.String()),
			r.Serial, r.Refresh, r.Retry, r.Expire, r.MinTTL), true
	case dnsmessage.TypeSRV:
		r, err := p.SRVResource()
		if err != nil {
			return "", false
		}
		return fmt.Sprintf("%d %d %d %s",
			r.Priority, r.Weight, r.Port, trimDNSDot(r.Target.String())), true
	case dnsTypeCAA:
		r, err := p.UnknownResource()
		if err != nil {
			return "", false
		}
		return formatCAAResource(r.Data)
	default:
		_ = p.SkipAnswer()
		return "", false
	}
}

// formatCAAResource formats RFC 8659 CAA RDATA as `<flags> <tag> "<value>"`.
func formatCAAResource(b []byte) (string, bool) {
	if len(b) < 2 {
		return "", false
	}
	flags := b[0]
	tagLen := int(b[1])
	if tagLen == 0 || 2+tagLen > len(b) {
		return "", false
	}
	tag := b[2 : 2+tagLen]
	for _, c := range tag {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
			return "", false
		}
	}
	val := string(b[2+tagLen:])
	return fmt.Sprintf("%d %s %s", flags, strings.ToLower(string(tag)), strconv.Quote(val)), true
}

func trimDNSDot(s string) string {
	return strings.TrimSuffix(s, ".")
}

// reversePTRName returns the in-addr.arpa or ip6.arpa reverse name of ip.
func reversePTRName(ip netip.Addr) (string, error) {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return "", errors.New("invalid IP address for PTR lookup")
	}
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0]), nil
	}
	b := ip.As16()
	const hexDigits = "0123456789abcdef"
	var sb strings.Builder
	sb.Grow(72)
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hexDigits[b[i]&0x0f])
		sb.WriteByte('.')
		sb.WriteByte(hexDigits[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa")
	return sb.String(), nil
}

// parseReverseArpa parses an in-addr.arpa or ip6.arpa name back into an IP
// address, so reverse queries cannot probe denied or operator-local ranges.
func parseReverseArpa(host string) (netip.Addr, bool) {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if stem, ok := strings.CutSuffix(h, ".in-addr.arpa"); ok {
		parts := strings.Split(stem, ".")
		if len(parts) != 4 {
			return netip.Addr{}, false
		}
		var b [4]byte
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(parts[3-i], 10, 8)
			if err != nil {
				return netip.Addr{}, false
			}
			b[i] = byte(v)
		}
		return netip.AddrFrom4(b), true
	}
	if stem, ok := strings.CutSuffix(h, ".ip6.arpa"); ok {
		parts := strings.Split(stem, ".")
		if len(parts) != 32 {
			return netip.Addr{}, false
		}
		var b [16]byte
		for i := 0; i < 16; i++ {
			lo, err1 := strconv.ParseUint(parts[31-2*i], 16, 4)
			hi, err2 := strconv.ParseUint(parts[31-(2*i+1)], 16, 4)
			if err1 != nil || err2 != nil {
				return netip.Addr{}, false
			}
			b[i] = byte(hi<<4 | lo)
		}
		return netip.AddrFrom16(b).Unmap(), true
	}
	return netip.Addr{}, false
}

// dnsHostAllowed checks a canonical DNS target host against local-only domain
// suffixes, reverse-DNS deny/ownNet checks, IP-literal deny/ownNet checks,
// and the do-not-probe list.
func (g *Guard) dnsHostAllowed(host string, p *netPolicy) (string, bool) {
	if host == PauseHost {
		return "pause host", false
	}
	if host == "localhost" {
		return "localhost", false
	}
	for _, suf := range localOnlyDNSSuffixes {
		if host == suf[1:] || strings.HasSuffix(host, suf) {
			return "local domain " + suf, false
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if why, ok := g.dnsTargetIPAllowed(ip.Unmap(), p); !ok {
			return why, false
		}
	} else if strings.HasSuffix(host, ".in-addr.arpa") || strings.HasSuffix(host, ".ip6.arpa") || host == "in-addr.arpa" || host == "ip6.arpa" {
		revIP, ok := parseReverseArpa(host)
		if !ok {
			return "malformed reverse DNS target", false
		}
		if why, ok := g.dnsTargetIPAllowed(revIP, p); !ok {
			return why, false
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

// dnsTargetIPAllowed checks an IP literal or reverse-DNS IP against Denied,
// ownNet, addDeny, dnp prefixes, and pause host addresses (independent of the
// transport family used to reach the recursive DNS resolver).
func (g *Guard) dnsTargetIPAllowed(a netip.Addr, p *netPolicy) (string, bool) {
	a = a.Unmap()
	if !(testHooksEnabled && prefixesContain(g.testPrefixes, a)) {
		if denied, why := Denied(a); denied {
			return why, false
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

func (g *Guard) recheckDNSHost(host string) error {
	g.mu.Lock()
	p := g.policyLocked()
	g.mu.Unlock()
	if why, ok := g.dnsHostAllowed(host, &p); !ok {
		return module.Refuse(nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL, "target denied locally: %s", why)
	}
	return nil
}

// maskedOpError wraps a net.OpError without exposing the underlying ISP
// resolver IP address in Error() while preserving Timeout() and Unwrap().
type maskedDNSError struct {
	cause   error
	timeout bool
}

func (e *maskedDNSError) Error() string { return "safety: ISP DNS query failed" }
func (e *maskedDNSError) Unwrap() error { return e.cause }
func (e *maskedDNSError) Timeout() bool { return e.timeout }

func sanitizeDNSError(resolverLabel string, err error) error {
	if err == nil || resolverLabel != "isp" {
		return err
	}
	var ne net.Error
	isTimeout := errors.As(err, &ne) && ne.Timeout()
	// Strip net.OpError.Addr so no log or caller ever sees the /etc/resolv.conf IP.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		stripped := &net.OpError{
			Op:  opErr.Op,
			Net: opErr.Net,
			Err: opErr.Err,
		}
		return &maskedDNSError{cause: stripped, timeout: isTimeout}
	}
	return &maskedDNSError{cause: err, timeout: isTimeout}
}
