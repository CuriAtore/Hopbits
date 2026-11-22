// Package safety is the node's safety layer: the limits compiled into every
// client that no message from the server can raise. It decides where a job
// may connect and how often, and it owns every socket a module uses.
package safety

import (
	"net/netip"
)

type deny struct {
	prefix netip.Prefix
	reason string
}

func mustPrefixes(entries ...[2]string) []deny {
	out := make([]deny, 0, len(entries))
	for _, e := range entries {
		out = append(out, deny{netip.MustParsePrefix(e[0]), e[1]})
	}
	return out
}

// Compiled deny ranges: OWASP's SSRF ranges and cloud-metadata endpoints
// plus the IANA special-purpose blocks OWASP omits (architecture section 12).
var (
	denyV4 = mustPrefixes(
		[2]string{"0.0.0.0/8", "this network"},
		[2]string{"10.0.0.0/8", "private"},
		[2]string{"100.64.0.0/10", "shared address space (CGNAT)"},
		[2]string{"127.0.0.0/8", "loopback"},
		[2]string{"169.254.0.0/16", "link-local and cloud metadata"},
		[2]string{"172.16.0.0/12", "private"},
		[2]string{"192.0.0.0/24", "IETF protocol assignments"},
		[2]string{"192.0.2.0/24", "documentation"},
		[2]string{"192.88.99.0/24", "6to4 relay anycast"},
		[2]string{"192.168.0.0/16", "private"},
		[2]string{"198.18.0.0/15", "benchmarking"},
		[2]string{"198.51.100.0/24", "documentation"},
		[2]string{"203.0.113.0/24", "documentation"},
		[2]string{"224.0.0.0/4", "multicast"},
		[2]string{"240.0.0.0/4", "reserved and broadcast"},
	)
	denyV6 = mustPrefixes(
		[2]string{"64:ff9b:1::/48", "local-use NAT64"},
		[2]string{"100::/64", "discard-only"},
		[2]string{"2001::/23", "IETF protocol assignments"},
		[2]string{"2001:db8::/32", "documentation"},
		[2]string{"2002::/16", "6to4"},
		[2]string{"3fff::/20", "documentation"},
		[2]string{"5f00::/16", "SRv6 segment identifiers"},
	)
	globalUnicastV6 = netip.MustParsePrefix("2000::/3")
	nat64WellKnown  = netip.MustParsePrefix("64:ff9b::/96")
)

// Denied reports whether a job may never connect to addr, whatever the
// server says, and why. IPv4-mapped and NAT64 addresses are judged by the
// IPv4 address they carry; IPv6 must be global unicast.
func Denied(addr netip.Addr) (bool, string) {
	if !addr.IsValid() {
		return true, "invalid address"
	}
	if addr.Zone() != "" {
		return true, "zoned address"
	}
	addr = addr.Unmap()
	if addr.Is4() {
		for _, d := range denyV4 {
			if d.prefix.Contains(addr) {
				return true, d.reason
			}
		}
		return false, ""
	}
	if nat64WellKnown.Contains(addr) {
		b := addr.As16()
		embedded := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		if denied, why := Denied(embedded); denied {
			return true, "NAT64 of " + why
		}
		return false, ""
	}
	if !globalUnicastV6.Contains(addr) {
		return true, "not global unicast IPv6"
	}
	for _, d := range denyV6 {
		if d.prefix.Contains(addr) {
			return true, d.reason
		}
	}
	return false, ""
}
