package safety

import (
	"net/netip"
	"slices"
)

// ipv4OnlyARPA is the name a node resolves to discover its network's NAT64
// prefix (RFC 7050): a DNS64 resolver answers its AAAA query with
// 192.0.0.170 and 192.0.0.171 embedded under the prefix.
const ipv4OnlyARPA = "ipv4only.arpa"

// isNAT64WellKnown reports whether a is one of the two well-known IPv4
// addresses of ipv4only.arpa.
func isNAT64WellKnown(a netip.Addr) bool {
	return a == netip.AddrFrom4([4]byte{192, 0, 0, 170}) || a == netip.AddrFrom4([4]byte{192, 0, 0, 171})
}

// embeddedIPv4 returns the IPv4 address RFC 6052 embeds in a, an address
// under a NAT64 prefix of the given length. The octet at bits 64 to 71
// carries no address bits. Lengths other than 32, 40, 48, 56, 64 and 96 are
// not NAT64 prefixes.
func embeddedIPv4(a netip.Addr, bits int) (netip.Addr, bool) {
	b := a.As16()
	var v [4]byte
	switch bits {
	case 32:
		v = [4]byte{b[4], b[5], b[6], b[7]}
	case 40:
		v = [4]byte{b[5], b[6], b[7], b[9]}
	case 48:
		v = [4]byte{b[6], b[7], b[9], b[10]}
	case 56:
		v = [4]byte{b[7], b[9], b[10], b[11]}
	case 64:
		v = [4]byte{b[9], b[10], b[11], b[12]}
	case 96:
		v = [4]byte{b[12], b[13], b[14], b[15]}
	default:
		return netip.Addr{}, false
	}
	return netip.AddrFrom4(v), true
}

// nat64Prefixes derives the NAT64 prefixes from the AAAA answers for
// ipv4only.arpa (RFC 7050 section 3): each answer carries a well-known
// address at the position its prefix length sets, tried longest first.
func nat64Prefixes(answers []netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range answers {
		if !a.Is6() || a.Is4In6() || a.Zone() != "" {
			continue
		}
		for _, bits := range [...]int{96, 64, 56, 48, 40, 32} {
			v4, ok := embeddedIPv4(a, bits)
			if !ok || !isNAT64WellKnown(v4) {
				continue
			}
			if p, err := a.Prefix(bits); err == nil && !slices.Contains(out, p) {
				out = append(out, p)
			}
			break
		}
	}
	return out
}

// nat64Destination returns the IPv4 address that a, an IPv6 address under
// one of the network's NAT64 prefixes, reaches through that NAT64.
// Compiled deny ranges judge only the well-known prefix 64:ff9b::/96; this
// covers the network-specific prefixes the node discovered.
func nat64Destination(a netip.Addr, prefixes []netip.Prefix) (netip.Addr, bool) {
	if !a.Is6() || a.Is4In6() {
		return netip.Addr{}, false
	}
	a = a.WithZone("")
	for _, p := range prefixes {
		if p.Contains(a) {
			return embeddedIPv4(a, p.Bits())
		}
	}
	return netip.Addr{}, false
}
