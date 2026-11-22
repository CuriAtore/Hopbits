package safety

import (
	"net"
	"net/netip"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
)

// hostProbe answers self-test questions that need the sockets the safety
// layer owns. It opens and closes sockets but sends nothing.
type hostProbe struct {
	g *Guard
}

// ICMP reports whether ICMP echo works for a family and how it is timed. It
// opens and closes a socket without sending.
func (h *hostProbe) ICMP(family nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	isV6 := family == nodev1.AddressFamily_ADDRESS_FAMILY_IPV6
	ok, detail := icmpAvailable(isV6)
	if !ok {
		return false, nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE, detail
	}
	return true, nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, detail
}

// Trace reports whether hop-limited path tracing works for a family and how
// it is timed. It opens and closes a socket without sending.
func (h *hostProbe) Trace(family nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	isV6 := family == nodev1.AddressFamily_ADDRESS_FAMILY_IPV6
	ok, detail := traceAvailable(isV6)
	if !ok {
		return false, nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE, detail
	}
	return true, nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, detail
}

// HasIPv6 reports whether the host has a global unicast IPv6 interface
// address.
func (h *hostProbe) HasIPv6() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.Is6() && !addr.Is4() && addr.IsGlobalUnicast() {
				return true
			}
		}
	}
	return false
}
