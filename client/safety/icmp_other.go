//go:build !linux && !darwin

package safety

import (
	"fmt"
	"net/netip"
	"runtime"
)

// dialICMP is not implemented outside Linux and Darwin; Windows ICMP comes
// later through the OS helper API.
func dialICMP(dst netip.Addr) (icmpConn, error) {
	return nil, fmt.Errorf("safety: ICMP is not implemented on %s", runtime.GOOS)
}

// icmpAvailable reports ICMP as unavailable on this OS.
func icmpAvailable(isV6 bool) (bool, string) {
	return false, fmt.Sprintf("ICMP not implemented on %s", runtime.GOOS)
}
