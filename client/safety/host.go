package safety

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Bounds on the server-supplied strings a job puts on the wire. The target
// host goes into the HTTP Host header and TLS SNI, and the measurement id
// into the X-Hopbits-Probe header, so both stay short whatever the server
// signs.
const (
	// MaxHostBytes is the longest target host name, without a trailing dot.
	MaxHostBytes = 253
	// maxLabelBytes is the longest label of a host name.
	maxLabelBytes = 63
	// MaxMeasurementIDBytes is the longest measurement id.
	MaxMeasurementIDBytes = 64
)

// CanonicalHost returns a job's target host in the one form the guard
// judges and the network sees: an IP literal in its standard text form, or
// a name in lower case without its trailing dot. It refuses every other
// form, so no two spellings of one name escape the per-domain caps: a name
// must be letters, digits, hyphens and underscores in labels of 1 to 63
// bytes, and at most MaxHostBytes long.
func CanonicalHost(host string) (string, error) {
	if host == "" {
		return "", errors.New("safety: target has no host")
	}
	if len(host) > MaxHostBytes+1 {
		return "", fmt.Errorf("safety: target host is %d bytes, at most %d allowed", len(host), MaxHostBytes)
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.String(), nil
	}
	name := strings.TrimSuffix(host, ".")
	if name == "" || len(name) > MaxHostBytes {
		return "", fmt.Errorf("safety: target host is %d bytes, at most %d allowed", len(name), MaxHostBytes)
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > maxLabelBytes {
			return "", errors.New("safety: target host has an empty or overlong label")
		}
		for i := 0; i < len(label); i++ {
			if !hostByte(label[i]) {
				return "", errors.New("safety: target host may hold only letters, digits, hyphens, underscores and dots")
			}
		}
	}
	return strings.ToLower(name), nil
}

func hostByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

// RegistrableDomain returns the domain the per-domain caps count a host
// under: its registrable domain (eTLD+1) from the compiled public-suffix
// list, the name itself when it has none, or the address for an IP
// literal. Case and a trailing dot are ignored. The dispatcher uses the same
// rule to mirror the caps, so it never assigns a job the guard refuses.
func RegistrableDomain(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().WithZone("").String()
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil && d != "" {
		return d
	}
	return h
}

// ValidMeasurementID reports whether id may go on the wire in the
// X-Hopbits-Probe header: 1 to MaxMeasurementIDBytes letters, digits,
// hyphens and underscores.
func ValidMeasurementID(id string) bool {
	if id == "" || len(id) > MaxMeasurementIDBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !hostByte(id[i]) {
			return false
		}
	}
	return true
}
