package protocol

import (
	"fmt"
	"strconv"
	"strings"
)

// Capability is one capability string, such as
// "measure.icmp_ping.v1:ipv4:ts.user": class, kind, version and qualifiers.
type Capability struct {
	Class      string
	Kind       string
	Version    uint32
	Qualifiers []string
}

// Base is the capability without qualifiers, such as "measure.icmp_ping.v1".
// The dispatcher indexes nodes by base and filters on qualifiers.
func (c Capability) Base() string {
	return c.Class + "." + c.Kind + ".v" + strconv.FormatUint(uint64(c.Version), 10)
}

// String renders the full capability string.
func (c Capability) String() string {
	if len(c.Qualifiers) == 0 {
		return c.Base()
	}
	return c.Base() + ":" + strings.Join(c.Qualifiers, ":")
}

// Has reports whether the capability carries a qualifier.
func (c Capability) Has(qualifier string) bool {
	for _, q := range c.Qualifiers {
		if q == qualifier {
			return true
		}
	}
	return false
}

// ParseCapability parses a capability string.
func ParseCapability(s string) (Capability, error) {
	parts := strings.Split(s, ":")
	head := strings.Split(parts[0], ".")
	if len(head) != 3 || head[0] == "" || head[1] == "" || !strings.HasPrefix(head[2], "v") {
		return Capability{}, fmt.Errorf("protocol: invalid capability %q", s)
	}
	v, err := strconv.ParseUint(head[2][1:], 10, 32)
	if err != nil || v == 0 {
		return Capability{}, fmt.Errorf("protocol: invalid capability version in %q", s)
	}
	c := Capability{Class: head[0], Kind: head[1], Version: uint32(v)}
	for _, q := range parts[1:] {
		if q == "" {
			return Capability{}, fmt.Errorf("protocol: empty qualifier in %q", s)
		}
		c.Qualifiers = append(c.Qualifiers, q)
	}
	return c, nil
}
