package agent

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/protocol"
)

// selfTest runs every registered module's self-test and returns the
// capability strings to advertise and one result per module and family.
// Only modules of the measure class the operator consented to advertise
// anything, and a module may only claim its own kind and version.
func (a *Agent) selfTest(ctx context.Context) ([]string, []*nodev1.SelfTestResult) {
	env := module.Env{
		ClientKind:  a.cfg.ClientKind,
		NetworkMode: a.cfg.NetworkMode,
		GOOS:        runtime.GOOS,
		Probe:       a.cfg.Gate.HostProbe(),
	}
	var (
		caps  []string
		tests []*nodev1.SelfTestResult
		seen  = make(map[string]bool)
	)
	for _, m := range a.cfg.Registry.Modules() {
		if m.Class() != nodev1.JobClass_JOB_CLASS_MEASURE || !a.consent[m.Class()] {
			continue
		}
		className := protocol.ClassName(m.Class())
		byFamily := make(map[nodev1.AddressFamily][]string)
		for _, c := range a.moduleSelfTest(ctx, m, env) {
			if c.Class != className || c.Kind != m.Kind() || c.Version != m.Version() {
				a.log.Warn("ignoring a capability a module may not claim", "kind", m.Kind(), "capability", c.String())
				continue
			}
			s := c.String()
			if parsed, err := protocol.ParseCapability(s); err != nil || parsed.String() != s {
				a.log.Warn("ignoring a malformed capability", "kind", m.Kind(), "capability", s)
				continue
			}
			if !seen[s] {
				seen[s] = true
				caps = append(caps, s)
			}
			f := capabilityFamily(c)
			byFamily[f] = append(byFamily[f], s)
		}
		if len(byFamily) == 0 {
			tests = append(tests, &nodev1.SelfTestResult{Kind: m.Kind(), Detail: "no working capability on this host"})
			continue
		}
		for _, f := range []nodev1.AddressFamily{
			nodev1.AddressFamily_ADDRESS_FAMILY_UNSPECIFIED,
			nodev1.AddressFamily_ADDRESS_FAMILY_IPV4,
			nodev1.AddressFamily_ADDRESS_FAMILY_IPV6,
		} {
			if list := byFamily[f]; len(list) > 0 {
				tests = append(tests, &nodev1.SelfTestResult{Kind: m.Kind(), Family: f, Ok: true, Detail: strings.Join(list, " ")})
			}
		}
	}
	return caps, tests
}

// moduleSelfTest runs one self-test under a timeout. A panicking self-test
// reports nothing rather than stopping the agent.
func (a *Agent) moduleSelfTest(ctx context.Context, m module.Module, env module.Env) (caps []protocol.Capability) {
	ctx, cancel := context.WithTimeout(ctx, selfTestTimeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			a.log.Error("module self-test panicked", "kind", m.Kind(), "panic", fmt.Sprint(r))
			caps = nil
		}
	}()
	return m.SelfTest(ctx, env)
}

// capabilityFamily reads the address family qualifier of a capability.
func capabilityFamily(c protocol.Capability) nodev1.AddressFamily {
	switch {
	case c.Has("ipv4"):
		return nodev1.AddressFamily_ADDRESS_FAMILY_IPV4
	case c.Has("ipv6"):
		return nodev1.AddressFamily_ADDRESS_FAMILY_IPV6
	default:
		return nodev1.AddressFamily_ADDRESS_FAMILY_UNSPECIFIED
	}
}
