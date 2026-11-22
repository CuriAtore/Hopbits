package all

import (
	"context"
	"runtime"
	"slices"
	"testing"
	"time"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/protocol"
	"github.com/hopbits/client/safety"
)

// The tests below hold for every module in Default, so adding a module
// needs no change here: each one must register, be of the measure class,
// declare a known transport and stay inside the compiled port policy.

func TestDefaultBuildsARegistry(t *testing.T) {
	mods := Default()
	reg, err := module.NewRegistry(mods...)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) == 0 || len(reg.Modules()) != len(mods) {
		t.Fatalf("%d modules registered from %d", len(reg.Modules()), len(mods))
	}
	for i, m := range reg.Modules() {
		if m.Kind() != mods[i].Kind() {
			t.Fatalf("module %d is %s, want %s: the registry changed the order", i, m.Kind(), mods[i].Kind())
		}
		if got, ok := reg.Lookup(m.Kind(), m.Version()); !ok || got != m {
			t.Fatalf("%s v%d does not look up", m.Kind(), m.Version())
		}
		if _, ok := reg.Lookup(m.Kind(), m.Version()+100); ok {
			t.Fatalf("%s: an unknown version was found", m.Kind())
		}
		if m.Class() != nodev1.JobClass_JOB_CLASS_MEASURE {
			t.Errorf("%s class %v", m.Kind(), m.Class())
		}
		switch n := m.Needs(); n.Transport {
		case module.TransportTCP:
			if len(n.Ports) == 0 {
				t.Errorf("%s uses TCP but declares no port", m.Kind())
			}
		case module.TransportICMP, module.TransportDNS:
			if len(n.Ports) != 0 {
				t.Errorf("%s uses non-TCP transport %d but declares ports %v", m.Kind(), n.Transport, n.Ports)
			}
		default:
			t.Errorf("%s declares transport %d, which the safety layer does not know", m.Kind(), n.Transport)
		}
	}
}

func TestNeedsStayInsideCompiledPortPolicy(t *testing.T) {
	// Every port a module uses without a grant is on the compiled allowlist
	// and never on the never-list.
	allowed := safety.AllowedPorts()
	for _, m := range Default() {
		for _, p := range m.Needs().Ports {
			if !slices.Contains(allowed, p) || safety.IsNeverPort(p) {
				t.Errorf("%s declares port %d outside the compiled policy", m.Kind(), p)
			}
		}
	}
	// Section 12 names the ports of the first kinds; these hold while the
	// kinds are compiled in.
	section12 := map[string][]uint16{
		"http":        {80, 443, 8080, 8443},
		"tcp_connect": {443, 80},
		"icmp_ping":   nil,
	}
	for _, m := range Default() {
		if want, ok := section12[m.Kind()]; ok && !slices.Equal(m.Needs().Ports, want) {
			t.Errorf("%s declares ports %v, section 12 says %v", m.Kind(), m.Needs().Ports, want)
		}
	}
}

func TestDefaultReturnsFreshModules(t *testing.T) {
	a, b := Default(), Default()
	for i := range a {
		if a[i] == b[i] {
			t.Fatalf("%s instance shared between calls", a[i].Kind())
		}
	}
}

// probe reports every capability as working.
type probe struct{}

func (probe) ICMP(nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	return true, nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, "ok"
}
func (probe) Trace(nodev1.AddressFamily) (bool, nodev1.TimestampSource, string) {
	return true, nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO, "ok"
}
func (probe) HasIPv6() bool { return true }

func TestCapabilitiesMatchModules(t *testing.T) {
	env := module.Env{
		ClientKind:  nodev1.ClientKind_CLIENT_KIND_AGENT,
		NetworkMode: nodev1.NetworkMode_NETWORK_MODE_HOST,
		GOOS:        runtime.GOOS,
		Probe:       probe{},
	}
	for _, m := range Default() {
		caps := m.SelfTest(context.Background(), env)
		if len(caps) == 0 {
			t.Errorf("%s advertises nothing on a capable host", m.Kind())
		}
		for _, c := range caps {
			parsed, err := protocol.ParseCapability(c.String())
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Class != protocol.ClassName(m.Class()) || parsed.Kind != m.Kind() || parsed.Version != m.Version() {
				t.Errorf("%s advertises %s", m.Kind(), c)
			}
			if !parsed.Has("ipv4") && !parsed.Has("ipv6") {
				t.Errorf("%s has no address family", c)
			}
		}
	}
}

func TestModulesRefuseBadJobs(t *testing.T) {
	now := time.Now()
	for _, m := range Default() {
		port := uint32(443)
		if m.Needs().Transport == module.TransportICMP || m.Needs().Transport == module.TransportDNS {
			port = 0
		}
		target := &nodev1.Target{Host: "example.com", Port: port, PinnedAddress: "192.0.2.1"}
		garbage := &module.Job{Kind: m.Kind(), KindVersion: 1, Target: target, Params: []byte{0xff, 0x01}, Issued: now, Deadline: now.Add(time.Minute)}
		if module.CodeOf(m.Check(garbage)) != nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS {
			t.Errorf("%s accepted undecodable params", m.Kind())
		}
		noDeadline := &module.Job{Kind: m.Kind(), KindVersion: 1, Target: target, Issued: now}
		if m.Check(noDeadline) == nil {
			t.Errorf("%s accepted a job without a deadline", m.Kind())
		}
		ok := &module.Job{Kind: m.Kind(), KindVersion: 1, Target: target, Issued: now, Deadline: now.Add(time.Minute)}
		if err := m.Check(ok); err != nil {
			t.Errorf("%s refused a default job: %v", m.Kind(), err)
		}
	}
}
