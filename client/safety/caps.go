package safety

import (
	"net"
	"net/netip"
	"slices"
	"time"
)

// defaultDailyTrafficBytes is the agent's compiled daily traffic budget,
// 200 MB (architecture section 12, Appendix C).
const defaultDailyTrafficBytes = 200 << 20

// Caps are the limits compiled into a client. No message from the server can
// raise any of them; ConfigUpdate limits may only lower the four fields that
// nodev1.Limits carries, and only a target grant lifts the per-domain window
// and the port list for one address-proven target.
type Caps struct {
	// JobsPerMinute is the most jobs admitted in any trailing 60 s.
	JobsPerMinute int
	// MaxConcurrency is the most leases open at once.
	MaxConcurrency int
	// DomainSpacing is the least time between two admitted jobs to one
	// registrable domain, and between two to one destination /24 or /48.
	DomainSpacing time.Duration
	// DomainJobsPerWindow is the most jobs to one registrable domain within
	// DomainWindow without a grant; 0 means no per-domain window cap.
	DomainJobsPerWindow int
	// DomainWindow is the window the per-domain cap counts over.
	DomainWindow time.Duration
	// ICMPPacketsPerSecond is the shared ICMP send rate across all leases.
	ICMPPacketsPerSecond int
	// MaxPingPackets is the most echo requests one ping lease may send.
	MaxPingPackets int
	// MaxTraceroutePackets is the most packets one traceroute lease may send.
	MaxTraceroutePackets int
	// DailyTrafficBytes is the per-UTC-day byte budget; 0 means no cap.
	DailyTrafficBytes int64
}

// AgentCaps are the compiled caps for a native node (the Go agent).
//
// Three of them bound how much work one node takes on, and were raised on
// 2026-11-15 by the owner's decision (30 jobs a minute, 4 at a time and 10
// ICMP packets a second were too low a ceiling for customers with thousands
// of checks): 300 jobs a minute, 16 at a time, 50 ICMP packets a second. The
// three go together: 300 jobs a minute of a second or two each need about ten
// leases open at once, and a ping job sends up to 16 packets.
//
// The others are unchanged on purpose. The spacing and the per-domain window
// protect the sites being measured and bound what a compromised server could
// aim at one of them. The daily traffic budget is what an operator was told
// their connection would carry; it now binds before the job rate does for
// HTTP work (about 35,000 HTTPS checks a day), and raising it is a separate
// decision.
func AgentCaps() Caps {
	return Caps{
		JobsPerMinute:        300,
		MaxConcurrency:       16,
		DomainSpacing:        55 * time.Second,
		DomainJobsPerWindow:  6,
		DomainWindow:         59 * time.Minute,
		ICMPPacketsPerSecond: 50,
		MaxPingPackets:       16,
		MaxTraceroutePackets: 90,
		DailyTrafficBytes:    defaultDailyTrafficBytes,
	}
}

// AnchorCaps are the compiled caps for anchor mode on a Hopbits-run server.
func AnchorCaps() Caps {
	return Caps{
		JobsPerMinute:        600,
		MaxConcurrency:       16,
		DomainSpacing:        1 * time.Second,
		DomainJobsPerWindow:  0,
		DomainWindow:         0,
		ICMPPacketsPerSecond: 50,
		MaxPingPackets:       16,
		MaxTraceroutePackets: 90,
		DailyTrafficBytes:    0,
	}
}

// anchorDomains are the compiled anchor-domain suffixes. A host equal to one
// of these, or a subdomain of it on a label boundary, is resolved locally and
// is exempt from the per-domain window cap.
var anchorDomains = [...]string{"anchor.hopbits.io"}

// AnchorDomains returns the compiled anchor-domain suffixes.
func AnchorDomains() []string { return slices.Clone(anchorDomains[:]) }

// PauseHost is the off-core pause-file host. It is compiled as never a job
// target, so no job may ever be aimed at it, by name or at an address its
// name resolves to.
const PauseHost = "pause.anchor.hopbits.io"

// ProbeUserAgent is the User-Agent every HTTP probe carries (RFC 9511 style).
const ProbeUserAgent = "HopbitsProbe/1 (+https://hopbits.io/probe)"

// ProbeHeader is the attribution header carrying the measurement id.
const ProbeHeader = "X-Hopbits-Probe"

// ProbeDescriptionURI is the RFC 9511 probe-description URI placed in ICMP
// echo payloads.
const ProbeDescriptionURI = "https://hopbits.io/probe"

// allowedPorts are the TCP ports a module may use without a target grant.
var allowedPorts = [...]uint16{80, 443, 8080, 8443}

// neverPorts are TCP ports no job may ever reach, even under a target grant:
// remote-access, mail, database and cache ports.
var neverPorts = [...]uint16{
	21, 22, 23, 25, 110, 135, 137, 138, 139, 143,
	445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900,
	6379, 11211, 27017,
}

// AllowedPorts returns the TCP ports a module may use without a target
// grant. The slice is a copy; changing it changes nothing in the guard.
func AllowedPorts() []uint16 { return slices.Clone(allowedPorts[:]) }

// NeverPorts returns the TCP ports no job may ever reach, even under a
// target grant. The slice is a copy; changing it changes nothing in the
// guard.
func NeverPorts() []uint16 { return slices.Clone(neverPorts[:]) }

// IsNeverPort reports whether port is on the compiled never-list.
func IsNeverPort(port uint16) bool { return slices.Contains(neverPorts[:], port) }

// InterfacePrefixes returns the host's interface network prefixes, for the
// node's own-network refusal. It reads net.Interfaces and masks each address
// to its interface prefix.
func InterfacePrefixes() ([]netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
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
			p, err := netip.ParsePrefix(ipnet.String())
			if err != nil {
				continue
			}
			out = append(out, p.Masked())
		}
	}
	return out, nil
}
