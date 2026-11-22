package agent

import (
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/protocol"
)

const (
	defaultBackoffMin = time.Second
	defaultBackoffMax = 120 * time.Second
)

// GateControl is the safety layer as the runtime drives it: it admits jobs
// and takes the session settings the gateway sends. The safety package's
// Guard implements it. Nothing passed to it can raise a compiled cap.
type GateControl interface {
	module.Gate
	// SetOwnNetwork replaces the operator's own network: the host's
	// interface prefixes and the public addresses the gateway observed.
	SetOwnNetwork(interfacePrefixes []netip.Prefix, observed []netip.Addr)
	// RefuseFamilies refuses IPv4 or IPv6 targets when the node's own network
	// in that family is unknown.
	RefuseFamilies(ipv4, ipv6 bool)
	// ApplyLimits lowers the compiled caps; it can never raise them.
	ApplyLimits(l *nodev1.Limits)
	// AddDenyPrefixes adds ranges to the compiled deny ranges.
	AddDenyPrefixes(p []netip.Prefix)
	// SetDoNotProbe replaces the do-not-probe entries.
	SetDoNotProbe(entries []string)
	// HostProbe answers module self-tests.
	HostProbe() module.HostProbe
}

// Config configures an Agent. Zero fields take the defaults New documents.
type Config struct {
	// GatewayURL is the node endpoint, protocol.DefaultGatewayURL by default.
	// It must be wss://, or ws:// to a loopback host for development, and
	// its path must be protocol.Path.
	GatewayURL string
	// DataDir holds the device key, the state file, results waiting for
	// acknowledgement and the job log.
	DataDir string
	// ClientKind is CLIENT_KIND_AGENT by default.
	ClientKind nodev1.ClientKind
	// ClientVersion is reported in Hello and in every Result.
	ClientVersion string
	// NetworkMode is how the node reaches the network.
	NetworkMode nodev1.NetworkMode
	// EnrollmentToken is an optional fleet enrolment token.
	EnrollmentToken string
	// NodeLabel is an optional display label for this node in the operator dashboard.
	NodeLabel string
	// Roots are the compiled root keys; index 0 is the working root.
	Roots protocol.Roots
	// Registry holds the modules compiled into the client.
	Registry *module.Registry
	// Gate is the safety layer every job passes before it runs.
	Gate GateControl
	// ConsentClasses are the job classes the operator consented to on this
	// device, [JOB_CLASS_MEASURE] by default. The server can never add one.
	ConsentClasses []nodev1.JobClass
	// InterfacePrefixes lists the host's interface prefixes, by default
	// from the system's interface addresses.
	InterfacePrefixes func() ([]netip.Prefix, error)
	// Logger receives the agent's logs, slog.Default() by default.
	Logger *slog.Logger
	// Now is the wall clock, time.Now by default.
	Now func() time.Time
	// TLSConfig is the base TLS configuration for wss://. TLS 1.3 is
	// always required.
	TLSConfig *tls.Config
	// BackoffMin is the first reconnect backoff, 1 s by default.
	BackoffMin time.Duration
	// BackoffMax caps the reconnect backoff, 120 s by default.
	BackoffMax time.Duration
	// PauseFetcher fetches the off-core signed pause file; nil defaults to
	// NewHTTPPauseFetcher(DefaultPauseURL, ...) unless PausePollInterval < 0.
	PauseFetcher PauseFetcher
	// PausePollInterval sets how often the pause file is polled (5 m by default;
	// negative disables periodic polling).
	PausePollInterval time.Duration
	// DisableAutoUpdate opts out of automatic signed self-updates (auto-update
	// is enabled by default). UPGRADE_REQUIRED is still checked against the
	// release manifest.
	DisableAutoUpdate bool
	// UpdateFetcher downloads the signed release manifest and release binaries;
	// nil defaults to NewHTTPUpdateFetcher(DefaultManifestURL, ...) unless
	// UpdatePollInterval < 0.
	UpdateFetcher UpdateFetcher
	// UpdatePollInterval sets how often release updates are polled (1 h by
	// default; negative disables periodic update polling).
	UpdatePollInterval time.Duration
	// BinaryInstaller stages verified binaries and re-executes the process; nil
	// defaults to NewVolumeBinaryInstaller(DataDir).
	BinaryInstaller BinaryInstaller

	// Test hooks for cross-platform release artifact selection.
	targetOS   string
	targetArch string
}

// AutoUpdateEnabled reports whether signed automatic self-updates are enabled.
func (c Config) AutoUpdateEnabled() bool {
	return !c.DisableAutoUpdate
}

// withDefaults returns a copy of c with the defaults applied and its slices
// copied, so the caller cannot change them later.
func (c Config) withDefaults() Config {
	if c.GatewayURL == "" {
		c.GatewayURL = protocol.DefaultGatewayURL
	}
	if c.ClientKind == nodev1.ClientKind_CLIENT_KIND_UNSPECIFIED {
		c.ClientKind = nodev1.ClientKind_CLIENT_KIND_AGENT
	}
	if len(c.ConsentClasses) == 0 {
		c.ConsentClasses = []nodev1.JobClass{nodev1.JobClass_JOB_CLASS_MEASURE}
	} else {
		c.ConsentClasses = slices.Clone(c.ConsentClasses)
		slices.Sort(c.ConsentClasses)
		c.ConsentClasses = slices.Compact(c.ConsentClasses)
	}
	if c.InterfacePrefixes == nil {
		c.InterfacePrefixes = systemInterfacePrefixes
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.BackoffMin == 0 {
		c.BackoffMin = defaultBackoffMin
	}
	if c.BackoffMax == 0 {
		c.BackoffMax = defaultBackoffMax
	}
	c.Roots = slices.Clone(c.Roots)
	return c
}

// validate checks a config that already has its defaults.
func (c Config) validate() error {
	if c.DataDir == "" {
		return errors.New("agent: DataDir is empty")
	}
	if len(c.Roots) == 0 {
		return errors.New("agent: no root keys")
	}
	for i, r := range c.Roots {
		if len(r) != ed25519.PublicKeySize {
			return fmt.Errorf("agent: root key %d has %d bytes, want %d", i, len(r), ed25519.PublicKeySize)
		}
	}
	if c.Registry == nil {
		return errors.New("agent: Registry is nil")
	}
	if c.Gate == nil {
		return errors.New("agent: Gate is nil")
	}
	if err := checkGatewayURL(c.GatewayURL); err != nil {
		return err
	}
	if c.BackoffMin < 0 || c.BackoffMax < 0 {
		return errors.New("agent: negative backoff")
	}
	if c.BackoffMin > c.BackoffMax {
		return fmt.Errorf("agent: BackoffMin %v is above BackoffMax %v", c.BackoffMin, c.BackoffMax)
	}
	for _, jc := range c.ConsentClasses {
		if _, known := nodev1.JobClass_name[int32(jc)]; !known || jc == nodev1.JobClass_JOB_CLASS_UNSPECIFIED {
			return fmt.Errorf("agent: consent for unknown job class %d", int32(jc))
		}
	}
	return nil
}

// checkGatewayURL accepts wss:// to any host, and ws:// only to a loopback
// host for development. The path must be the node endpoint, and the URL may
// carry no credentials, query or fragment: tokens travel only inside frames.
func checkGatewayURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("agent: gateway URL: %w", err)
	}
	if u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("agent: gateway URL %q must have no credentials, query or fragment", raw)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("agent: gateway URL %q has no host", raw)
	}
	switch u.Scheme {
	case "wss":
	case "ws":
		if !isLoopbackHost(host) {
			return fmt.Errorf("agent: gateway URL %q: ws:// is allowed only to 127.0.0.1, ::1 or localhost", raw)
		}
	default:
		return fmt.Errorf("agent: gateway URL %q must use wss://", raw)
	}
	if u.EscapedPath() != protocol.Path {
		return fmt.Errorf("agent: gateway URL path must be %s", protocol.Path)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return a == netip.AddrFrom4([4]byte{127, 0, 0, 1}) || a == netip.IPv6Loopback()
}

// systemInterfacePrefixes lists the prefixes of every interface address.
func systemInterfacePrefixes() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("agent: list interface addresses: %w", err)
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ones, bits := ipn.Mask.Size()
		if bits == 0 {
			continue
		}
		if ip.Is4In6() {
			ip = ip.Unmap()
			if bits == 8*net.IPv6len {
				ones -= 96
			}
		}
		p, err := ip.Prefix(ones)
		if err != nil {
			continue
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}
