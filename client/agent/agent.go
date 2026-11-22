// Package agent is the Hopbits node runtime. It keeps one WebSocket session
// to the gateway, answers heartbeats, verifies signed jobs, runs them through
// the compiled modules and the safety gate, and returns signed results.
//
// The runtime trusts the server only as far as the compiled caps allow. A
// Welcome or a job counts only with a valid signature from a root-certified
// dispatcher key, a job must name this node, every job passes its module's
// compiled checks and the safety gate before it touches the network, a job
// class runs only with the operator's local consent, and the gateway can
// only lower limits or add refusals.
package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/protocol"
)

const (
	// connectTimeout bounds one TCP connect: to the gateway, and to the pause
	// and update hosts.
	connectTimeout = 30 * time.Second
	// handshakeTimeout bounds the TLS handshake, and then the wait for the
	// answer's headers, on every connection the agent makes: 45 s each, so a
	// node on a slow or lossy link (a satellite, a crowded mobile network)
	// still gets through. 15 s was too little for some (0.2.2, 2026-11-17).
	handshakeTimeout = 45 * time.Second
	// dialTimeout bounds the whole gateway dial, the TCP, TLS and WebSocket
	// handshakes together: never shorter than the three in turn.
	dialTimeout = connectTimeout + 2*handshakeTimeout
	// welcomeTimeout bounds the wait for a Welcome after Hello, over the same
	// slow link.
	welcomeTimeout = handshakeTimeout
	// writeTimeout bounds one frame write.
	writeTimeout = 10 * time.Second
	// defaultHeartbeat is the native Ping interval when the gateway names none.
	defaultHeartbeat = 45 * time.Second
	// A session with no frame for this many heartbeats is dead.
	idleHeartbeats = 3
	minIdle        = 30 * time.Second
	maxIdle        = 15 * time.Minute
	// maxIssueAhead is how far in the future a job's issue time may lie.
	maxIssueAhead = 120 * time.Second
	// maxJobRun bounds a job's run whatever its deadline says.
	maxJobRun = 10 * time.Minute
	// maxByeWait caps a Bye's reconnect window, so a faulty server cannot
	// keep a node away for good.
	maxByeWait = 24 * time.Hour
	// selfTestTimeout bounds one module's self-test.
	selfTestTimeout = 10 * time.Second
	// selfTestEvery is the self-test cadence within a session.
	selfTestEvery = 6 * time.Hour
	// interfacePollEvery is how often the agent looks for a network change.
	interfacePollEvery = 30 * time.Second
	// maxAdmitting bounds jobs waiting for the safety gate at once.
	maxAdmitting = 32
	// maxRememberedJobs bounds the finished jobs kept to refuse replays.
	maxRememberedJobs = 8192
	// jobMemory is how long past its deadline a finished job is remembered.
	jobMemory = 10 * time.Minute
	// maxResultData bounds a module's result payload.
	maxResultData = 256 << 10
	// nonceSize is the length of the Hello nonce.
	nonceSize = 16
	// maxObservationsPerBatch bounds one SignedObservationBatch frame.
	maxObservationsPerBatch = 128
	// maxBufferedObservations bounds anchor observations retained while disconnected.
	maxBufferedObservations = 4096
)

// Agent is the node runtime. Create it with New and start it with Run.
type Agent struct {
	cfg           Config
	log           *slog.Logger
	key           ed25519.PrivateKey
	pub           ed25519.PublicKey
	nodeID        []byte
	nodeHex       string
	consent       map[nodev1.JobClass]bool
	ring          *protocol.KeyRing
	client        *http.Client
	controlClient *http.Client
	monoBase      time.Time

	state   *stateStore
	results *resultStore
	jobLog  *jobLog

	// sleep and jitter are replaced in tests.
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func(n time.Duration) time.Duration

	runMu    sync.Mutex
	jobWG    sync.WaitGroup
	noticeWG sync.WaitGroup

	mu        sync.Mutex
	sess      *session
	jobs      map[jobKey]*jobEntry
	admitting int
	running   int
	draining  bool
	denied    map[netip.Prefix]bool

	pauseMu             sync.Mutex
	pauseLastIssuedUnix int64
	pauseActive         bool
	pauseExpiresUnix    int64
	pauseReason         string

	updateMu             sync.Mutex
	updateLastIssuedUnix int64
	latestManifest       *ReleaseManifest
	loopRunning          bool
	stagedExecPath       string
	drainReqCh           chan struct{}
	updateDrainHook      func()
	drainHookOnce        sync.Once

	obsFlushMu sync.Mutex
	obsMu      sync.Mutex
	obsBuf     []*nodev1.Observation
}

// New checks cfg, applies its defaults, and loads or creates the device key,
// the state file, the result buffer and the job log under cfg.DataDir.
//
// Defaults: GatewayURL protocol.DefaultGatewayURL, ClientKind
// CLIENT_KIND_AGENT, ConsentClasses [JOB_CLASS_MEASURE], BackoffMin 1 s,
// BackoffMax 120 s, Now time.Now, Logger slog.Default() and
// InterfacePrefixes from the system's interfaces.
func New(cfg Config) (*Agent, error) {
	cfg = cfg.withDefaults()
	cleanLabel, labelTrunc := protocol.SanitizeNodeLabel(cfg.NodeLabel)
	cfg.NodeLabel = cleanLabel
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	key, err := LoadOrCreateKey(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("agent: device key has no Ed25519 public key")
	}
	id := protocol.NodeID(pub)
	a := &Agent{
		cfg:           cfg,
		key:           key,
		pub:           pub,
		nodeID:        id,
		nodeHex:       protocol.NodeIDString(id),
		consent:       make(map[nodev1.JobClass]bool, len(cfg.ConsentClasses)),
		ring:          protocol.NewKeyRing(cfg.Roots),
		client:        newHTTPClient(cfg.TLSConfig),
		controlClient: newControlHTTPClient(cfg.TLSConfig),
		monoBase:      time.Now(),
		sleep:         sleepCtx,
		jitter:        uniformJitter,
		jobs:          make(map[jobKey]*jobEntry),
		denied:        make(map[netip.Prefix]bool),
	}
	if a.cfg.PausePollInterval == 0 {
		a.cfg.PausePollInterval = defaultPausePollInterval
	}
	if a.cfg.PauseFetcher == nil && a.cfg.PausePollInterval > 0 {
		a.cfg.PauseFetcher = NewHTTPPauseFetcher(DefaultPauseURL, a.controlClient)
	}
	if a.cfg.UpdatePollInterval == 0 {
		a.cfg.UpdatePollInterval = defaultUpdatePollInterval
	}
	if a.cfg.UpdateFetcher == nil && a.cfg.UpdatePollInterval >= 0 {
		a.cfg.UpdateFetcher = NewHTTPUpdateFetcher(DefaultManifestURL, a.controlClient)
	}
	if a.cfg.BinaryInstaller == nil {
		a.cfg.BinaryInstaller = NewVolumeBinaryInstaller(a.cfg.DataDir)
	}
	a.log = cfg.Logger.With("node_id", a.nodeHex)
	if labelTrunc {
		a.log.Warn("node label exceeds 80 characters; truncated", "label", a.cfg.NodeLabel)
	}
	for _, c := range cfg.ConsentClasses {
		a.consent[c] = true
	}
	if a.state, err = openState(cfg.DataDir, a.log); err != nil {
		return nil, err
	}
	for _, sr := range a.state.revocations() {
		if err := a.ring.ApplyRevocation(sr); err != nil {
			a.log.Warn("ignoring a stored revocation that no longer verifies", "err", err)
		}
	}
	if a.results, err = openResultStore(cfg.DataDir, cfg.Now, a.log); err != nil {
		return nil, err
	}
	if a.jobLog, err = openJobLog(cfg.DataDir); err != nil {
		return nil, err
	}
	// A job whose result still waits for its acknowledgement has run; a
	// replay of it is acknowledged, not run again.
	for _, p := range a.results.list() {
		a.jobs[p.key] = &jobEntry{state: jobFinished, forgetAt: p.stored.Add(maxPendingAge)}
	}
	return a, nil
}

// NodeID returns the node id in its hex form.
func (a *Agent) NodeID() string { return a.nodeHex }

// VerifyGrant checks a signed target grant against the root-certified
// target-grant key the gateway delivered, and returns its body while it is
// valid at now. The safety layer can use it to lift per-target limits.
func (a *Agent) VerifyGrant(sg *nodev1.SignedTargetGrant, now time.Time) (*nodev1.TargetGrant, error) {
	if sg == nil {
		return nil, errors.New("agent: no target grant")
	}
	err := a.ring.Verify(sg.GetKeyId(), nodev1.KeyRole_KEY_ROLE_TARGET_GRANT, protocol.PurposeTargetGrant, sg.GetBody(), sg.GetSig(), now)
	if err != nil {
		return nil, fmt.Errorf("agent: target grant: %w", err)
	}
	tg := &nodev1.TargetGrant{}
	if err := proto.Unmarshal(sg.GetBody(), tg); err != nil {
		return nil, fmt.Errorf("agent: decode target grant: %w", err)
	}
	if tg.GetExpiresUnix() <= now.Unix() {
		return nil, errors.New("agent: target grant expired")
	}
	return tg, nil
}

// SetUpdateDrainHook registers an optional callback invoked once when a signed
// update has been staged during Run so co-hosted listeners (such as anchor
// mode's HTTP/WS/ICMP server) can shut down and flush queued observations
// before the gateway session closes and the process re-executes.
func (a *Agent) SetUpdateDrainHook(fn func()) {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	a.updateDrainHook = fn
}

func (a *Agent) stageUpdateForDrain(path string) bool {
	a.updateMu.Lock()
	if !a.loopRunning {
		a.updateMu.Unlock()
		return false
	}
	if a.stagedExecPath == "" {
		a.stagedExecPath = path
	}
	ch := a.drainReqCh
	a.updateMu.Unlock()

	a.mu.Lock()
	a.draining = true
	a.mu.Unlock()

	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return true
}

func (a *Agent) hasStagedUpdate() bool {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	return a.stagedExecPath != ""
}

func (a *Agent) runUpdateDrainHook() {
	a.updateMu.Lock()
	hook := a.updateDrainHook
	a.updateMu.Unlock()
	a.drainHookOnce.Do(func() {
		if hook != nil {
			hook()
		}
	})
}

// Run connects to the gateway and keeps a session until ctx ends (or a signed
// self-update is staged), reconnecting with full-jitter backoff between
// BackoffMin and BackoffMax. A Bye's reconnect window is honoured, survives
// restarts and never resets the backoff. Run waits for running jobs to finish
// and persist their results, then either returns ctx.Err() or re-execs into the
// verified staged binary.
func (a *Agent) Run(ctx context.Context) error {
	stagedPath, err := a.runLoop(ctx)
	if err != nil {
		return err
	}
	if stagedPath != "" && a.cfg.BinaryInstaller != nil {
		if execErr := a.cfg.BinaryInstaller.Exec(stagedPath); execErr != nil {
			a.log.Warn("cannot exec staged release binary", "path", stagedPath, "err", execErr)
			return execErr
		}
	}
	return nil
}

func (a *Agent) runLoop(ctx context.Context) (stagedPath string, retErr error) {
	if !a.runMu.TryLock() {
		return "", errors.New("agent: Run is already active")
	}
	defer a.runMu.Unlock()

	intakeCtx, stopIntake := context.WithCancel(ctx)
	drainReqCh := make(chan struct{}, 1)

	a.mu.Lock()
	a.draining = false
	a.mu.Unlock()

	a.updateMu.Lock()
	a.loopRunning = true
	a.stagedExecPath = ""
	a.drainReqCh = drainReqCh
	a.drainHookOnce = sync.Once{}
	a.updateMu.Unlock()

	bgCtx, stopBG := context.WithCancel(intakeCtx)
	drainWatchCtx, stopDrainWatch := context.WithCancel(ctx)
	var bgWG sync.WaitGroup
	var drainWG sync.WaitGroup
	drainWG.Add(1)
	go func() {
		defer drainWG.Done()
		select {
		case <-drainWatchCtx.Done():
			return
		case <-drainReqCh:
		}
		// New job admissions are already blocked (a.draining == true); wait for
		// accepted measurement jobs to finish and transmit/persist their results
		// while the gateway WebSocket session remains open.
		a.jobWG.Wait()
		if ctx.Err() != nil {
			return
		}
		a.runUpdateDrainHook()
		if s := a.currentSession(); s != nil {
			_ = a.flushObservations(s)
			s.setEndNote("draining for signed self-update")
			s.close(websocket.StatusGoingAway, "updating")
		}
		stopIntake()
	}()

	if a.cfg.PauseFetcher != nil && a.cfg.PausePollInterval > 0 {
		bgWG.Add(1)
		go func() {
			defer bgWG.Done()
			a.runPauseLoop(bgCtx)
		}()
	}
	if a.cfg.UpdateFetcher != nil && a.cfg.UpdatePollInterval > 0 && a.cfg.AutoUpdateEnabled() {
		bgWG.Add(1)
		go func() {
			defer bgWG.Done()
			a.runUpdateLoop(bgCtx)
		}()
	}

	defer func() {
		stopIntake()
		stopBG()
		bgWG.Wait()
		a.noticeWG.Wait()
		a.jobWG.Wait()
		if a.hasStagedUpdate() && ctx.Err() == nil {
			a.runUpdateDrainHook()
		}
		stopDrainWatch()
		drainWG.Wait()
		a.client.CloseIdleConnections()
		if a.controlClient != nil {
			a.controlClient.CloseIdleConnections()
		}
		a.mu.Lock()
		a.draining = false
		a.mu.Unlock()
		a.updateMu.Lock()
		s := a.stagedExecPath
		a.stagedExecPath = ""
		a.loopRunning = false
		a.drainReqCh = nil
		a.updateMu.Unlock()
		if retErr == nil && ctx.Err() == nil {
			stagedPath = s
		}
	}()

	b := &backoff{min: a.cfg.BackoffMin, max: a.cfg.BackoffMax, jitter: a.jitter}
	wait := a.byeWait()
	if wait > 0 {
		a.log.Info("honouring the reconnect window of the last Bye", "delay", wait.Round(time.Second).String())
	}
	for {
		if a.hasStagedUpdate() && ctx.Err() == nil {
			break
		}
		if wait > 0 {
			a.log.Debug("waiting before connecting to the gateway", "delay", wait.Round(time.Millisecond).String())
			if err := a.sleep(intakeCtx, wait); err != nil {
				if ctx.Err() != nil {
					return "", ctx.Err()
				}
				if a.hasStagedUpdate() {
					break
				}
				return "", err
			}
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if a.hasStagedUpdate() {
			break
		}
		end := a.runSession(ctx, intakeCtx)
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if a.hasStagedUpdate() {
			break
		}
		wait = a.nextWait(ctx, end, b)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "", nil
}

// sessionEnd says how a session ended, for the reconnect policy.
type sessionEnd struct {
	// established is true once a Welcome was verified.
	established bool
	// lasted is how long an established session stayed up.
	lasted time.Duration
	// bye is the Bye that ended the session, if any.
	bye *nodev1.Bye
}

// nextWait applies the reconnect policy. A session that stayed up for
// BackoffMax without a Bye resets the backoff; a failed connect or a short
// session raises it. A Bye never resets it: the wait is drawn from the Bye's
// window, and when the session was short the backoff also applies, so a
// server that says Bye at once cannot pull the node into a reconnect loop.
func (a *Agent) nextWait(ctx context.Context, end sessionEnd, b *backoff) time.Duration {
	stable := end.established && end.lasted >= a.cfg.BackoffMax
	if end.bye != nil {
		if end.bye.GetReason() == nodev1.ByeReason_BYE_REASON_UPGRADE_REQUIRED && !a.confirmUpgradeRequired(ctx) {
			return b.next()
		}
		if a.hasStagedUpdate() {
			return 0
		}
		d := a.byeDelay(end.bye)
		if !stable {
			d = max(d, b.next())
		}
		a.recordBye(end.bye, d)
		return d
	}
	if stable {
		b.reset()
	}
	return b.next()
}

// byeDelay draws a delay from a Bye's reconnect window.
func (a *Agent) byeDelay(bye *nodev1.Bye) time.Duration {
	lo := time.Duration(bye.GetReconnectMinS()) * time.Second
	hi := time.Duration(bye.GetReconnectMaxS()) * time.Second
	lo, hi = min(lo, maxByeWait), min(hi, maxByeWait)
	if hi < lo {
		hi = lo
	}
	d := lo
	if hi > lo {
		d += a.jitter(hi - lo)
	}
	return d
}

// recordBye persists the end of the wait a Bye caused, so a restart inside
// the window still waits.
func (a *Agent) recordBye(bye *nodev1.Bye, d time.Duration) {
	reason := bye.GetReason().String()
	if err := a.state.setReconnectAfterVersion(a.now().Add(d), reason, a.cfg.ClientVersion); err != nil {
		a.log.Warn("cannot persist the reconnect window", "err", err)
	}
	a.log.Info("the gateway closed the session", "reason", reason, "reconnect_in", d.Round(time.Millisecond).String())
}

// byeWait returns what remains of a stored Bye window.
func (a *Agent) byeWait() time.Duration {
	until := a.state.reconnectAfterVersion(a.cfg.ClientVersion)
	if until.IsZero() {
		return 0
	}
	return min(max(until.Sub(a.now()), 0), maxByeWait)
}

func (a *Agent) now() time.Time { return a.cfg.Now() }

// mono reads the node's monotonic clock in nanoseconds.
func (a *Agent) mono() int64 { return int64(time.Since(a.monoBase)) }

func (a *Agent) currentSession() *session {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sess
}

func (a *Agent) setSession(s *session) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sess = s
}

func (a *Agent) clearSession(s *session) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sess == s {
		a.sess = nil
	}
}

// applyRevocation verifies a root-signed revocation, withdraws its keys and
// remembers it across restarts.
func (a *Agent) applyRevocation(sr *nodev1.SignedRevocation) {
	if err := a.ring.ApplyRevocation(sr); err != nil {
		a.log.Warn("ignoring a revocation that does not verify", "err", err)
		return
	}
	if err := a.state.addRevocation(sr); err != nil {
		a.log.Warn("cannot persist a revocation", "err", err)
	}
}

// addCertificate adds a root-certified key for role.
func (a *Agent) addCertificate(sc *nodev1.SignedKeyCertificate, role nodev1.KeyRole) {
	if _, err := a.ring.AddCertificate(sc, role); err != nil {
		a.log.Warn("ignoring a key certificate", "role", role.String(), "err", err)
	}
}

// addDenyPrefixes passes deny prefixes the gate has not seen yet.
func (a *Agent) addDenyPrefixes(entries []string) {
	var fresh []netip.Prefix
	a.mu.Lock()
	for _, s := range entries {
		p, err := parseDenyPrefix(s)
		if err != nil {
			a.log.Warn("ignoring an invalid deny prefix", "prefix", s)
			continue
		}
		if !a.denied[p] {
			a.denied[p] = true
			fresh = append(fresh, p)
		}
	}
	a.mu.Unlock()
	if len(fresh) > 0 {
		a.cfg.Gate.AddDenyPrefixes(fresh)
	}
}

// parseDenyPrefix parses a CIDR prefix; a bare address denies just itself.
func parseDenyPrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("agent: deny prefix %q is too wide", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("agent: invalid deny prefix %q", s)
	}
	addr = addr.Unmap().WithZone("")
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// parseAddrs parses the gateway's observed addresses, with or without port.
func parseAddrs(ss []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		if ap, err := netip.ParseAddrPort(s); err == nil {
			out = append(out, ap.Addr().Unmap().WithZone(""))
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.Unmap().WithZone(""))
		}
	}
	return out
}

// sleepCtx waits for d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

var errRedirect = errors.New("agent: the gateway endpoint does not redirect")

// maxIPv4DialWait caps the initial IPv4 attempt when dialing a gateway hostname
// so even a blackholed IPv4 route leaves plenty of dialTimeout for IPv6 fallback.
const maxIPv4DialWait = 10 * time.Second

// dialPreferIPv4 wraps dialer so gateway hostname dials try IPv4 ("tcp4")
// before falling back to IPv6 ("tcp6"). Without this, Go's Happy Eyeballs
// connects dual-stack nodes to Cloudflare's AAAA record first, leaving
// Welcome.ObservedAddresses without the node's public IPv4 address and causing
// refusedFamilies to refuse all IPv4 jobs locally.
func dialPreferIPv4(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" {
			return dialer.DialContext(ctx, network, addr)
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return dialer.DialContext(ctx, network, addr)
		}
		if ip, perr := netip.ParseAddr(host); perr == nil {
			if ip.Is6() && !ip.Is4In6() {
				return dialer.DialContext(ctx, "tcp", addr)
			}
			return dialer.DialContext(ctx, "tcp4", addr)
		}

		v4Wait := connectTimeout / 2
		if dialer.Timeout > 0 {
			v4Wait = max(dialer.Timeout/2, time.Millisecond)
		}
		v4Wait = min(v4Wait, maxIPv4DialWait)
		if dl, ok := ctx.Deadline(); ok {
			rem := time.Until(dl)
			if rem <= 0 {
				return dialer.DialContext(ctx, "tcp4", addr)
			}
			v4Wait = min(v4Wait, max(rem/2, time.Millisecond))
		}

		ctx4, cancel4 := context.WithTimeout(ctx, v4Wait)
		conn, err4 := dialer.DialContext(ctx4, "tcp4", addr)
		cancel4()
		if err4 == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, err4
		}
		conn6, err6 := dialer.DialContext(ctx, "tcp6", addr)
		if err6 == nil {
			return conn6, nil
		}
		return nil, fmt.Errorf("tcp4: %w; tcp6: %w", err4, err6)
	}
}

// newHTTPClient builds the client for the WebSocket handshake: HTTP/1.1
// only, TLS 1.3 at least, IPv4 preferred with IPv6 fallback, and no redirects.
func newHTTPClient(base *tls.Config) *http.Client {
	tc := &tls.Config{}
	if base != nil {
		tc = base.Clone()
	}
	if tc.MinVersion < tls.VersionTLS13 {
		tc.MinVersion = tls.VersionTLS13
	}
	tc.NextProtos = []string{"http/1.1"}
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	dialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialPreferIPv4(dialer),
		TLSClientConfig:       tc,
		TLSHandshakeTimeout:   handshakeTimeout,
		ResponseHeaderTimeout: handshakeTimeout,
		Protocols:             &protocols,
		MaxIdleConns:          1,
		IdleConnTimeout:       30 * time.Second,
		DisableCompression:    true,
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirect
		},
	}
}
