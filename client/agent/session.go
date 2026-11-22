package agent

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/protocol"
)

// errBadFrame marks a frame that does not decode; the connection itself is
// still usable.
var errBadFrame = errors.New("agent: undecodable frame")

// session is one WebSocket connection to the gateway.
type session struct {
	a        *Agent
	conn     *websocket.Conn
	exporter []byte
	// runCtx is Run's context: jobs outlive their session but not Run.
	runCtx context.Context
	// readCtx ends when frame intake stops (e.g. draining for self-update) or
	// when ctx ends.
	readCtx context.Context
	// ctx ends with the session (after any update drain flush completes).
	ctx    context.Context
	cancel context.CancelFunc

	sendMu sync.Mutex
	seq    uint64
	recv   seqTracker

	// Owned by the read loop.
	idle time.Duration
	bye  *nodev1.Bye

	// Set during setup, then owned by the maintenance goroutine; endNote is
	// guarded by noteMu so update drain can record why the session closed.
	prefixes []netip.Prefix
	caps     []string
	noteMu   sync.Mutex
	endNote  string
}

// runSession dials the gateway and runs one session to its end. The
// self-test runs first, so Hello leaves as soon as the connection is up.
func (a *Agent) runSession(runCtx, intakeCtx context.Context) sessionEnd {
	caps, tests := a.selfTest(intakeCtx)
	dctx, cancel := context.WithTimeout(intakeCtx, dialTimeout)
	conn, resp, err := websocket.Dial(dctx, a.cfg.GatewayURL, &websocket.DialOptions{
		HTTPClient: a.client,
		HTTPHeader: http.Header{"User-Agent": []string{userAgent(a.cfg.ClientVersion)}},
	})
	cancel()
	if err != nil {
		if intakeCtx.Err() == nil && runCtx.Err() == nil {
			a.log.Warn("cannot connect to the gateway", "err", err)
		}
		return sessionEnd{}
	}
	defer func() { _ = conn.CloseNow() }()
	conn.SetReadLimit(protocol.MaxFrameBytes)

	sctx, scancel := context.WithCancel(runCtx)
	rctx, rcancel := context.WithCancel(intakeCtx)
	stopSession := func() {
		rcancel()
		scancel()
	}
	defer stopSession()
	s := &session{
		a:       a,
		conn:    conn,
		runCtx:  runCtx,
		readCtx: rctx,
		ctx:     sctx,
		cancel:  stopSession,
		idle:    idleTimeout(0),
	}
	if resp != nil && resp.TLS != nil {
		ekm, err := resp.TLS.ExportKeyingMaterial(protocol.TLSExporterLabel, nil, protocol.TLSExporterLength)
		if err != nil {
			a.log.Debug("no TLS exporter value for this connection", "err", err)
		} else {
			s.exporter = ekm
		}
	}
	return s.run(caps, tests)
}

func userAgent(version string) string {
	if version == "" {
		return "hopbits-agent"
	}
	return "hopbits-agent/" + version
}

// idleTimeout is how long a session may stay silent before it counts as dead.
func idleTimeout(heartbeatS uint32) time.Duration {
	hb := defaultHeartbeat
	if heartbeatS > 0 {
		hb = time.Duration(heartbeatS) * time.Second
	}
	return min(max(idleHeartbeats*hb, minIdle), maxIdle)
}

// run performs the handshake, then serves the session until it ends.
func (s *session) run(caps []string, tests []*nodev1.SelfTestResult) sessionEnd {
	a := s.a
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		a.log.Error("cannot draw a Hello nonce", "err", err)
		return sessionEnd{}
	}
	if err := s.sendHello(caps, nonce); err != nil {
		if s.runCtx.Err() == nil {
			a.log.Warn("cannot send Hello", "err", err)
		}
		return sessionEnd{}
	}
	w, bye, err := s.awaitWelcome(nonce)
	switch {
	case bye != nil:
		s.close(websocket.StatusNormalClosure, "bye")
		return sessionEnd{bye: bye}
	case err != nil && (s.runCtx.Err() != nil || s.readCtx.Err() != nil):
		return sessionEnd{}
	case err != nil:
		a.log.Warn("no valid welcome from the gateway; closing the session", "err", err)
		s.close(websocket.StatusPolicyViolation, "welcome rejected")
		return sessionEnd{}
	}
	if err := s.applyWelcome(w); err != nil {
		a.log.Error("cannot set up the session; closing it", "err", err)
		s.close(websocket.StatusInternalError, "setup failed")
		return sessionEnd{}
	}
	s.caps = caps
	if err := s.sendCapabilities(caps, tests); err != nil {
		a.log.Warn("cannot send capabilities", "err", err)
		return sessionEnd{}
	}
	if err := s.sendConsent(); err != nil {
		a.log.Warn("cannot send the consent state", "err", err)
		return sessionEnd{}
	}

	started := time.Now()
	// The session becomes current before the buffer is read, so a result
	// stored meanwhile is either in the resend or sent by its job.
	a.setSession(s)
	defer a.clearSession(s)
	a.log.Info("connected to the gateway", "session_id", w.GetSessionId(), "capabilities", strings.Join(caps, " "))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.resendPending()
	}()
	go func() {
		defer wg.Done()
		s.maintain()
	}()
	err = s.readLoop()
	s.cancel()
	wg.Wait()

	endNote := s.getEndNote()
	switch {
	case s.bye != nil:
		s.close(websocket.StatusNormalClosure, "bye")
	case endNote != "":
		a.log.Info("session ended", "reason", endNote)
	case s.runCtx.Err() != nil:
	case errors.Is(err, context.DeadlineExceeded):
		a.log.Warn("no frame from the gateway in time; reconnecting", "idle", s.idle.String())
	default:
		a.log.Warn("session lost; reconnecting", "err", err)
	}
	return sessionEnd{established: true, lasted: time.Since(started), bye: s.bye}
}

func (s *session) setEndNote(note string) {
	s.noteMu.Lock()
	defer s.noteMu.Unlock()
	if s.endNote == "" {
		s.endNote = note
	}
}

func (s *session) getEndNote() string {
	s.noteMu.Lock()
	defer s.noteMu.Unlock()
	return s.endNote
}

func (s *session) close(code websocket.StatusCode, reason string) {
	_ = s.conn.Close(code, reason)
}

// awaitWelcome reads until the Welcome arrives, a Bye ends the attempt or
// welcomeTimeout passes. Error frames are logged; anything else fails.
func (s *session) awaitWelcome(nonce []byte) (*nodev1.Welcome, *nodev1.Bye, error) {
	ctx, cancel := context.WithTimeout(s.readCtx, welcomeTimeout)
	defer cancel()
	for {
		env, _, err := s.readFrame(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("agent: wait for welcome: %w", err)
		}
		if env.GetChannel() != 0 {
			return nil, nil, errors.New("agent: frame on a reserved channel before the welcome")
		}
		switch b := env.GetBody().(type) {
		case *nodev1.Envelope_Welcome:
			w, err := s.a.verifyWelcome(b.Welcome, nonce, s.exporter)
			return w, nil, err
		case *nodev1.Envelope_Bye:
			return nil, b.Bye, nil
		case *nodev1.Envelope_Error:
			s.a.logServerError(b.Error)
		default:
			return nil, nil, fmt.Errorf("agent: unexpected %T before the welcome", b)
		}
	}
}

// verifyWelcome checks a SignedWelcome. Its certificates and revocations
// carry root signatures of their own, so they are taken first; nothing else
// in the body is trusted before the dispatcher signature verifies.
func (a *Agent) verifyWelcome(sw *nodev1.SignedWelcome, nonce, exporter []byte) (*nodev1.Welcome, error) {
	w := &nodev1.Welcome{}
	if err := proto.Unmarshal(sw.GetBody(), w); err != nil {
		return nil, fmt.Errorf("agent: decode welcome: %w", err)
	}
	for _, r := range w.GetRevocations() {
		a.applyRevocation(r)
	}
	for _, c := range w.GetDispatcherCerts() {
		a.addCertificate(c, nodev1.KeyRole_KEY_ROLE_DISPATCHER)
	}
	err := a.ring.Verify(sw.GetKeyId(), nodev1.KeyRole_KEY_ROLE_DISPATCHER, protocol.PurposeWelcome, sw.GetBody(), sw.GetSig(), a.now())
	if err != nil {
		return nil, fmt.Errorf("agent: welcome signature: %w", err)
	}
	if len(nonce) == 0 || subtle.ConstantTimeCompare(w.GetHelloNonce(), nonce) != 1 {
		return nil, errors.New("agent: welcome does not answer this session's Hello")
	}
	if !bytes.Equal(w.GetNodeId(), a.nodeID) {
		return nil, errors.New("agent: welcome is for another node")
	}
	if want := w.GetTlsExporter(); len(want) > 0 {
		if exporter == nil {
			return nil, errors.New("agent: welcome carries a TLS exporter value but this connection has none")
		}
		if subtle.ConstantTimeCompare(want, exporter) != 1 {
			return nil, errors.New("agent: welcome is bound to another TLS session")
		}
	}
	if gc := w.GetGrantKeyCert(); gc != nil {
		a.addCertificate(gc, nodev1.KeyRole_KEY_ROLE_TARGET_GRANT)
	}
	return w, nil
}

// applyWelcome applies a verified Welcome to the safety gate.
func (s *session) applyWelcome(w *nodev1.Welcome) error {
	a := s.a
	if st := w.GetServerTimeUnixMs(); st != 0 {
		if skew := a.now().UnixMilli() - st; skew > protocol.MaxClockSkewMillis || skew < -protocol.MaxClockSkewMillis {
			a.log.Warn("the local clock is far from the gateway's; jobs may be refused as expired", "skew", (time.Duration(skew) * time.Millisecond).String())
		}
	}
	if l := w.GetLimits(); l != nil {
		a.cfg.Gate.ApplyLimits(l)
	}
	prefixes, err := a.cfg.InterfacePrefixes()
	if err != nil {
		return fmt.Errorf("agent: list interface prefixes: %w", err)
	}
	observed := parseAddrs(w.GetObservedAddresses())
	a.cfg.Gate.SetOwnNetwork(slices.Clone(prefixes), observed)
	refuse4, refuse6 := refusedFamilies(a.cfg.NetworkMode, observed)
	a.cfg.Gate.RefuseFamilies(refuse4, refuse6)
	s.prefixes = prefixes
	s.idle = idleTimeout(w.GetHeartbeatIntervalS())
	if h := w.GetRedirectHost(); h != "" {
		a.log.Info("the gateway offered a redirect, which this client does not follow", "host", h)
	}
	return nil
}

func (s *session) sendHello(caps []string, nonce []byte) error {
	a := s.a
	body, err := proto.Marshal(&nodev1.Hello{
		ProtocolVersion: protocol.Version,
		ClientKind:      a.cfg.ClientKind,
		ClientVersion:   a.cfg.ClientVersion,
		PublicKey:       a.pub,
		NodeId:          a.nodeID,
		Os:              runtime.GOOS + "/" + runtime.GOARCH,
		NetworkMode:     a.cfg.NetworkMode,
		Capabilities:    caps,
		EnrollmentToken: a.cfg.EnrollmentToken,
		TimestampUnixMs: a.now().UnixMilli(),
		Nonce:           nonce,
		Label:           a.cfg.NodeLabel,
	})
	if err != nil {
		return fmt.Errorf("agent: encode hello: %w", err)
	}
	return s.send(&nodev1.Envelope{Body: &nodev1.Envelope_Hello{Hello: &nodev1.SignedHello{
		Body: body,
		Sig:  protocol.Sign(a.key, protocol.PurposeHello, body),
	}}})
}

func (s *session) sendCapabilities(caps []string, tests []*nodev1.SelfTestResult) error {
	return s.send(&nodev1.Envelope{Body: &nodev1.Envelope_Caps{Caps: &nodev1.CapabilityUpdate{
		Capabilities:      caps,
		SelfTests:         tests,
		NetworkMode:       s.a.cfg.NetworkMode,
		HostAccess:        nodev1.HostAccess_HOST_ACCESS_NOT_APPLICABLE,
		InterfacePrefixes: publicPrefixes(s.prefixes),
	}}})
}

// sendConsent reports the operator's local consent record, signed.
func (s *session) sendConsent() error {
	a := s.a
	now := a.now()
	granted, err := a.state.consentGrants(a.cfg.ConsentClasses, now)
	if err != nil {
		a.log.Warn("cannot persist the consent record", "err", err)
	}
	cs := &nodev1.ConsentState{TimestampUnixMs: now.UnixMilli()}
	for _, c := range a.cfg.ConsentClasses {
		cs.Classes = append(cs.Classes, &nodev1.ClassConsent{JobClass: c, GrantedUnix: granted[c]})
	}
	body, err := proto.Marshal(cs)
	if err != nil {
		return fmt.Errorf("agent: encode consent state: %w", err)
	}
	return s.send(&nodev1.Envelope{Body: &nodev1.Envelope_Consent{Consent: &nodev1.SignedConsentState{
		Body: body,
		Sig:  protocol.Sign(a.key, protocol.PurposeConsent, body),
	}}})
}

// resendPending sends every stored result not yet acknowledged and flushes
// any anchor observations buffered while disconnected.
func (s *session) resendPending() {
	pending := s.a.results.list()
	for i, p := range pending {
		if err := s.send(resultEnvelope(p.signed)); err != nil {
			// The next session resends the rest.
			s.a.log.Debug("stopped resending buffered results", "sent", i, "err", err)
			return
		}
	}
	if len(pending) > 0 {
		s.a.log.Info("resent buffered results", "count", len(pending))
	}
	s.a.flushObservations(s)
}

func resultEnvelope(sr *nodev1.SignedResult) *nodev1.Envelope {
	return &nodev1.Envelope{Body: &nodev1.Envelope_Result{Result: sr}}
}

// readFrame reads and decodes one frame. A frame that does not decode
// returns an error wrapping errBadFrame; the connection stays usable.
func (s *session) readFrame(ctx context.Context) (*nodev1.Envelope, int64, error) {
	typ, b, err := s.conn.Read(ctx)
	recv := s.a.mono()
	if err != nil {
		return nil, 0, err
	}
	if typ != websocket.MessageBinary {
		return nil, recv, fmt.Errorf("%w: not a binary frame", errBadFrame)
	}
	env, err := protocol.DecodeEnvelope(b)
	if err != nil {
		return nil, recv, fmt.Errorf("%w: %w", errBadFrame, err)
	}
	s.recv.received(env.GetSeq())
	return env, recv, nil
}

// readLoop serves frames until the session ends. It returns nil after a Bye.
func (s *session) readLoop() error {
	for {
		ctx, cancel := context.WithTimeout(s.readCtx, s.idle)
		env, recv, err := s.readFrame(ctx)
		cancel()
		if errors.Is(err, errBadFrame) {
			s.a.log.Warn("the gateway sent an undecodable frame", "err", err)
			s.sendError(nodev1.ErrorCode_ERROR_CODE_PROTOCOL_VIOLATION, "undecodable frame")
			continue
		}
		if err != nil {
			return err
		}
		if s.handle(env, recv) {
			return nil
		}
	}
}

// handle serves one frame and reports whether it ends the session.
func (s *session) handle(env *nodev1.Envelope, recv int64) bool {
	a := s.a
	if env.GetChannel() != 0 {
		s.sendError(nodev1.ErrorCode_ERROR_CODE_CLASS_NOT_ENABLED, "channel not enabled")
		return false
	}
	switch b := env.GetBody().(type) {
	case *nodev1.Envelope_Ping:
		s.pong(b.Ping, recv)
	case *nodev1.Envelope_Job:
		s.handleJob(b.Job)
	case *nodev1.Envelope_JobCancel:
		a.cancelJob(b.JobCancel)
	case *nodev1.Envelope_ResultAck:
		a.ackResult(b.ResultAck)
	case *nodev1.Envelope_Config:
		s.applyConfig(b.Config)
	case *nodev1.Envelope_PairCode:
		a.log.Warn("PAIRING CODE: enter it in the Hopbits dashboard to bind this node to your account",
			"code", b.PairCode.GetCode(), "expires", formatUnix(b.PairCode.GetExpiresUnix()))
	case *nodev1.Envelope_Paired:
		a.log.Info("node paired with an account", "account", b.Paired.GetAccountHint(), "tier", b.Paired.GetTier().String())
	case *nodev1.Envelope_Notice:
		a.logNotice(b.Notice)
		if b.Notice.GetKind() == nodev1.NoticeKind_NOTICE_KIND_UPGRADE {
			notice := b.Notice
			a.noticeWG.Add(1)
			go func() {
				defer a.noticeWG.Done()
				a.checkUpgradeNotice(s.runCtx, notice)
			}()
		}
	case *nodev1.Envelope_Error:
		a.logServerError(b.Error)
	case *nodev1.Envelope_Bye:
		s.bye = b.Bye
		return true
	default:
		s.sendError(nodev1.ErrorCode_ERROR_CODE_UNSUPPORTED_MESSAGE, "unsupported message")
	}
	return false
}

// pong answers a Ping at once.
func (s *session) pong(p *nodev1.Ping, recv int64) {
	pong := &nodev1.Pong{
		Nonce:          p.GetNonce(),
		NodeRecvMonoNs: recv,
		RunningJobs:    uint32(s.a.runningJobs()),
	}
	err := s.sendStamped(&nodev1.Envelope{Body: &nodev1.Envelope_Pong{Pong: pong}}, func() {
		pong.NodeSendMonoNs = s.a.mono()
	})
	if err != nil {
		s.a.log.Debug("cannot answer a ping", "err", err)
	}
}

// applyConfig applies a ConfigUpdate. Certificates and revocations carry
// root signatures; limits can only lower caps; deny prefixes and
// do-not-probe entries only add refusals.
func (s *session) applyConfig(cu *nodev1.ConfigUpdate) {
	a := s.a
	for _, r := range cu.GetRevocations() {
		a.applyRevocation(r)
	}
	for _, c := range cu.GetDispatcherCerts() {
		a.addCertificate(c, nodev1.KeyRole_KEY_ROLE_DISPATCHER)
	}
	if gc := cu.GetGrantKeyCert(); gc != nil {
		a.addCertificate(gc, nodev1.KeyRole_KEY_ROLE_TARGET_GRANT)
	}
	if l := cu.GetLimits(); l != nil {
		a.cfg.Gate.ApplyLimits(l)
	}
	if p := cu.GetDenyPrefixes(); len(p) > 0 {
		a.addDenyPrefixes(p)
	}
	// An empty list cannot be told from an absent one, so it changes nothing.
	if d := cu.GetDoNotProbe(); len(d) > 0 {
		a.cfg.Gate.SetDoNotProbe(slices.Clone(d))
	}
	if hb := cu.GetHeartbeatIntervalS(); hb > 0 {
		s.idle = idleTimeout(hb)
	}
}

// maintain watches for network changes, repeats the self-test and prunes
// buffers until the session ends.
func (s *session) maintain() {
	a := s.a
	poll := time.NewTicker(interfacePollEvery)
	defer poll.Stop()
	retest := time.NewTicker(selfTestEvery)
	defer retest.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-poll.C:
			p, err := a.cfg.InterfacePrefixes()
			if err != nil {
				a.log.Error("cannot list the host's interfaces", "err", err)
				s.setEndNote("the own-network refusal cannot be kept current")
				s.cancel()
				return
			}
			if !samePrefixes(p, s.prefixes) {
				// A new Welcome brings the addresses the gateway now sees,
				// which the own-network refusal needs.
				s.setEndNote("network changed; reconnecting")
				s.cancel()
				return
			}
		case <-retest.C:
			caps, tests := a.selfTest(s.ctx)
			if !slices.Equal(caps, s.caps) {
				s.caps = caps
				if err := s.sendCapabilities(caps, tests); err != nil {
					a.log.Debug("cannot send capabilities", "err", err)
				}
			}
		case <-prune.C:
			a.results.prune()
			a.pruneJobs()
		}
	}
}

func (s *session) send(env *nodev1.Envelope) error { return s.sendStamped(env, nil) }

// sendStamped numbers and writes one frame. stamp runs just before the
// frame is encoded, for fields that record the send time.
func (s *session) sendStamped(env *nodev1.Envelope, stamp func()) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if err := s.ctx.Err(); err != nil {
		return fmt.Errorf("agent: session closed: %w", err)
	}
	env.V = protocol.Version
	env.Seq = s.seq + 1
	env.Ack = s.recv.ack()
	if stamp != nil {
		stamp()
	}
	b, err := protocol.EncodeEnvelope(env)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(s.ctx, writeTimeout)
	defer cancel()
	if err := s.conn.Write(ctx, websocket.MessageBinary, b); err != nil {
		return fmt.Errorf("agent: write frame: %w", err)
	}
	s.seq++
	return nil
}

func (s *session) sendError(code nodev1.ErrorCode, detail string) {
	err := s.send(&nodev1.Envelope{Body: &nodev1.Envelope_Error{Error: &nodev1.Error{Code: code, Detail: detail}}})
	if err != nil {
		s.a.log.Debug("cannot send an error frame", "err", err)
	}
}

func (a *Agent) logServerError(e *nodev1.Error) {
	a.log.Warn("the gateway reported an error", "code", codeName(e.GetCode()),
		"retry_after_ms", e.GetRetryAfterMs(), "detail", e.GetDetail())
}

func (a *Agent) logNotice(n *nodev1.Notice) {
	days := make([]string, 0, len(n.GetPoints()))
	for _, d := range n.GetPoints() {
		days = append(days, fmt.Sprintf("%s uptime=%d work=%d", d.GetUtcDay(), d.GetUptimePoints(), d.GetWorkPoints()))
	}
	a.log.Info("notice from Hopbits", "kind", n.GetKind().String(), "tier", n.GetTier().String(),
		"location_level", n.GetLocationLevel(), "min_client_version", n.GetMinClientVersion(),
		"points", strings.Join(days, "; "))
}

func formatUnix(sec int64) string {
	if sec == 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

// seqTracker tracks the highest contiguous seq received from the peer.
type seqTracker struct {
	mu         sync.Mutex
	contiguous uint64
	ahead      map[uint64]bool
}

// maxSeqAhead bounds the out-of-order seqs remembered.
const maxSeqAhead = 1024

func (t *seqTracker) received(seq uint64) {
	if seq == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case seq <= t.contiguous:
	case seq == t.contiguous+1:
		t.contiguous = seq
		for t.ahead[t.contiguous+1] {
			delete(t.ahead, t.contiguous+1)
			t.contiguous++
		}
	default:
		if t.ahead == nil {
			t.ahead = make(map[uint64]bool)
		}
		if len(t.ahead) < maxSeqAhead {
			t.ahead[seq] = true
		}
	}
}

func (t *seqTracker) ack() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.contiguous
}

// samePrefixes compares two prefix lists as sets of masked prefixes.
func samePrefixes(a, b []netip.Prefix) bool {
	return slices.Equal(normPrefixes(a), normPrefixes(b))
}

func normPrefixes(ps []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if p.IsValid() {
			out = append(out, p.Masked())
		}
	}
	slices.SortFunc(out, func(x, y netip.Prefix) int {
		if c := x.Addr().Compare(y.Addr()); c != 0 {
			return c
		}
		return cmp.Compare(x.Bits(), y.Bits())
	})
	return slices.Compact(out)
}

// publicPrefixes renders the interface prefixes the server needs for its
// own-network refusal: global unicast only, so private ranges stay local.
func publicPrefixes(ps []netip.Prefix) []string {
	var out []string
	for _, p := range normPrefixes(ps) {
		a := p.Addr()
		if !a.IsGlobalUnicast() || a.IsPrivate() || sharedAddressSpace.Contains(a) {
			continue
		}
		out = append(out, p.String())
	}
	return out
}

// refusedFamilies determines which address families must be refused because the
// node's own network in that family is unknown: IPv4 whenever the gateway saw
// no IPv4 address of the node, and IPv6 in any non-host container network mode
// when the gateway saw no IPv6 address.
func refusedFamilies(mode nodev1.NetworkMode, observed []netip.Addr) (refuse4, refuse6 bool) {
	var has4, has6 bool
	for _, a := range observed {
		a = a.Unmap()
		if a.Is4() {
			has4 = true
		} else if a.Is6() {
			has6 = true
		}
	}
	nonHost := mode != nodev1.NetworkMode_NETWORK_MODE_HOST &&
		mode != nodev1.NetworkMode_NETWORK_MODE_NATIVE
	return !has4, nonHost && !has6
}

// sharedAddressSpace is 100.64.0.0/10, the CGNAT range.
var sharedAddressSpace = netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10)
