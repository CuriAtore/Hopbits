// Package anchor implements the Hopbits anchor endpoint server.
//
// An anchor accepts HTTP/1.1 calibration requests (with Connection: close so
// subdomains never coalesce) and WebSocket echo connections, observes the
// client's source IP, nonce, server-side TCP_INFO handshake RTT and TLS
// handshake RTT, logs ICMP probe nonces and arriving TTLs where permitted, and
// forwards signed ObservationBatch records through an ObservationSink.
package anchor

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/safety"
)

const (
	defaultFlushInterval  = 1 * time.Second
	defaultMaxBatchSize   = 64
	defaultQueueCapacity  = 4096
	maxNonceBytes         = 128
	maxWSEchoFrames       = 64
	maxWSEchoRecordFrames = 16
	maxWSMessageBytes     = 64 << 10
	wsSessionTimeout      = 30 * time.Second
)

// ObservationSink accepts batches of anchor observations to forward to the gateway.
type ObservationSink interface {
	SendObservations(ctx context.Context, obs []*nodev1.Observation) error
}

// Config configures an anchor Server.
type Config struct {
	// ListenAddr is the TCP address to listen on (for example ":8443" or "127.0.0.1:0").
	ListenAddr string
	// Domain restricts accepted Host headers to Domain and subdomains of Domain
	// (empty accepts any host, for local testing).
	Domain string
	// TLSConfig configures TLS 1.2+ with HTTP/1.1 forced when serving HTTPS/WSS.
	// When nil, plain HTTP/WS is served (intended for loopback tests or behind a local listener).
	TLSConfig *tls.Config
	// Sink receives batched observations (typically *agent.Agent).
	Sink ObservationSink
	// EnableICMP attempts to attach a Linux ICMP packet observer in addition to
	// kernel echo replies. Permission errors are logged and non-fatal.
	EnableICMP bool
	// FlushInterval controls how often buffered observations are sent (1 s by default).
	FlushInterval time.Duration
	// MaxBatchSize bounds one forwarded observation batch (64 by default).
	MaxBatchSize int
	// Logger receives structured logs; slog.Default() by default.
	Logger *slog.Logger
	// Now provides wall-clock time; time.Now by default.
	Now func() time.Time
}

// Server serves anchor HTTP/1.1 calibration, WebSocket echo, and ICMP observation.
type Server struct {
	cfg     Config
	log     *slog.Logger
	now     func() time.Time
	httpSrv *http.Server

	queue   chan *nodev1.Observation
	dropped atomic.Int64

	wg sync.WaitGroup
}

// New builds an anchor Server from cfg.
func New(cfg Config) (*Server, error) {
	if cfg.Sink == nil {
		return nil, errors.New("anchor: Sink is nil")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8443"
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushInterval
	}
	if cfg.MaxBatchSize <= 0 {
		cfg.MaxBatchSize = defaultMaxBatchSize
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Domain != "" {
		d, err := safety.CanonicalHost(cfg.Domain)
		if err != nil {
			return nil, fmt.Errorf("anchor: invalid domain %q: %w", cfg.Domain, err)
		}
		cfg.Domain = d
	}

	s := &Server{
		cfg:   cfg,
		log:   cfg.Logger,
		now:   cfg.Now,
		queue: make(chan *nodev1.Observation, defaultQueueCapacity),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/calibration", s.handleCalibration)
	mux.HandleFunc("/calibrate", s.handleCalibration)
	mux.HandleFunc("/ws", s.handleWSEcho)
	mux.HandleFunc("/ws_echo", s.handleWSEcho)
	mux.HandleFunc("/echo", s.handleWSEcho)
	mux.HandleFunc("/", s.handleRoot)

	var protocols http.Protocols
	protocols.SetHTTP1(true)
	var tlsCfg *tls.Config
	if cfg.TLSConfig != nil {
		tlsCfg = cfg.TLSConfig.Clone()
		if tlsCfg.MinVersion == 0 {
			tlsCfg.MinVersion = tls.VersionTLS12
		}
		tlsCfg.NextProtos = []string{"http/1.1"}
	}

	s.httpSrv = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		TLSConfig:         tlsCfg,
		Protocols:         &protocols,
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       5 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc := unwrapTrackedConn(c); tc != nil {
				return context.WithValue(ctx, connContextKey{}, tc)
			}
			return ctx
		},
		ConnState: func(c net.Conn, state http.ConnState) {
			if tc := unwrapTrackedConn(c); tc != nil {
				tc.onState(state)
			}
		},
	}
	s.httpSrv.SetKeepAlivesEnabled(false)
	return s, nil
}

// Serve runs the anchor HTTP/WS server on ln, optional ICMP listener, and the
// observation flusher until ctx cancels.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", s.cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("anchor: listen %s: %w", s.cfg.ListenAddr, err)
		}
	}
	tln := &trackedListener{Listener: ln, hasTLS: s.httpSrv.TLSConfig != nil}
	serveLn := net.Listener(tln)
	if s.httpSrv.TLSConfig != nil {
		serveLn = tls.NewListener(tln, s.httpSrv.TLSConfig)
	}

	if s.cfg.EnableICMP {
		s.listenICMP(ctx)
	}

	flusherCtx, stopFlusher := context.WithCancel(context.Background())
	var flusherWG sync.WaitGroup
	flusherWG.Add(1)
	go func() {
		defer flusherWG.Done()
		s.runFlusher(flusherCtx)
	}()

	errCh := make(chan error, 1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		err := s.httpSrv.Serve(serveLn)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = s.httpSrv.Shutdown(shutCtx)
		cancel()
		err := <-errCh
		s.wg.Wait()
		stopFlusher()
		flusherWG.Wait()
		if err != nil {
			return err
		}
		return ctx.Err()
	case err := <-errCh:
		s.wg.Wait()
		stopFlusher()
		flusherWG.Wait()
		return err
	}
}

// ListenAndServe binds cfg.ListenAddr and runs Serve until ctx cancels.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("anchor: listen %s: %w", s.cfg.ListenAddr, err)
	}
	return s.Serve(ctx, ln)
}

// DroppedObservations returns the count of observations dropped because the
// outbound buffer was full.
func (s *Server) DroppedObservations() int64 {
	return s.dropped.Load()
}

// RecordICMP queues an ICMP observation captured for source.
func (s *Server) RecordICMP(source netip.Addr, icmpNonce []byte, arrivingTTL uint32, served bool) {
	if !source.IsValid() {
		return
	}
	obs := &nodev1.Observation{
		SourceAddress:         source.Unmap().WithZone("").String(),
		IcmpNonce:             trimNonce(icmpNonce),
		ArrivingTtl:           arrivingTTL,
		ServedAndAcknowledged: served,
		ObservedUnixMs:        s.now().UnixMilli(),
	}
	s.enqueue(obs)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, "ok\n")
	}
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if websocketRequested(r) {
		s.handleWSEcho(w, r)
		return
	}
	s.handleCalibration(w, r)
}

func websocketRequested(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func (s *Server) handleCalibration(w http.ResponseWriter, r *http.Request) {
	if !s.allowHost(r.Host) {
		http.Error(w, "misdirected host", http.StatusMisdirectedRequest)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Calibration runs strictly over HTTP/1.1 with Connection: close so wildcard
	// subdomains cannot coalesce onto a single session.
	w.Header().Set("Connection", "close")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, "ok\n")
	}
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}

	nonce := extractRequestNonce(r)
	s.recordConnObservation(r, nonce, true)
}

func (s *Server) handleWSEcho(w http.ResponseWriter, r *http.Request) {
	if !s.allowHost(r.Host) {
		http.Error(w, "misdirected host", http.StatusMisdirectedRequest)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		s.log.Debug("anchor websocket accept failed", "err", err)
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(maxWSMessageBytes)

	queryNonce := extractRequestNonce(r)
	src, hsRTT, tlsRTT := connMetricsFromRequest(r)

	ctx, cancel := context.WithTimeout(r.Context(), wsSessionTimeout)
	defer cancel()

	var recordedFrames int
	for range maxWSEchoFrames {
		typ, payload, err := conn.Read(ctx)
		if err != nil {
			if len(queryNonce) > 0 && recordedFrames == 0 {
				s.enqueue(&nodev1.Observation{
					Nonce:                 queryNonce,
					SourceAddress:         src,
					HandshakeRttUs:        hsRTT,
					TlsRttUs:              tlsRTT,
					ServedAndAcknowledged: false,
					ObservedUnixMs:        s.now().UnixMilli(),
				})
			}
			return
		}
		if err := conn.Write(ctx, typ, payload); err != nil {
			return
		}
		if recordedFrames < maxWSEchoRecordFrames {
			nonce := queryNonce
			if len(payload) > 0 {
				nonce = trimNonce(payload)
			}
			s.enqueue(&nodev1.Observation{
				Nonce:                 nonce,
				SourceAddress:         src,
				HandshakeRttUs:        hsRTT,
				TlsRttUs:              tlsRTT,
				ServedAndAcknowledged: true,
				ObservedUnixMs:        s.now().UnixMilli(),
			})
			recordedFrames++
		}
	}
	_ = conn.Close(websocket.StatusNormalClosure, "echo limit reached")
}

func (s *Server) allowHost(hostHeader string) bool {
	if s.cfg.Domain == "" {
		return true
	}
	host := strings.TrimSpace(hostHeader)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	canon, err := safety.CanonicalHost(host)
	if err != nil {
		return false
	}
	return canon == s.cfg.Domain || strings.HasSuffix(canon, "."+s.cfg.Domain)
}

func (s *Server) recordConnObservation(r *http.Request, nonce []byte, served bool) {
	src, hsRTT, tlsRTT := connMetricsFromRequest(r)
	s.enqueue(&nodev1.Observation{
		Nonce:                 nonce,
		SourceAddress:         src,
		HandshakeRttUs:        hsRTT,
		TlsRttUs:              tlsRTT,
		ServedAndAcknowledged: served,
		ObservedUnixMs:        s.now().UnixMilli(),
	})
}

func connMetricsFromRequest(r *http.Request) (src string, handshakeRttUs, tlsRttUs uint32) {
	if tc, ok := r.Context().Value(connContextKey{}).(*trackedConn); ok && tc != nil {
		addr, hs, tlsRTT := tc.snapshot()
		if addr.IsValid() {
			src = addr.String()
		}
		return src, hs, tlsRTT
	}
	if addr := addrFromString(r.RemoteAddr); addr.IsValid() {
		src = addr.String()
	}
	return src, 0, 0
}

func extractRequestNonce(r *http.Request) []byte {
	for _, raw := range []string{
		r.URL.Query().Get("nonce"),
		r.Header.Get("X-Hopbits-Nonce"),
		r.Header.Get("X-Hopbits-Probe"),
	} {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if len(raw) <= maxNonceBytes*2 && len(raw)%2 == 0 {
			if b, err := hex.DecodeString(raw); err == nil && len(b) > 0 {
				return trimNonce(b)
			}
		}
		return trimNonce([]byte(raw))
	}
	return nil
}

func trimNonce(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	if len(b) > maxNonceBytes {
		b = b[:maxNonceBytes]
	}
	return append([]byte(nil), b...)
}

func (s *Server) enqueue(obs *nodev1.Observation) {
	if obs == nil {
		return
	}
	select {
	case s.queue <- obs:
	default:
		s.dropped.Add(1)
	}
}

func (s *Server) runFlusher(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()

	batch := make([]*nodev1.Observation, 0, s.cfg.MaxBatchSize)
	flush := func(sendCtx context.Context) {
		if len(batch) == 0 {
			return
		}
		if err := s.cfg.Sink.SendObservations(sendCtx, batch); err != nil {
			s.log.Debug("anchor observation flush failed", "count", len(batch), "err", err)
		}
		clear(batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			// Drain queued observations before returning.
			for {
				select {
				case obs := <-s.queue:
					batch = append(batch, obs)
					if len(batch) >= s.cfg.MaxBatchSize {
						flushCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
						flush(flushCtx)
						cancel()
					}
				default:
					flushCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					flush(flushCtx)
					cancel()
					return
				}
			}
		case obs := <-s.queue:
			batch = append(batch, obs)
			if len(batch) >= s.cfg.MaxBatchSize {
				flush(ctx)
			}
		case <-ticker.C:
			flush(ctx)
		}
	}
}

type connContextKey struct{}

type trackedListener struct {
	net.Listener
	hasTLS bool
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{
		Conn:     c,
		hasTLS:   l.hasTLS,
		remote:   addrFromNetAddr(c.RemoteAddr()),
		acceptAt: time.Now(),
	}
	if rtt, ok := readTCPRTT(c); ok {
		tc.handshakeRTT = rtt
	}
	return tc, nil
}

type trackedConn struct {
	net.Conn
	hasTLS   bool
	remote   netip.Addr
	acceptAt time.Time

	mu           sync.Mutex
	activeSeen   bool
	handshakeRTT uint32
	tlsRTT       uint32
}

func unwrapTrackedConn(c net.Conn) *trackedConn {
	type netConnUnwrapper interface {
		NetConn() net.Conn
	}
	for c != nil {
		if tc, ok := c.(*trackedConn); ok {
			return tc
		}
		u, ok := c.(netConnUnwrapper)
		if !ok {
			return nil
		}
		c = u.NetConn()
	}
	return nil
}

func (c *trackedConn) onState(st http.ConnState) {
	if st != http.StateActive {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.activeSeen {
		c.activeSeen = true
		if c.hasTLS {
			d := time.Since(c.acceptAt)
			if d > 0 {
				c.tlsRTT = uint32(min(d.Microseconds(), int64(^uint32(0))))
			}
		}
	}
	if rtt, ok := readTCPRTT(c.Conn); ok {
		c.handshakeRTT = rtt
	}
}

func (c *trackedConn) snapshot() (addr netip.Addr, handshakeRTT, tlsRTT uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rtt, ok := readTCPRTT(c.Conn); ok {
		c.handshakeRTT = rtt
	}
	return c.remote, c.handshakeRTT, c.tlsRTT
}

func addrFromNetAddr(a net.Addr) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	if ta, ok := a.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(ta.IP); ok {
			return ip.Unmap().WithZone("")
		}
	}
	if ua, ok := a.(*net.UDPAddr); ok {
		if ip, ok := netip.AddrFromSlice(ua.IP); ok {
			return ip.Unmap().WithZone("")
		}
	}
	return addrFromString(a.String())
}

func addrFromString(s string) netip.Addr {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone("")
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().WithZone("")
	}
	return netip.Addr{}
}
