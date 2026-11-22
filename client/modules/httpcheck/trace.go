package httpcheck

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http/httptrace"
	"sync"
	"time"

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/modules/internal/kit"
)

// Errors the dialer returns to the transport.
var (
	errSecondDial = errors.New("httpcheck: a job opens one connection")
	errJobOver    = errors.New("httpcheck: the job is over")
)

// dialer connects the transport to the job's target. It ignores the
// address the transport asks for and calls TargetNet.DialTCP, opens at
// most one connection per job, and times the connect itself, because
// httptrace reports no connect events for a custom DialContext.
type dialer struct {
	tn module.TargetNet
	// job is the request's context; a dial never outlives it.
	job context.Context
	now func() time.Time

	mu          sync.Mutex
	used        bool
	closed      bool
	conn        net.Conn
	start, done time.Time
	err         error
	wg          sync.WaitGroup
}

// dial is the transport's DialContext.
func (d *dialer) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	d.mu.Lock()
	switch {
	case d.closed:
		d.mu.Unlock()
		return nil, errJobOver
	case d.used:
		d.mu.Unlock()
		return nil, errSecondDial
	}
	d.used = true
	d.wg.Add(1)
	d.mu.Unlock()
	defer d.wg.Done()

	// The transport may detach its dial from the request; end it with the
	// job's request either way.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(d.job, cancel)
	defer stop()

	start := d.now()
	conn, err := d.tn.DialTCP(ctx)
	done := d.now()

	d.mu.Lock()
	defer d.mu.Unlock()
	d.start, d.done, d.err = start, done, err
	if err != nil {
		return nil, err
	}
	if d.closed {
		conn.Close()
		return nil, errJobOver
	}
	d.conn = conn
	return conn, nil
}

// close ends the job's connection and waits for a dial in progress. The
// request's context must already be done, so that the dial returns.
func (d *dialer) close() {
	d.mu.Lock()
	d.closed = true
	conn := d.conn
	d.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	d.wg.Wait()
}

// failed returns the dial's error, if a dial ran and failed.
func (d *dialer) failed() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

// times returns when the dial started and finished.
func (d *dialer) times() (start, done time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.start, d.done
}

// timeline records when the request's phases happened. The transport
// calls its hooks from its own goroutines.
type timeline struct {
	now func() time.Time

	mu                sync.Mutex
	tlsStart, tlsDone time.Time
	tlsErr            error
	wrote, firstByte  time.Time
	reused            bool
}

// trace returns the httptrace hooks that fill the timeline.
func (tl *timeline) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			tl.mu.Lock()
			defer tl.mu.Unlock()
			tl.reused = tl.reused || info.Reused
		},
		TLSHandshakeStart: func() { tl.mark(&tl.tlsStart) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			tl.mark(&tl.tlsDone)
			if err != nil {
				tl.mu.Lock()
				defer tl.mu.Unlock()
				tl.tlsErr = err
			}
		},
		// WroteHeaders fires before the request is flushed, so it always
		// precedes the response; WroteRequest fires after the flush and a
		// fast response can beat it.
		WroteHeaders:         func() { tl.mark(&tl.wrote) },
		GotFirstResponseByte: func() { tl.mark(&tl.firstByte) },
	}
}

// mark sets *t to now, once.
func (tl *timeline) mark(t *time.Time) {
	now := tl.now()
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if t.IsZero() {
		*t = now
	}
}

// tlsFailed reports whether a TLS handshake ran and failed.
func (tl *timeline) tlsFailed() bool {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	return tl.tlsErr != nil
}

// reusedConn reports whether the transport said it reused a connection.
func (tl *timeline) reusedConn() bool {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	return tl.reused
}

// phases computes the request's timing phases in microseconds:
//   - dns_us stays 0, because the node never resolves the target;
//   - connect_us is the TCP connect;
//   - tls_us is the TLS handshake, for HTTPS;
//   - first_byte_us runs from the request headers being written to the
//     first response byte;
//   - total_us runs from the start of the request to the end of the
//     body read.
func (tl *timeline) phases(d *dialer, t0, end time.Time) *measurev1.HttpPhases {
	dialStart, dialDone := d.times()
	tl.mu.Lock()
	defer tl.mu.Unlock()
	ph := &measurev1.HttpPhases{
		ConnectUs: kit.Micros(since(dialStart, dialDone)),
		TlsUs:     kit.Micros(since(tl.tlsStart, tl.tlsDone)),
		TotalUs:   kit.Micros(since(t0, end)),
	}
	sent := tl.wrote
	if sent.IsZero() {
		sent = dialDone
		if !tl.tlsDone.IsZero() {
			sent = tl.tlsDone
		}
	}
	ph.FirstByteUs = kit.Micros(since(sent, tl.firstByte))
	return ph
}

// since is to minus from, or 0 when either time is missing.
func since(from, to time.Time) time.Duration {
	if from.IsZero() || to.IsZero() {
		return 0
	}
	return to.Sub(from)
}
