package safety

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
)

// ICMP protocol numbers (IANA), inlined because x/net's iana package is
// internal.
const (
	protoICMP4 = 1
	protoICMP6 = 58
)

// echoTimeoutError is the type of ErrEchoTimeout.
type echoTimeoutError struct{}

// Error describes the timeout.
func (echoTimeoutError) Error() string { return "safety: ICMP echo timed out" }

// Timeout reports true: the echo request left the node and no reply came.
func (echoTimeoutError) Timeout() bool { return true }

// ErrEchoTimeout is returned by Pinger.Echo when an echo request was sent
// and no matching reply arrived before the per-echo timeout. Its Timeout
// method reports true, which tells modules to count a lost packet.
var ErrEchoTimeout error = echoTimeoutError{}

// lostEcho is returned for an echo request that was sent but whose wait
// ended without a reply, because the job ended or the socket failed. Like
// ErrEchoTimeout it reports Timeout, so it counts as a lost packet; every
// error from Echo without a Timeout method that reports true means the
// request never left the node.
type lostEcho struct{ cause error }

// Error describes the lost reply.
func (e *lostEcho) Error() string { return "safety: no ICMP echo reply: " + e.cause.Error() }

// Unwrap returns why the wait ended.
func (e *lostEcho) Unwrap() error { return e.cause }

// Timeout reports true: the request was sent, so it counts as lost.
func (e *lostEcho) Timeout() bool { return true }

// errPingerClosed refuses an echo on a closed pinger.
var errPingerClosed = module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "the ICMP pinger is closed")

// icmpConn is one open ICMP socket. It is created per OS.
type icmpConn interface {
	// writeEcho sends one echo request to dst.
	writeEcho(dst netip.Addr, id, seq int, payload []byte) error
	// readEcho reads one ICMP message before deadline. A non-echo message
	// returns seq -1 and a nil error so the caller keeps waiting.
	readEcho(deadline time.Time) (seq int, data []byte, ttl int, err error)
	close() error
}

// tokenBucket paces ICMP sends across all leases at a rate per second, with a
// burst of one second's worth of tokens.
type tokenBucket struct {
	now func() time.Time

	mu      sync.Mutex
	rate    float64
	tokens  float64
	last    time.Time
	started bool
}

func newTokenBucket(now func() time.Time, rate int) *tokenBucket {
	return &tokenBucket{now: now, rate: float64(rate), tokens: float64(rate)}
}

func (b *tokenBucket) setRate(rate int) {
	b.mu.Lock()
	b.rate = float64(rate)
	if b.tokens > b.rate {
		b.tokens = b.rate
	}
	b.mu.Unlock()
}

// take consumes one token, waiting until one is available or ctx ends.
func (b *tokenBucket) take(ctx context.Context) error {
	for {
		b.mu.Lock()
		now := b.now()
		if !b.started {
			b.last = now
			b.started = true
		}
		if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
			b.tokens += elapsed * b.rate
			if b.tokens > b.rate {
				b.tokens = b.rate
			}
			b.last = now
		}
		if b.rate <= 0 {
			b.mu.Unlock()
			return errors.New("safety: ICMP rate is zero")
		}
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}
		need := (1 - b.tokens) / b.rate
		b.mu.Unlock()
		wait := time.Duration(need * float64(time.Second))
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Echo payloads, matching and the reader's polling.
const (
	// echoNonceLen is the random part of each echo payload that ties a
	// reply to its request.
	echoNonceLen = 16
	// echoNonceOffset is where the nonce starts: after the probe
	// description URI and the 0x00 octet that ends it (RFC 9511 section 4).
	echoNonceOffset = len(ProbeDescriptionURI) + 1
	// readerPoll bounds one socket read, so the reader notices when no echo
	// waits any more and stops.
	readerPoll = 200 * time.Millisecond
)

// echoPayload is an echo request's data: the RFC 9511 probe-description
// URI at the start, a 0x00 octet ending it, then the nonce.
func echoPayload(nonce []byte) []byte {
	b := make([]byte, 0, echoNonceOffset+len(nonce))
	b = append(b, ProbeDescriptionURI...)
	b = append(b, 0)
	return append(b, nonce...)
}

// echoBudget is a lease's cap on echo requests. Every pinger the lease
// hands out draws from it, so asking for another pinger never resets it.
type echoBudget struct {
	max int

	mu   sync.Mutex
	sent int
}

// take reserves one echo request; it reports false once the cap is used.
func (b *echoBudget) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sent >= b.max {
		return false
	}
	b.sent++
	return true
}

// refund returns a reserved echo request that never left the node.
func (b *echoBudget) refund() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sent > 0 {
		b.sent--
	}
}

// icmpPinger is an ICMP echo sender bound to one address, under the shared
// rate cap and its lease's packet cap. Echo is safe for concurrent use with
// distinct sequence numbers, as ping overlaps its waits: one reader
// goroutine owns the socket's reads while any echo waits and hands each
// reply to the echo with its sequence number and nonce, so overlapping
// echoes never take each other's replies or each other's read deadlines.
type icmpPinger struct {
	g      *Guard
	ep     icmpConn
	dst    netip.Addr
	id     int
	budget *echoBudget

	mu      sync.Mutex
	closed  bool
	waiting map[int]*echoWait
	// reading is true while a reader goroutine runs; readerDone closes when
	// the latest one has stopped.
	reading    bool
	readerDone chan struct{}
}

// echoWait is one echo request waiting for its reply.
type echoWait struct {
	nonce []byte
	// arrived holds at most one value and is never closed.
	arrived chan echoArrival
}

// echoArrival is what the reader saw for one echo request.
type echoArrival struct {
	at  time.Time
	ttl int
	err error
}

// newPinger opens an ICMP socket for dst and returns a pinger drawing on
// budget, or an error when ICMP is unavailable on this host.
func (g *Guard) newPinger(dst netip.Addr, budget *echoBudget) (*icmpPinger, error) {
	ep, err := g.dialICMP(dst)
	if err != nil {
		return nil, fmt.Errorf("safety: open ICMP socket: %w", err)
	}
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := int(idb[0])<<8 | int(idb[1])
	return &icmpPinger{g: g, ep: ep, dst: dst, id: id, budget: budget}, nil
}

// Echo sends one echo request and waits for its reply, the timeout or ctx.
// Several echoes may wait at once if their sequence numbers differ.
//
// What Echo returns tells a module whether a packet left the node: a nil
// error is a reply, an error whose Timeout method reports true is a request
// sent and lost, and any other error means nothing was sent: a
// *module.Refusal for the packet cap, the rate cap or the address rules,
// or the socket's error when the send failed.
func (p *icmpPinger) Echo(ctx context.Context, seq uint16, timeout time.Duration) (module.EchoReply, error) {
	nonce := make([]byte, echoNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return module.EchoReply{}, fmt.Errorf("safety: draw echo nonce: %w", err)
	}
	key := int(seq)
	w := &echoWait{nonce: nonce, arrived: make(chan echoArrival, 1)}

	p.mu.Lock()
	switch {
	case p.closed:
		p.mu.Unlock()
		return module.EchoReply{}, errPingerClosed
	case p.waiting[key] != nil:
		p.mu.Unlock()
		return module.EchoReply{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "echo %d is already waiting for its reply", seq)
	case !p.budget.take():
		p.mu.Unlock()
		return module.EchoReply{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY, "ping packet cap %d reached", p.budget.max)
	}
	if p.waiting == nil {
		p.waiting = make(map[int]*echoWait)
	}
	p.waiting[key] = w
	p.startReaderLocked()
	p.mu.Unlock()
	defer p.forget(key, w)

	if err := p.g.icmp.take(ctx); err != nil {
		p.budget.refund()
		return module.EchoReply{}, module.Refuse(nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED, "no ICMP send slot under the rate cap: %v", err)
	}
	if err := p.g.recheckDial(p.dst); err != nil {
		p.budget.refund()
		return module.EchoReply{}, err
	}
	start := time.Now()
	if err := p.ep.writeEcho(p.dst, p.id, key, echoPayload(nonce)); err != nil {
		p.budget.refund()
		return module.EchoReply{}, fmt.Errorf("safety: send echo %d: %w", seq, err)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case a := <-w.arrived:
		if a.err != nil {
			return module.EchoReply{}, &lostEcho{cause: a.err}
		}
		return module.EchoReply{RTT: a.at.Sub(start), TTL: a.ttl}, nil
	case <-timer.C:
		return module.EchoReply{}, ErrEchoTimeout
	case <-ctx.Done():
		return module.EchoReply{}, &lostEcho{cause: ctx.Err()}
	}
}

// forget drops an echo's waiter once it has its answer or gives up.
func (p *icmpPinger) forget(key int, w *echoWait) {
	p.mu.Lock()
	if p.waiting[key] == w {
		delete(p.waiting, key)
	}
	p.mu.Unlock()
}

// startReaderLocked starts the reader goroutine unless one runs. p.mu must
// be held.
func (p *icmpPinger) startReaderLocked() {
	if p.reading {
		return
	}
	p.reading = true
	done := make(chan struct{})
	p.readerDone = done
	go p.readLoop(done)
}

// readLoop reads the socket and hands each echo reply to the echo waiting
// for its sequence number and nonce. It stops once no echo waits, or when
// the socket fails or closes, which fails the echoes still waiting.
func (p *icmpPinger) readLoop(done chan struct{}) {
	defer close(done)
	for {
		seq, data, ttl, err := p.ep.readEcho(time.Now().Add(readerPoll))
		at := time.Now()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				p.mu.Lock()
				idle := len(p.waiting) == 0 || p.closed
				if idle {
					p.reading = false
				}
				p.mu.Unlock()
				if idle {
					return
				}
				continue
			}
			p.mu.Lock()
			p.reading = false
			for k, w := range p.waiting {
				w.arrived <- echoArrival{err: fmt.Errorf("safety: read ICMP reply: %w", err)}
				delete(p.waiting, k)
			}
			p.mu.Unlock()
			return
		}
		if seq < 0 || len(data) < echoNonceOffset+echoNonceLen {
			continue
		}
		p.mu.Lock()
		if w := p.waiting[seq]; w != nil && bytes.Equal(data[echoNonceOffset:echoNonceOffset+echoNonceLen], w.nonce) {
			delete(p.waiting, seq)
			w.arrived <- echoArrival{at: at, ttl: ttl}
		}
		p.mu.Unlock()
	}
}

// TimestampSource reports that RTTs are timed with the userspace monotonic
// clock.
func (p *icmpPinger) TimestampSource() nodev1.TimestampSource {
	return nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO
}

// Close closes the ICMP socket and waits for the reader to stop; echoes
// still waiting fail. Close is idempotent.
func (p *icmpPinger) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	done := p.readerDone
	p.mu.Unlock()
	var err error
	if p.ep != nil {
		err = p.ep.close()
	}
	if done != nil {
		<-done
	}
	return err
}
