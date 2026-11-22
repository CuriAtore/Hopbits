package safety

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
)

// fakeEcho is one ICMP message the fake socket delivers to a read.
type fakeEcho struct {
	seq  int
	data []byte
	ttl  int
}

// fakeTimeout is the error a read returns when its deadline passes.
type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "fake: i/o timeout" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

var _ net.Error = fakeTimeout{}

// fakeICMPConn is an icmpConn whose replies the test delivers by hand.
type fakeICMPConn struct {
	written chan int
	replies chan fakeEcho
	closed  chan struct{}
	once    sync.Once

	mu       sync.Mutex
	payloads map[int][]byte
	readers  int
	maxRead  int
	writeErr error
}

func newFakeICMPConn() *fakeICMPConn {
	return &fakeICMPConn{
		written:  make(chan int, 16),
		replies:  make(chan fakeEcho, 16),
		closed:   make(chan struct{}),
		payloads: make(map[int][]byte),
	}
}

func (f *fakeICMPConn) writeEcho(_ netip.Addr, _, seq int, payload []byte) error {
	f.mu.Lock()
	if err := f.writeErr; err != nil {
		f.mu.Unlock()
		return err
	}
	f.payloads[seq] = append([]byte(nil), payload...)
	f.mu.Unlock()
	f.written <- seq
	return nil
}

func (f *fakeICMPConn) readEcho(deadline time.Time) (int, []byte, int, error) {
	f.mu.Lock()
	f.readers++
	f.maxRead = max(f.maxRead, f.readers)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.readers--
		f.mu.Unlock()
	}()
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case r := <-f.replies:
		return r.seq, r.data, r.ttl, nil
	case <-t.C:
		return 0, nil, 0, fakeTimeout{}
	case <-f.closed:
		return 0, nil, 0, net.ErrClosed
	}
}

func (f *fakeICMPConn) close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

// payload returns what was sent for seq.
func (f *fakeICMPConn) payload(seq int) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.payloads[seq]
}

// concurrentReads reports the most reads that ever ran at once.
func (f *fakeICMPConn) concurrentReads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxRead
}

// waitWritten waits until n echoes have been sent.
func waitWritten(t *testing.T, f *fakeICMPConn, n int) {
	t.Helper()
	for range n {
		select {
		case <-f.written:
		case <-time.After(5 * time.Second):
			t.Fatal("echo was not sent")
		}
	}
}

// waitWrittenSeq waits until the echo with sequence number seq has been
// sent, skipping notifications of earlier echoes.
func waitWrittenSeq(t *testing.T, f *fakeICMPConn, seq int) {
	t.Helper()
	for {
		select {
		case got := <-f.written:
			if got == seq {
				return
			}
		case <-time.After(5 * time.Second):
			t.Errorf("echo %d was not sent", seq)
			return
		}
	}
}

// echoResult is what one Echo call returned.
type echoResult struct {
	reply module.EchoReply
	err   error
}

func TestPingerOverlappingEchoesGetTheirOwnReplies(t *testing.T) {
	g, _ := newGuard(t, AgentCaps(), nil, nil)
	conn := newFakeICMPConn()
	p := &icmpPinger{g: g, ep: conn, dst: netip.MustParseAddr("8.8.8.8"), id: 7, budget: &echoBudget{max: 16}}

	results := make(map[int]chan echoResult)
	for _, seq := range []int{1, 2} {
		ch := make(chan echoResult, 1)
		results[seq] = ch
		go func() {
			r, err := p.Echo(context.Background(), uint16(seq), 5*time.Second)
			ch <- echoResult{reply: r, err: err}
		}()
	}
	waitWritten(t, conn, 2)

	// Replies arrive in reverse order, after noise a matcher must skip: a
	// non-echo message, a short payload and a reply to seq 1 with another
	// nonce, as a raw socket sees replies meant for other pingers.
	conn.replies <- fakeEcho{seq: -1}
	conn.replies <- fakeEcho{seq: 1, data: []byte("short")}
	conn.replies <- fakeEcho{seq: 1, data: make([]byte, echoNonceLen+4), ttl: 99}
	conn.replies <- fakeEcho{seq: 2, data: conn.payload(2), ttl: 62}
	conn.replies <- fakeEcho{seq: 1, data: conn.payload(1), ttl: 61}

	for seq, want := range map[int]int{1: 61, 2: 62} {
		select {
		case r := <-results[seq]:
			if r.err != nil {
				t.Fatalf("echo %d: %v", seq, r.err)
			}
			if r.reply.TTL != want {
				t.Fatalf("echo %d got the reply with TTL %d, want %d", seq, r.reply.TTL, want)
			}
			if r.reply.RTT < 0 {
				t.Fatalf("echo %d has a negative round trip %v", seq, r.reply.RTT)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("echo %d never returned", seq)
		}
	}
	if n := conn.concurrentReads(); n != 1 {
		t.Fatalf("%d reads ran at once on one socket, want 1", n)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := p.Echo(context.Background(), 3, time.Second); !errors.Is(err, errPingerClosed) {
		t.Fatalf("Echo after Close: %v, want errPingerClosed", err)
	}
}

func TestPingerTimeoutAndIdleReader(t *testing.T) {
	g, _ := newGuard(t, AgentCaps(), nil, nil)
	conn := newFakeICMPConn()
	p := &icmpPinger{g: g, ep: conn, dst: netip.MustParseAddr("8.8.8.8"), id: 7, budget: &echoBudget{max: 16}}
	defer p.Close()

	if _, err := p.Echo(context.Background(), 1, 20*time.Millisecond); !errors.Is(err, ErrEchoTimeout) {
		t.Fatalf("lost echo: %v, want ErrEchoTimeout", err)
	}
	// With nothing waiting, the reader stops after one poll.
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.mu.Lock()
		reading, waiting := p.reading, len(p.waiting)
		p.mu.Unlock()
		if waiting != 0 {
			t.Fatalf("%d waiters left after the echo returned", waiting)
		}
		if !reading {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reader still running with nothing to wait for")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A late reply to the lost echo is ignored, and a new echo starts a
	// new reader.
	go func() {
		waitWrittenSeq(t, conn, 2)
		conn.replies <- fakeEcho{seq: 1, data: conn.payload(1), ttl: 50}
		conn.replies <- fakeEcho{seq: 2, data: conn.payload(2), ttl: 51}
	}()
	r, err := p.Echo(context.Background(), 2, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if r.TTL != 51 {
		t.Fatalf("got TTL %d, want 51", r.TTL)
	}
}

func TestPingerRefusesADuplicateSequenceNumber(t *testing.T) {
	g, _ := newGuard(t, AgentCaps(), nil, nil)
	conn := newFakeICMPConn()
	p := &icmpPinger{g: g, ep: conn, dst: netip.MustParseAddr("8.8.8.8"), id: 7, budget: &echoBudget{max: 16}}
	defer p.Close()

	first := make(chan error, 1)
	go func() {
		_, err := p.Echo(context.Background(), 5, 5*time.Second)
		first <- err
	}()
	waitWritten(t, conn, 1)
	if _, err := p.Echo(context.Background(), 5, time.Second); err == nil {
		t.Fatal("a second echo with a waiting sequence number was sent")
	}
	conn.replies <- fakeEcho{seq: 5, data: conn.payload(5), ttl: 60}
	if err := <-first; err != nil {
		t.Fatalf("first echo: %v", err)
	}
}

func TestPingerCloseFailsWaitingEchoes(t *testing.T) {
	g, _ := newGuard(t, AgentCaps(), nil, nil)
	conn := newFakeICMPConn()
	p := &icmpPinger{g: g, ep: conn, dst: netip.MustParseAddr("8.8.8.8"), id: 7, budget: &echoBudget{max: 16}}

	done := make(chan error, 1)
	go func() {
		_, err := p.Echo(context.Background(), 1, time.Minute)
		done <- err
	}()
	waitWritten(t, conn, 1)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("echo succeeded after Close")
		}
		// The request had left: it counts as lost, not as unsent.
		var lost interface{ Timeout() bool }
		if !errors.As(err, &lost) || !lost.Timeout() {
			t.Fatalf("echo cut off by Close: %v, want a lost-reply error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("echo still waiting after Close")
	}
}

func TestEchoPayloadCarriesTheProbeURIFirst(t *testing.T) {
	g, _ := newGuard(t, AgentCaps(), nil, nil)
	conn := newFakeICMPConn()
	p := &icmpPinger{g: g, ep: conn, dst: netip.MustParseAddr("8.8.8.8"), id: 7, budget: &echoBudget{max: 16}}
	defer p.Close()
	if _, err := p.Echo(context.Background(), 1, time.Millisecond); !errors.Is(err, ErrEchoTimeout) {
		t.Fatalf("lost echo: %v", err)
	}
	got := conn.payload(1)
	// RFC 9511 section 4: the URI starts the payload and a 0x00 octet ends it.
	if !bytes.HasPrefix(got, []byte(ProbeDescriptionURI+"\x00")) || len(got) != len(ProbeDescriptionURI)+1+echoNonceLen {
		t.Fatalf("payload %q", got)
	}
}

func TestEchoErrorsTellSentFromUnsent(t *testing.T) {
	lost := func(err error) bool {
		var t interface{ Timeout() bool }
		return errors.As(err, &t) && t.Timeout()
	}
	t.Run("lost reply", func(t *testing.T) {
		g, _ := newGuard(t, AgentCaps(), nil, nil)
		p := &icmpPinger{g: g, ep: newFakeICMPConn(), dst: netip.MustParseAddr("8.8.8.8"), id: 7, budget: &echoBudget{max: 16}}
		defer p.Close()
		_, err := p.Echo(context.Background(), 1, time.Millisecond)
		if !lost(err) {
			t.Fatalf("%v does not count as lost", err)
		}
	})
	t.Run("job ends after the send", func(t *testing.T) {
		g, _ := newGuard(t, AgentCaps(), nil, nil)
		conn := newFakeICMPConn()
		p := &icmpPinger{g: g, ep: conn, dst: netip.MustParseAddr("8.8.8.8"), id: 7, budget: &echoBudget{max: 16}}
		defer p.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			select {
			case <-conn.written:
				cancel()
			case <-ctx.Done():
			}
		}()
		_, err := p.Echo(ctx, 1, time.Minute)
		if !lost(err) || !errors.Is(err, context.Canceled) {
			t.Fatalf("%v: want a lost reply caused by the cancel", err)
		}
	})
	t.Run("send fails", func(t *testing.T) {
		g, _ := newGuard(t, AgentCaps(), nil, nil)
		conn := newFakeICMPConn()
		conn.writeErr = errors.New("sendto: operation not permitted")
		b := &echoBudget{max: 1}
		p := &icmpPinger{g: g, ep: conn, dst: netip.MustParseAddr("8.8.8.8"), id: 7, budget: b}
		defer p.Close()
		for range 2 {
			_, err := p.Echo(context.Background(), 1, time.Millisecond)
			if err == nil || lost(err) {
				t.Fatalf("a failed send: %v", err)
			}
		}
		if b.sent != 0 {
			t.Fatalf("failed sends used %d of the packet cap", b.sent)
		}
	})
	t.Run("rate cap", func(t *testing.T) {
		caps := AgentCaps()
		caps.ICMPPacketsPerSecond = 1
		g, _ := newGuard(t, caps, nil, nil)
		conn := newFakeICMPConn()
		b := &echoBudget{max: 16}
		p := &icmpPinger{g: g, ep: conn, dst: netip.MustParseAddr("8.8.8.8"), id: 7, budget: b}
		defer p.Close()
		if _, err := p.Echo(context.Background(), 1, time.Millisecond); !lost(err) {
			t.Fatalf("first echo: %v", err)
		}
		// The bucket is empty and the guard's clock stands still: the job's
		// deadline ends the wait for a send slot.
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := p.Echo(ctx, 2, time.Millisecond)
		wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED)
		if b.sent != 1 || len(conn.written) != 1 {
			t.Fatalf("budget %d, %d echoes written; want 1 and 1", b.sent, len(conn.written))
		}
	})
}
