//go:build hopbits_unsafe_testing

package safety

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
)

// TestTestHooksLoopback checks that, under the unsafe testing tag, a
// test-allowed prefix and port let a job reach a loopback server and that the
// bytes are charged to the daily traffic counter.
func TestTestHooksLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind loopback: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}(c)
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	clk := newClock()
	g := NewGuard(Config{
		Caps:              Caps{JobsPerMinute: 100, MaxConcurrency: 10, DailyTrafficBytes: 1 << 20, MaxPingPackets: 16},
		Now:               clk.now,
		Resolver:          &fakeResolver{},
		TestAllowPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		TestAllowPorts:    []uint16{port},
	})

	job := mkJob("127.0.0.1", port, v4, pinned("127.0.0.1"))
	needs := module.Needs{Transport: module.TransportTCP, Ports: []uint16{port}}
	lease, err := g.Admit(context.Background(), job, needs)
	if err != nil {
		t.Fatalf("admit loopback: %v", err)
	}
	defer lease.Close()

	conn, err := lease.DialTCP(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	msg := []byte("hello hopbits probe")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = conn.Close()

	g.mu.Lock()
	used := g.trafficUsed
	g.mu.Unlock()
	if used < int64(2*len(msg)) {
		t.Fatalf("traffic counted %d, want >= %d", used, 2*len(msg))
	}
}

// TestTestHooksScoped checks that the loopback exemption applies only to a
// test-allowed prefix, even under the unsafe tag.
func TestTestHooksScoped(t *testing.T) {
	clk := newClock()
	g := NewGuard(Config{Caps: AgentCaps(), Now: clk.now, Resolver: &fakeResolver{}})
	_, err := g.Admit(context.Background(), mkJob("127.0.0.1", 443, v4, pinned("127.0.0.1")), tcp443)
	wantCode(t, err, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL)
}

// TestTestHooksNoPanic checks that NewGuard accepts the Test fields under the
// unsafe tag.
func TestTestHooksNoPanic(t *testing.T) {
	g := NewGuard(Config{
		Caps:           AgentCaps(),
		TestAllowPorts: []uint16{12345},
	})
	if g == nil {
		t.Fatal("nil guard")
	}
}

// TestTestHooksPortBypass checks that a test-allowed port is admitted for any
// kind, even one that is otherwise unlisted.
func TestTestHooksPortBypass(t *testing.T) {
	clk := newClock()
	g := NewGuard(Config{
		Caps:              AgentCaps(),
		Now:               clk.now,
		Resolver:          &fakeResolver{},
		TestAllowPrefixes: []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")},
		TestAllowPorts:    []uint16{9999},
	})
	lease, err := g.Admit(context.Background(), mkJob("8.8.8.8", 9999, v4, pinned("8.8.8.8")),
		module.Needs{Transport: module.TransportTCP, Ports: []uint16{443}})
	if err != nil {
		t.Fatalf("test-allowed port should be admitted: %v", err)
	}
	lease.Close()
}
