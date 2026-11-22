package kit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
)

func TestStats(t *testing.T) {
	cases := []struct {
		in          []uint32
		lo, med, hi uint32
	}{
		{nil, 0, 0, 0},
		{[]uint32{5}, 5, 5, 5},
		{[]uint32{3, 1, 2}, 1, 2, 3},
		{[]uint32{4, 1, 3, 2}, 1, 2, 4},
		{[]uint32{400, 200}, 200, 300, 400},
		{[]uint32{math.MaxUint32, math.MaxUint32}, math.MaxUint32, math.MaxUint32, math.MaxUint32},
	}
	for _, tc := range cases {
		in := slices.Clone(tc.in)
		lo, med, hi := Stats(in)
		if lo != tc.lo || med != tc.med || hi != tc.hi {
			t.Errorf("Stats(%v) = %d %d %d, want %d %d %d", tc.in, lo, med, hi, tc.lo, tc.med, tc.hi)
		}
		if !slices.Equal(in, tc.in) {
			t.Errorf("Stats reordered its input: %v", in)
		}
	}
}

func TestMicros(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want uint32
	}{
		{-time.Second, 0},
		{0, 0},
		{999 * time.Nanosecond, 0},
		{1500 * time.Nanosecond, 1},
		{2 * time.Second, 2_000_000},
		{100 * time.Hour, math.MaxUint32},
	}
	for _, tc := range cases {
		if got := Micros(tc.in); got != tc.want {
			t.Errorf("Micros(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
	if SampleMicros(0) != 1 || SampleMicros(5*time.Microsecond) != 5 {
		t.Fatal("SampleMicros must be at least 1")
	}
}

func TestCheckWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cases := []struct {
		name             string
		issued, deadline time.Time
		need             time.Duration
		ok               bool
	}{
		{"exact fit", now, now.Add(5 * time.Second), 5 * time.Second, true},
		{"short", now, now.Add(5 * time.Second), 6 * time.Second, false},
		{"no deadline", now, time.Time{}, time.Second, false},
		{"no issue time uses now", time.Time{}, now.Add(3 * time.Second), 3 * time.Second, true},
		{"no issue time, short", time.Time{}, now.Add(3 * time.Second), 4 * time.Second, false},
		{"issued late but signed with room", now.Add(-time.Minute), now.Add(time.Second), 30 * time.Second, true},
	}
	for _, tc := range cases {
		err := CheckWindow(&module.Job{Issued: tc.issued, Deadline: tc.deadline}, tc.need, now)
		if (err == nil) != tc.ok {
			t.Errorf("%s: got %v", tc.name, err)
		}
		if err != nil && module.CodeOf(err) != nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS {
			t.Errorf("%s: code %v", tc.name, module.CodeOf(err))
		}
	}
}

func TestWithDeadline(t *testing.T) {
	ctx, cancel := WithDeadline(context.Background(), &module.Job{})
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("a job without a deadline got one")
	}
	d := time.Now().Add(time.Minute)
	ctx2, cancel2 := WithDeadline(context.Background(), &module.Job{Deadline: d})
	defer cancel2()
	if got, ok := ctx2.Deadline(); !ok || !got.Equal(d) {
		t.Fatalf("deadline %v %v", got, ok)
	}
}

// refusedDial returns the error of a real connect to a closed loopback port.
func refusedDial(t *testing.T) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		c.Close()
		t.Skip("something answered on a closed port")
	}
	return err
}

func TestConnectOutcome(t *testing.T) {
	refused := refusedDial(t)
	if _, ok := errno(refused); !ok && runtime.GOOS != "js" && runtime.GOOS != "wasip1" {
		t.Fatalf("no errno found in %v", refused)
	}
	cases := []struct {
		name    string
		err     error
		outcome nodev1.Outcome
		code    nodev1.ErrorCode
	}{
		{"refused by the OS", refused, nodev1.Outcome_OUTCOME_REFUSED, 0},
		{"refused, wrapped", fmt.Errorf("dial: %w", refused), nodev1.Outcome_OUTCOME_REFUSED, 0},
		{"refused, joined", errors.Join(errors.New("first"), refused), nodev1.Outcome_OUTCOME_REFUSED, 0},
		{"deadline", context.DeadlineExceeded, nodev1.Outcome_OUTCOME_TIMEOUT, 0},
		{"net timeout", &net.OpError{Op: "dial", Net: "tcp", Err: context.DeadlineExceeded}, nodev1.Outcome_OUTCOME_TIMEOUT, 0},
		{"cancelled", &net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled}, nodev1.Outcome_OUTCOME_CANCELLED, 0},
		{"denied locally", module.Refuse(nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL, "deny range"),
			nodev1.Outcome_OUTCOME_DENIED_LOCAL, nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL},
		{"rate limited, wrapped", fmt.Errorf("guard: %w", module.Refuse(nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED, "cap")),
			nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE, nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED},
		{"anything else", errors.New("no route to host"), nodev1.Outcome_OUTCOME_UNREACHABLE, 0},
		{"not permitted", fmt.Errorf("send: %w", &net.OpError{Op: "write", Net: "ip4:icmp", Err: os.NewSyscallError("sendto", permErrno())}),
			nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY},
	}
	for _, tc := range cases {
		o, code := ConnectOutcome(tc.err)
		if o != tc.outcome || code != tc.code {
			t.Errorf("%s: got %v %v, want %v %v", tc.name, o, code, tc.outcome, tc.code)
		}
	}
}

// permErrno is the operating system's "not permitted" error for a send.
func permErrno() error {
	if runtime.GOOS == "windows" {
		return syscall.Errno(10013) // WSAEACCES
	}
	return syscall.Errno(1) // EPERM
}

// lostErr is a lost echo reply as the safety layer reports one.
type lostErr struct{}

func (lostErr) Error() string { return "no reply" }
func (lostErr) Timeout() bool { return true }

func TestLostReply(t *testing.T) {
	cases := []struct {
		name string
		err  error
		lost bool
	}{
		{"timeout", lostErr{}, true},
		{"wrapped timeout", fmt.Errorf("echo: %w", lostErr{}), true},
		{"deadline", context.DeadlineExceeded, true},
		{"refusal", module.Refuse(nodev1.ErrorCode_ERROR_CODE_RATE_LIMITED, "cap"), false},
		{"failed send", &net.OpError{Op: "write", Net: "ip4:icmp", Err: os.NewSyscallError("sendto", permErrno())}, false},
		{"plain", errors.New("closed"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		if got := LostReply(tc.err); got != tc.lost {
			t.Errorf("%s: LostReply = %v, want %v", tc.name, got, tc.lost)
		}
	}
	if IsBlocked(nil) || IsBlocked(errors.New("permission denied")) {
		t.Fatal("an error without an errno counts as blocked")
	}
	if r, w := permErrnos("linux"), permErrnos("windows"); !slices.Contains(r, 1) || !slices.Contains(w, 10013) || permErrnos("plan9") != nil {
		t.Fatalf("permission errnos %v %v", r, w)
	}
}

func TestErrnoTables(t *testing.T) {
	cases := []struct {
		goos              string
		refused, timedOut uint64
	}{
		{"linux", 111, 110},
		{"darwin", 61, 60},
		{"freebsd", 61, 60},
		{"windows", 10061, 10060},
	}
	for _, tc := range cases {
		refused, timedOut := connErrnos(tc.goos)
		if !slices.Contains(refused, tc.refused) || !slices.Contains(timedOut, tc.timedOut) {
			t.Errorf("%s: %v %v", tc.goos, refused, timedOut)
		}
	}
	if r, to := connErrnos("plan9"); r != nil || to != nil {
		t.Fatal("unknown platform has errnos")
	}
	if IsRefused(errors.New("connection refused")) != true || IsRefused(errors.New("reset")) {
		t.Fatal("text fallback wrong")
	}
	if IsTimeout(nil) || IsRefused(nil) {
		t.Fatal("nil error classified")
	}
}

func TestBlocked(t *testing.T) {
	r := Blocked(Invalid("too many"))
	if r.Outcome != nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE || r.Error != nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS ||
		r.TSSource != nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE || r.Data != nil {
		t.Fatalf("result %+v", r)
	}
	if r := Blocked(errors.New("plain")); r.Error != nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY {
		t.Fatalf("plain error code %v", r.Error)
	}
}

func TestTargetHelpers(t *testing.T) {
	if HasGrant(nil) || HasGrant(&nodev1.Target{}) || HasGrant(&nodev1.Target{Grant: &nodev1.SignedTargetGrant{Body: []byte("b")}}) {
		t.Fatal("grant without a signature counted")
	}
	if !HasGrant(&nodev1.Target{Grant: &nodev1.SignedTargetGrant{Body: []byte("b"), Sig: []byte("s")}}) {
		t.Fatal("grant missed")
	}
	for in, want := range map[uint32]bool{0: false, 1: true, 443: true, 65535: true, 65536: false} {
		if _, ok := Port(&nodev1.Target{Port: in}); ok != want {
			t.Errorf("Port(%d) ok = %v", in, ok)
		}
	}
	if _, ok := Port(nil); ok {
		t.Fatal("nil target has a port")
	}
}

func TestQualifiers(t *testing.T) {
	cases := map[nodev1.TimestampSource]string{
		nodev1.TimestampSource_TIMESTAMP_SOURCE_KERNEL_RX:        "ts.kernel",
		nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO:   "ts.user",
		nodev1.TimestampSource_TIMESTAMP_SOURCE_OS_API_MS:        "ts.osms",
		nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE:             "",
		nodev1.TimestampSource_TIMESTAMP_SOURCE_UNSPECIFIED:      "",
		nodev1.TimestampSource_TIMESTAMP_SOURCE_BROWSER_NETSTACK: "",
	}
	for ts, want := range cases {
		got, ok := TSQualifier(ts)
		if got != want || ok != (want != "") {
			t.Errorf("%v: %q %v", ts, got, ok)
		}
	}
	c := Capability("http", 1, QualIPv4, QualPhases)
	if c.String() != "measure.http.v1:ipv4:phases" {
		t.Fatalf("capability %s", c)
	}
}

func TestSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := Sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("Sleep ignored its context")
	}
	if err := Sleep(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := Sleep(context.Background(), -time.Second); err != nil {
		t.Fatal(err)
	}
}
