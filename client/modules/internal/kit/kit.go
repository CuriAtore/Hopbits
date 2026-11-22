// Package kit holds what the node modules share: parameter decoding,
// deadline checks, outcome mapping for connection errors, timing
// conversions, simple statistics and capability strings. It never touches
// the network.
package kit

import (
	"context"
	"errors"
	"math"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/module"
	"github.com/hopbits/client/protocol"
)

// Capability qualifiers the modules advertise.
const (
	QualIPv4     = "ipv4"
	QualIPv6     = "ipv6"
	QualPhases   = "phases"
	QualTSKernel = "ts.kernel"
	QualTSUser   = "ts.user"
	QualTSOSMs   = "ts.osms"
)

// Clock is the time source a module uses. Tests replace it so that waits
// between samples and packets cost no real time.
type Clock struct {
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// RealClock is the system clock. time.Now carries a monotonic reading, so
// durations between its values are monotonic.
func RealClock() Clock {
	return Clock{Now: time.Now, Sleep: Sleep}
}

// Sleep waits for d or until ctx ends, and then returns ctx's error.
func Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Invalid refuses a job whose params break the kind's compiled limits.
func Invalid(format string, args ...any) *module.Refusal {
	return module.Refuse(nodev1.ErrorCode_ERROR_CODE_INVALID_PARAMS, format, args...)
}

// Decode parses a job's params into m. Bytes that do not decode are
// refused with INVALID_PARAMS.
func Decode(params []byte, m proto.Message) error {
	if err := proto.Unmarshal(params, m); err != nil {
		return Invalid("params do not decode: %v", err)
	}
	return nil
}

// CheckWindow refuses a job whose deadline leaves less than need. The
// window runs from the job's issue time, or from now if it has none, to
// its deadline. Both times are the ones the dispatcher signed, so the
// check does not depend on how long the job took to arrive.
func CheckWindow(job *module.Job, need time.Duration, now time.Time) error {
	if job.Deadline.IsZero() {
		return Invalid("job has no deadline")
	}
	from := job.Issued
	if from.IsZero() {
		from = now
	}
	if have := job.Deadline.Sub(from); have < need {
		return Invalid("deadline leaves %v but the params need %v", have, need)
	}
	return nil
}

// WithDeadline bounds ctx by the job's deadline, if it has one.
func WithDeadline(ctx context.Context, job *module.Job) (context.Context, context.CancelFunc) {
	if job.Deadline.IsZero() {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, job.Deadline)
}

// HasGrant reports whether a target carries a target grant. Check uses it
// to apply a granted target's limits; the safety layer verifies the grant
// before the job runs, and Run relies on TargetNet.Verified instead.
func HasGrant(t *nodev1.Target) bool {
	g := t.GetGrant()
	return len(g.GetBody()) > 0 && len(g.GetSig()) > 0
}

// Port returns a target's port, or false if it is 0 or out of range.
func Port(t *nodev1.Target) (uint16, bool) {
	p := t.GetPort()
	if p == 0 || p > math.MaxUint16 {
		return 0, false
	}
	return uint16(p), true
}

// unsafeTestPortFloor is the lowest port UnsafeTestPort opens: the start of
// the ephemeral range, where test servers listen.
const unsafeTestPortFloor = 32768

// UnsafeTestPort reports whether a module may use port without a target
// grant only because this is the unsafe end-to-end test build. It is false
// in every build without the hopbits_unsafe_testing tag. With the tag it is
// true for ports from 32768 up, where test servers listen, so a test can
// measure a local server; the safety layer still admits only the ports its
// test hooks name.
func UnsafeTestPort(port uint16) bool {
	return unsafeTestHooks && port >= unsafeTestPortFloor
}

// Blocked is the result of a job the node would not run or could not
// start: the outcome RefusalOutcome gives, no timing and no data.
func Blocked(err error) module.Result {
	o, code := RefusalOutcome(err)
	return module.Result{
		Outcome:  o,
		Error:    code,
		TSSource: nodev1.TimestampSource_TIMESTAMP_SOURCE_NONE,
	}
}

// RefusalOutcome maps a refusal from the safety layer or a module check:
// DENIED_LOCAL for a target denied locally, BLOCKED_ON_NODE otherwise,
// with the refusal's error code (REFUSED_LOCALLY for a plain error).
func RefusalOutcome(err error) (nodev1.Outcome, nodev1.ErrorCode) {
	code := module.CodeOf(err)
	if code == nodev1.ErrorCode_ERROR_CODE_TARGET_DENIED_LOCAL {
		return nodev1.Outcome_OUTCOME_DENIED_LOCAL, code
	}
	return nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE, code
}

// ConnectOutcome maps an error from TargetNet.DialTCP, or from sending an
// echo request, to a result outcome:
//   - a *module.Refusal from the safety layer maps as RefusalOutcome does;
//   - cancellation is CANCELLED;
//   - a deadline or timeout is TIMEOUT;
//   - a refused connection is REFUSED;
//   - the operating system not permitting the send is BLOCKED_ON_NODE with
//     REFUSED_LOCALLY, since the target was never tried;
//   - anything else is UNREACHABLE.
//
// Only a refusal or a blocked send carries an error code.
func ConnectOutcome(err error) (nodev1.Outcome, nodev1.ErrorCode) {
	var r *module.Refusal
	switch {
	case errors.As(err, &r):
		return RefusalOutcome(r)
	case errors.Is(err, context.Canceled):
		return nodev1.Outcome_OUTCOME_CANCELLED, nodev1.ErrorCode_ERROR_CODE_UNSPECIFIED
	case IsTimeout(err):
		return nodev1.Outcome_OUTCOME_TIMEOUT, nodev1.ErrorCode_ERROR_CODE_UNSPECIFIED
	case IsRefused(err):
		return nodev1.Outcome_OUTCOME_REFUSED, nodev1.ErrorCode_ERROR_CODE_UNSPECIFIED
	case IsBlocked(err):
		return nodev1.Outcome_OUTCOME_BLOCKED_ON_NODE, nodev1.ErrorCode_ERROR_CODE_REFUSED_LOCALLY
	default:
		return nodev1.Outcome_OUTCOME_UNREACHABLE, nodev1.ErrorCode_ERROR_CODE_UNSPECIFIED
	}
}

// LostReply reports whether err from module.Pinger.Echo means the echo
// request left the node and no reply came: the safety layer marks such
// errors with a Timeout method that reports true. Any other error means
// the request was never sent.
func LostReply(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// Micros converts a duration to whole microseconds, clamped to the uint32
// range.
func Micros(d time.Duration) uint32 {
	us := d.Microseconds()
	switch {
	case us <= 0:
		return 0
	case us > math.MaxUint32:
		return math.MaxUint32
	}
	return uint32(us)
}

// SampleMicros is Micros for a sample that succeeded. It is at least 1,
// because results use 0 for a failed sample.
func SampleMicros(d time.Duration) uint32 {
	return max(Micros(d), 1)
}

// Stats returns the minimum, median and maximum of vals, or zeros when
// there are none. The median of an even count is the mean of the two
// middle values, rounded down.
func Stats(vals []uint32) (lo, median, hi uint32) {
	if len(vals) == 0 {
		return 0, 0, 0
	}
	s := slices.Clone(vals)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		median = s[n/2]
	} else {
		median = uint32((uint64(s[n/2-1]) + uint64(s[n/2])) / 2)
	}
	return s[0], median, s[n-1]
}

// Capability builds a capability of the measure class.
func Capability(kind string, version uint32, qualifiers ...string) protocol.Capability {
	return protocol.Capability{
		Class:      protocol.ClassName(nodev1.JobClass_JOB_CLASS_MEASURE),
		Kind:       kind,
		Version:    version,
		Qualifiers: qualifiers,
	}
}

// Families returns the address-family qualifiers for TCP-based kinds:
// ipv4, plus ipv6 when the host has a global IPv6 address.
func Families(env module.Env) []string {
	q := []string{QualIPv4}
	if env.Probe != nil && env.Probe.HasIPv6() {
		q = append(q, QualIPv6)
	}
	return q
}

// TSQualifier names a timestamp source as a capability qualifier. It
// reports false for sources a module cannot advertise.
func TSQualifier(ts nodev1.TimestampSource) (string, bool) {
	switch ts {
	case nodev1.TimestampSource_TIMESTAMP_SOURCE_KERNEL_RX:
		return QualTSKernel, true
	case nodev1.TimestampSource_TIMESTAMP_SOURCE_USERSPACE_MONO:
		return QualTSUser, true
	case nodev1.TimestampSource_TIMESTAMP_SOURCE_OS_API_MS:
		return QualTSOSMs, true
	default:
		return "", false
	}
}
