package httpcheck

// A site that never answers the connect (dropped SYNs: a stopped host behind
// a dropping firewall, a blackholed address) is a timeout. The dialer ends a
// connect still in progress by cancelling it when the request's time runs
// out, so the dial can come back cancelled; the hub does not count a
// cancelled answer against the site, so it must not be reported as one.

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	measurev1 "github.com/hopbits/client/gen/go/hopbits/measure/v1"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
)

// cancelledDial returns only when its context ends, and always as cancelled:
// the way the race with the dialer's own cancel can end.
func cancelledDial(ctx context.Context) (net.Conn, error) {
	<-ctx.Done()
	return nil, fmt.Errorf("safety: dial 192.0.2.1:8080: %w", &net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled})
}

// Whether the dial's cancelled error is recorded before the request's own
// error is read is a race in Run (the transport returns as soon as the
// request's time is up), so the case is set up directly: the dial ended
// cancelled, and the request ended by its deadline.
func TestUnansweredConnectIsATimeout(t *testing.T) {
	reqCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Millisecond))
	defer cancel()
	_, dialErr := cancelledDial(reqCtx)
	d := &dialer{err: dialErr}
	if r := failure(reqCtx, context.DeadlineExceeded, d, &timeline{now: time.Now}); r.Outcome != nodev1.Outcome_OUTCOME_TIMEOUT {
		t.Errorf("outcome %v, want TIMEOUT", r.Outcome)
	}
	// A dial the node cancelled itself, with time left on the request, stays cancelled.
	stopCtx, stop := context.WithCancel(context.Background())
	stop()
	if r := failure(stopCtx, context.Canceled, d, &timeline{now: time.Now}); r.Outcome != nodev1.Outcome_OUTCOME_CANCELLED {
		t.Errorf("stopped: outcome %v, want CANCELLED", r.Outcome)
	}
}

// A job the node stops itself, as when the agent shuts down, stays cancelled.
func TestStoppedJobStaysCancelled(t *testing.T) {
	tn := &fakeNet{host: "example.com", port: 8080, dial: cancelledDial}
	job := newJob(t, 8080, &measurev1.HttpParams{Scheme: plainHTTP}, 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(50*time.Millisecond, cancel)
	if r := New().Run(ctx, job, tn); r.Outcome != nodev1.Outcome_OUTCOME_CANCELLED {
		t.Errorf("outcome %v, want CANCELLED", r.Outcome)
	}
}
