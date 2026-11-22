//go:build !linux

package safety

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"time"
)

func defaultTraceHop(_ context.Context, _ *Guard, _ netip.Addr, proto string, _, _ int, _ time.Duration) (rawHopSample, error) {
	return rawHopSample{protocol: proto}, fmt.Errorf("safety: trace is not implemented on %s", runtime.GOOS)
}

func traceAvailable(_ bool) (bool, string) {
	return false, fmt.Sprintf("trace not implemented on %s", runtime.GOOS)
}
