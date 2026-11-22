package kit

import (
	"context"
	"errors"
	"net"
	"reflect"
	"runtime"
	"slices"
	"strings"
)

// IsTimeout reports whether err is a deadline or a timeout, including a
// connect that the operating system timed out.
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	_, timedOut := connErrnos(runtime.GOOS)
	n, ok := errno(err)
	return ok && slices.Contains(timedOut, n)
}

// IsRefused reports whether err is a connection the target refused.
func IsRefused(err error) bool {
	if err == nil {
		return false
	}
	if n, ok := errno(err); ok {
		refused, _ := connErrnos(runtime.GOOS)
		if len(refused) > 0 {
			return slices.Contains(refused, n)
		}
	}
	// Platforms without a known errno: Unix says "connection refused",
	// Windows says the target "actively refused it".
	return strings.Contains(strings.ToLower(err.Error()), "refused")
}

// IsBlocked reports whether err is the operating system refusing the node
// permission to send, as a local firewall does.
func IsBlocked(err error) bool {
	if err == nil {
		return false
	}
	n, ok := errno(err)
	return ok && slices.Contains(permErrnos(runtime.GOOS), n)
}

// errno finds a syscall.Errno in err's chain and returns its number.
// Modules may not import syscall, so it reads the value by reflection.
func errno(err error) (uint64, bool) {
	for err != nil {
		v := reflect.ValueOf(err)
		if t := v.Type(); v.Kind() == reflect.Uintptr && t.PkgPath() == "syscall" && t.Name() == "Errno" {
			return v.Uint(), true
		}
		switch u := err.(type) {
		case interface{ Unwrap() []error }:
			for _, e := range u.Unwrap() {
				if n, ok := errno(e); ok {
					return n, true
				}
			}
			return 0, false
		default:
			err = errors.Unwrap(err)
		}
	}
	return 0, false
}

// connErrnos returns the errno numbers of a refused and of a timed-out
// connection on goos.
func connErrnos(goos string) (refused, timedOut []uint64) {
	switch goos {
	case "linux", "android":
		return []uint64{111}, []uint64{110}
	case "darwin", "ios", "freebsd", "netbsd", "openbsd", "dragonfly":
		return []uint64{61}, []uint64{60}
	case "solaris", "illumos":
		return []uint64{146}, []uint64{145}
	case "aix":
		return []uint64{79}, []uint64{78}
	case "windows":
		// WSAECONNREFUSED and ERROR_CONNECTION_REFUSED; WSAETIMEDOUT and
		// ERROR_SEM_TIMEOUT.
		return []uint64{10061, 1225}, []uint64{10060, 121}
	default:
		return nil, nil
	}
}

// permErrnos returns the errno numbers of a send the operating system did
// not permit on goos: EPERM and EACCES, or WSAEACCES and
// ERROR_ACCESS_DENIED on Windows.
func permErrnos(goos string) []uint64 {
	switch goos {
	case "linux", "android", "darwin", "ios", "freebsd", "netbsd", "openbsd", "dragonfly", "solaris", "illumos", "aix":
		return []uint64{1, 13}
	case "windows":
		return []uint64{10013, 5}
	default:
		return nil
	}
}
