//go:build linux

package anchor

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// readTCPRTT returns the kernel-estimated TCP RTT in microseconds via TCP_INFO.
func readTCPRTT(conn net.Conn) (uint32, bool) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var (
		rtt uint32
		ok2 bool
	)
	if cerr := raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.SOL_TCP, unix.TCP_INFO)
		if err == nil && info != nil {
			rtt = info.Rtt
			ok2 = true
		}
	}); cerr != nil {
		return 0, false
	}
	return rtt, ok2
}
