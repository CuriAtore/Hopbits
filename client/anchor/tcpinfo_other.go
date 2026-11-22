//go:build !linux

package anchor

import "net"

func readTCPRTT(net.Conn) (uint32, bool) {
	return 0, false
}
