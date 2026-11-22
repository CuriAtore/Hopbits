//go:build !linux

package anchor

import "context"

func (s *Server) listenICMP(context.Context) {
	s.log.Debug("anchor ICMP listener requires Linux; relying on OS echo replies")
}
