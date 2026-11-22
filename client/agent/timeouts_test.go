package agent

import (
	"net/http"
	"testing"
	"time"
)

// A node on a slow or lossy link gets 45 s for its TLS handshake and 45 s for
// the answer's headers, on the gateway connection and on the pause and update
// fetches, and no outer limit cuts those short (0.2.2, 2026-11-17: 15 s each,
// inside a 30 s dial and a 15 s fetch, kept such a node from ever connecting
// or learning of an update).
func TestConnectionTimeoutsLetASlowLinkThrough(t *testing.T) {
	if handshakeTimeout < 45*time.Second {
		t.Errorf("handshakeTimeout = %v, want at least 45 s", handshakeTimeout)
	}
	if dialTimeout < connectTimeout+2*handshakeTimeout {
		t.Errorf("dialTimeout %v is shorter than a connect (%v) and a TLS handshake and an answer (%v each)", dialTimeout, connectTimeout, handshakeTimeout)
	}
	if welcomeTimeout < handshakeTimeout {
		t.Errorf("welcomeTimeout %v is shorter than handshakeTimeout %v", welcomeTimeout, handshakeTimeout)
	}
	if pauseFetchTimeout <= dialTimeout {
		t.Errorf("pauseFetchTimeout %v does not cover a whole dial (%v)", pauseFetchTimeout, dialTimeout)
	}
	if binaryFetchTimeout <= dialTimeout {
		t.Errorf("binaryFetchTimeout %v does not cover a whole dial (%v)", binaryFetchTimeout, dialTimeout)
	}
	for name, c := range map[string]*http.Client{"gateway": newHTTPClient(nil), "pause and update": newControlHTTPClient(nil)} {
		tr := c.Transport.(*http.Transport)
		if tr.TLSHandshakeTimeout != handshakeTimeout || tr.ResponseHeaderTimeout != handshakeTimeout {
			t.Errorf("%s client: TLS handshake %v, answer %v; want %v each", name, tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout, handshakeTimeout)
		}
	}
}
