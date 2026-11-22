// Package protocol holds the parts of the Hopbits node protocol that every
// client and the server share: signing over exact bytes, root-certified keys,
// node identifiers, capability strings and frame encoding.
//
// The wire messages themselves are generated from proto/ into gen/go.
package protocol

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
)

const (
	// Version is the protocol major version carried in Envelope.v and the URL path.
	Version = 1
	// Path is the gateway's node endpoint.
	Path = "/v1/node"
	// DefaultGatewayURL is where production nodes connect.
	DefaultGatewayURL = "wss://api.hopbits.io/v1/node"
	// MaxFrameBytes bounds one Envelope on the wire.
	MaxFrameBytes = 1 << 20
	// MaxClockSkewMillis is how far a Hello timestamp may be from server time.
	MaxClockSkewMillis = 120_000
	// TLSExporterLabel binds a native node's Welcome to its TLS session.
	TLSExporterLabel = "EXPORTER-hopbits-node-v1-welcome"
	// TLSExporterLength is the exporter value length in bytes.
	TLSExporterLength = 32
	// MaxNodeLabelRunes bounds the display label a node reports in Hello.
	MaxNodeLabelRunes = 80
	// MaxNodeLabelBytes bounds the wire UTF-8 byte length of Hello.label.
	MaxNodeLabelBytes = 256
)

// ErrFrameTooLarge is returned for frames above MaxFrameBytes.
var ErrFrameTooLarge = errors.New("protocol: frame too large")

// EncodeEnvelope serialises one frame.
func EncodeEnvelope(env *nodev1.Envelope) ([]byte, error) {
	if env.GetV() == 0 {
		env.V = Version
	}
	b, err := proto.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("protocol: encode envelope: %w", err)
	}
	if len(b) > MaxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	return b, nil
}

// DecodeEnvelope parses one frame and checks its version and channel.
// A non-zero channel is reserved and refused with CLASS_NOT_ENABLED by callers.
func DecodeEnvelope(b []byte) (*nodev1.Envelope, error) {
	if len(b) > MaxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	env := &nodev1.Envelope{}
	if err := proto.Unmarshal(b, env); err != nil {
		return nil, fmt.Errorf("protocol: decode envelope: %w", err)
	}
	if env.GetV() != Version {
		return nil, fmt.Errorf("protocol: unsupported version %d", env.GetV())
	}
	return env, nil
}

// ClassName returns the capability-string class for a job class.
func ClassName(c nodev1.JobClass) string {
	switch c {
	case nodev1.JobClass_JOB_CLASS_MEASURE:
		return "measure"
	default:
		return ""
	}
}

// SanitizeNodeLabel cleans an operator-supplied node display label: invalid
// UTF-8 sequences and ASCII control characters (< 0x20 or 0x7f) are stripped,
// outer whitespace is trimmed, and labels exceeding MaxNodeLabelRunes (or
// MaxNodeLabelBytes in UTF-8) are truncated on a rune boundary with
// truncated == true.
func SanitizeNodeLabel(raw string) (label string, truncated bool) {
	if raw == "" {
		return "", false
	}
	valid := strings.ToValidUTF8(raw, "")
	var b strings.Builder
	b.Grow(min(len(valid), MaxNodeLabelBytes))
	for _, r := range valid {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	cleaned := strings.TrimSpace(b.String())
	if cleaned == "" {
		return "", false
	}
	if utf8.RuneCountInString(cleaned) <= MaxNodeLabelRunes && len(cleaned) <= MaxNodeLabelBytes {
		return cleaned, false
	}
	var out strings.Builder
	out.Grow(MaxNodeLabelBytes)
	runes := 0
	for _, r := range cleaned {
		rLen := utf8.RuneLen(r)
		if rLen < 0 {
			continue
		}
		if runes >= MaxNodeLabelRunes || out.Len()+rLen > MaxNodeLabelBytes {
			truncated = true
			break
		}
		out.WriteRune(r)
		runes++
	}
	return strings.TrimSpace(out.String()), truncated
}
