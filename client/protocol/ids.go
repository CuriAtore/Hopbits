package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
)

// NodeIDLength is the length of a node id in bytes.
const NodeIDLength = 16

// NodeID derives a node's id: the first 16 bytes of SHA-256 of its public key.
func NodeID(pub ed25519.PublicKey) []byte {
	sum := sha256.Sum256(pub)
	id := make([]byte, NodeIDLength)
	copy(id, sum[:NodeIDLength])
	return id
}

// NodeIDString renders a node id for logs, the dashboard and APIs.
func NodeIDString(id []byte) string {
	return hex.EncodeToString(id)
}

// ParseNodeID parses the form NodeIDString produces.
func ParseNodeID(s string) ([]byte, error) {
	id, err := hex.DecodeString(s)
	if err != nil || len(id) != NodeIDLength {
		return nil, fmt.Errorf("protocol: invalid node id %q", s)
	}
	return id, nil
}

// KeyID names a root-certified key: "k-" plus base32 of the first 10 bytes of
// SHA-256 of its public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:10])
	return "k-" + strings.ToLower(enc)
}
