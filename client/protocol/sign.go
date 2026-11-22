package protocol

import (
	"crypto/ed25519"
)

// Purpose separates signatures by message type, so a signature made for one
// kind of body can never verify as another.
type Purpose string

// Signing purposes, one per signed message type.
const (
	PurposeHello           Purpose = "hello"
	PurposeWelcome         Purpose = "welcome"
	PurposeJob             Purpose = "job"
	PurposeResult          Purpose = "result"
	PurposeConsent         Purpose = "consent"
	PurposeObservations    Purpose = "observations"
	PurposeKeyCertificate  Purpose = "key-certificate"
	PurposeRevocation      Purpose = "revocation"
	PurposeTargetGrant     Purpose = "target-grant"
	PurposePauseFile       Purpose = "pause-file"
	PurposeReleaseManifest Purpose = "release-manifest"
	PurposeReleaseBinary   Purpose = "release-binary"
)

const signingPrefix = "hopbits.node.v1/"

// SigningInput is the exact byte string a signature covers: a fixed prefix,
// the purpose, a zero byte, then the serialised body as received. The
// receiver verifies over these bytes before parsing the body, so there is no
// canonicalisation to get wrong.
func SigningInput(p Purpose, body []byte) []byte {
	in := make([]byte, 0, len(signingPrefix)+len(p)+1+len(body))
	in = append(in, signingPrefix...)
	in = append(in, p...)
	in = append(in, 0)
	in = append(in, body...)
	return in
}

// Sign signs body for purpose p.
func Sign(priv ed25519.PrivateKey, p Purpose, body []byte) []byte {
	return ed25519.Sign(priv, SigningInput(p, body))
}

// Verify checks a signature made by Sign.
func Verify(pub ed25519.PublicKey, p Purpose, body, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, SigningInput(p, body), sig)
}
