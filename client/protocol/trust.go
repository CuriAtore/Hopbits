package protocol

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
)

// Errors returned by KeyRing.
var (
	ErrUnknownKey      = errors.New("protocol: unknown key")
	ErrKeyRevoked      = errors.New("protocol: key revoked")
	ErrKeyOutsideValid = errors.New("protocol: key outside its validity window")
	ErrWrongRole       = errors.New("protocol: key has the wrong role")
	ErrBadSignature    = errors.New("protocol: bad signature")
	ErrUnknownRoot     = errors.New("protocol: unknown root")
)

// Roots are the root public keys compiled into a client: index 0 is the
// working root, the rest are recovery roots.
type Roots []ed25519.PublicKey

type certifiedKey struct {
	cert *nodev1.KeyCertificate
	pub  ed25519.PublicKey
}

// KeyRing holds root-certified keys (dispatcher, target-grant, release) and
// root-signed revocations. It is safe for concurrent use.
type KeyRing struct {
	roots Roots

	mu      sync.RWMutex
	keys    map[string]certifiedKey
	revoked map[string]bool
}

// NewKeyRing returns an empty key ring trusting roots.
func NewKeyRing(roots Roots) *KeyRing {
	return &KeyRing{
		roots:   roots,
		keys:    make(map[string]certifiedKey),
		revoked: make(map[string]bool),
	}
}

func (k *KeyRing) root(i uint32) (ed25519.PublicKey, error) {
	if int(i) >= len(k.roots) || len(k.roots[i]) != ed25519.PublicKeySize {
		return nil, ErrUnknownRoot
	}
	return k.roots[i], nil
}

// AddCertificate verifies a root-signed key certificate and adds the key.
// Certificates for future windows are kept, so a node holds the next
// dispatcher key before it starts signing.
func (k *KeyRing) AddCertificate(sc *nodev1.SignedKeyCertificate, want nodev1.KeyRole) (*nodev1.KeyCertificate, error) {
	root, err := k.root(sc.GetRootIndex())
	if err != nil {
		return nil, err
	}
	if !Verify(root, PurposeKeyCertificate, sc.GetBody(), sc.GetSig()) {
		return nil, ErrBadSignature
	}
	cert := &nodev1.KeyCertificate{}
	if err := proto.Unmarshal(sc.GetBody(), cert); err != nil {
		return nil, fmt.Errorf("protocol: decode key certificate: %w", err)
	}
	if cert.GetRole() != want {
		return nil, ErrWrongRole
	}
	pub := ed25519.PublicKey(cert.GetPublicKey())
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("protocol: key certificate has a %d-byte key", len(pub))
	}
	if cert.GetKeyId() != KeyID(pub) {
		return nil, fmt.Errorf("protocol: key id %q does not match its key", cert.GetKeyId())
	}
	if cert.GetNotAfterUnix() <= cert.GetNotBeforeUnix() {
		return nil, ErrKeyOutsideValid
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.revoked[cert.GetKeyId()] {
		return nil, ErrKeyRevoked
	}
	k.keys[cert.GetKeyId()] = certifiedKey{cert: cert, pub: pub}
	return cert, nil
}

// ApplyRevocation verifies a root-signed revocation and withdraws its keys.
func (k *KeyRing) ApplyRevocation(sr *nodev1.SignedRevocation) error {
	root, err := k.root(sr.GetRootIndex())
	if err != nil {
		return err
	}
	if !Verify(root, PurposeRevocation, sr.GetBody(), sr.GetSig()) {
		return ErrBadSignature
	}
	rev := &nodev1.Revocation{}
	if err := proto.Unmarshal(sr.GetBody(), rev); err != nil {
		return fmt.Errorf("protocol: decode revocation: %w", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, id := range rev.GetKeyIds() {
		k.revoked[id] = true
		delete(k.keys, id)
	}
	return nil
}

// Verify checks that keyID is a known, unrevoked key with the given role,
// valid at now, and that sig is its signature over body for purpose p.
func (k *KeyRing) Verify(keyID string, role nodev1.KeyRole, p Purpose, body, sig []byte, now time.Time) error {
	k.mu.RLock()
	ck, ok := k.keys[keyID]
	revoked := k.revoked[keyID]
	k.mu.RUnlock()
	switch {
	case revoked:
		return ErrKeyRevoked
	case !ok:
		return ErrUnknownKey
	case ck.cert.GetRole() != role:
		return ErrWrongRole
	}
	t := now.Unix()
	if t < ck.cert.GetNotBeforeUnix() || t >= ck.cert.GetNotAfterUnix() {
		return ErrKeyOutsideValid
	}
	if !Verify(ck.pub, p, body, sig) {
		return ErrBadSignature
	}
	return nil
}

// VerifyWorkingRoot verifies that sig is a valid signature for purpose p over
// body made by the compiled working root (index 0).
func (k *KeyRing) VerifyWorkingRoot(p Purpose, body, sig []byte) error {
	root, err := k.root(0)
	if err != nil {
		return err
	}
	if !Verify(root, p, body, sig) {
		return ErrBadSignature
	}
	return nil
}

// CertifyKey signs a key certificate with a root key. It runs at the key
// ceremony on an offline machine, and in development tooling.
func CertifyKey(rootPriv ed25519.PrivateKey, rootIndex uint32, cert *nodev1.KeyCertificate) (*nodev1.SignedKeyCertificate, error) {
	body, err := proto.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("protocol: encode key certificate: %w", err)
	}
	return &nodev1.SignedKeyCertificate{
		Body:      body,
		Sig:       Sign(rootPriv, PurposeKeyCertificate, body),
		RootIndex: rootIndex,
	}, nil
}

// NewKeyCertificate describes pub for role over [notBefore, notAfter).
func NewKeyCertificate(pub ed25519.PublicKey, role nodev1.KeyRole, notBefore, notAfter time.Time) *nodev1.KeyCertificate {
	return &nodev1.KeyCertificate{
		KeyId:         KeyID(pub),
		Role:          role,
		PublicKey:     pub,
		NotBeforeUnix: notBefore.Unix(),
		NotAfterUnix:  notAfter.Unix(),
	}
}

// SignRevocation signs a revocation with a root key.
func SignRevocation(rootPriv ed25519.PrivateKey, rootIndex uint32, rev *nodev1.Revocation) (*nodev1.SignedRevocation, error) {
	body, err := proto.Marshal(rev)
	if err != nil {
		return nil, fmt.Errorf("protocol: encode revocation: %w", err)
	}
	return &nodev1.SignedRevocation{
		Body:      body,
		Sig:       Sign(rootPriv, PurposeRevocation, body),
		RootIndex: rootIndex,
	}, nil
}
