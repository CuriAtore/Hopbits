// Package release is the owner's side of a node's self-update and of its
// stop switch.
//
// A node in the field asks the pause host for two files: the release
// manifest, once an hour, and the pause file, every five minutes. It checks
// both against the root keys compiled into it (package agent, update.go and
// pause.go). This package writes those two files, and the certificate that
// lets a release key sign the first of them.
//
// The keys:
//
//   - The root key is the one whose public half is compiled into every
//     node. It signs the pause file itself and certifies release keys. It is
//     needed rarely and belongs off networked machines.
//   - A release key signs release manifests and the binaries they list. A
//     node accepts it only with a root-signed certificate, and only inside
//     that certificate's dates.
//
// Whoever holds a certified release key can put new software on every node
// that has updates switched on, so it is kept like a production secret.
package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/hopbits/client/agent"
	nodev1 "github.com/hopbits/client/gen/go/hopbits/node/v1"
	"github.com/hopbits/client/protocol"
)

// Sizes above which a node refuses a file. The agent keeps the same numbers
// unexported (agent/update.go, agent/pause.go); they are repeated here so
// that nothing is signed that no node would take.
const (
	MaxBinaryBytes   = 128 << 20
	MaxManifestBytes = 1 << 20
	MaxPauseBytes    = 1 << 20
)

// Backdate is how long before the moment of signing a release key's
// certificate starts, so that a node whose clock runs slow accepts a fresh
// certificate at once.
const Backdate = 24 * time.Hour

// NewKey makes a release key.
func NewKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("release: generate a key: %w", err)
	}
	return priv, nil
}

// FormatKey returns priv as a key file holds it: its 32-byte seed in
// standard base64 and a line end, the form of the root key file.
func FormatKey(priv ed25519.PrivateKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n")
}

// ParseKey reads a private key from the text of a key file: the 32-byte seed
// in standard base64, or the whole 64-byte key. Its errors never repeat the
// text.
func ParseKey(text []byte) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(text)))
	if err != nil {
		return nil, errors.New("release: the key file is not standard base64")
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		priv := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !bytes.Equal(priv, raw) {
			return nil, errors.New("release: the key file holds a private key whose two halves do not match")
		}
		return priv, nil
	}
	return nil, fmt.Errorf("release: the key file holds %d bytes, want a %d-byte seed", len(raw), ed25519.SeedSize)
}

// FormatPublicKey returns pub in standard base64, the form root keys are
// compiled into the agent in.
func FormatPublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// ParsePublicKey reads an Ed25519 public key in standard base64.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("release: %q is not a base64 Ed25519 public key", strings.TrimSpace(s))
	}
	return ed25519.PublicKey(raw), nil
}

// ParseRoots reads the root public keys a node is built with: standard
// base64, separated by commas, the working root first. It is the value of
// RELEASE_ROOTS in the agent's build.
func ParseRoots(csv string) (protocol.Roots, error) {
	var roots protocol.Roots
	for _, part := range strings.Split(csv, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		pub, err := ParsePublicKey(part)
		if err != nil {
			return nil, err
		}
		roots = append(roots, pub)
	}
	if len(roots) == 0 {
		return nil, errors.New("release: no root public key given")
	}
	return roots, nil
}

// Certify makes the certificate that lets nodes built with root's public
// half as root number rootIndex accept pub as a release key from notBefore
// until notAfter.
func Certify(root ed25519.PrivateKey, rootIndex uint32, pub ed25519.PublicKey, notBefore, notAfter time.Time) (agent.SignedKeyCertEntry, error) {
	if len(root) != ed25519.PrivateKeySize {
		return agent.SignedKeyCertEntry{}, errors.New("release: the root key is not an Ed25519 private key")
	}
	if len(pub) != ed25519.PublicKeySize {
		return agent.SignedKeyCertEntry{}, errors.New("release: the release key is not an Ed25519 public key")
	}
	if !notAfter.After(notBefore) {
		return agent.SignedKeyCertEntry{}, errors.New("release: the certificate would end before it starts")
	}
	signed, err := protocol.CertifyKey(root, rootIndex,
		protocol.NewKeyCertificate(pub, nodev1.KeyRole_KEY_ROLE_RELEASE, notBefore, notAfter))
	if err != nil {
		return agent.SignedKeyCertEntry{}, fmt.Errorf("release: %w", err)
	}
	return agent.SignedKeyCertEntry{Body: signed.GetBody(), Sig: signed.GetSig(), RootIndex: signed.GetRootIndex()}, nil
}

// Certificate decodes what a certificate says, without checking who signed
// it; a Node checks that.
func Certificate(c agent.SignedKeyCertEntry) (*nodev1.KeyCertificate, error) {
	cert := &nodev1.KeyCertificate{}
	if len(c.Body) == 0 {
		return nil, errors.New("release: the certificate is empty")
	}
	if err := proto.Unmarshal(c.Body, cert); err != nil {
		return nil, fmt.Errorf("release: decode the certificate: %w", err)
	}
	return cert, nil
}

// CheckCertificate puts a release key's certificate through the key ring a
// node built with roots keeps: the root's signature, the role, the key id.
// The dates are checked when the key is used, by a Node.
func CheckCertificate(roots protocol.Roots, c agent.SignedKeyCertEntry) error {
	_, err := protocol.NewKeyRing(roots).AddCertificate(
		&nodev1.SignedKeyCertificate{Body: c.Body, Sig: c.Sig, RootIndex: c.RootIndex},
		nodev1.KeyRole_KEY_ROLE_RELEASE)
	return err
}

// Binary is one release binary for a manifest to list.
type Binary struct {
	// OS and Arch name the platform as Go does: "linux" and "amd64" or
	// "arm64".
	OS   string
	Arch string
	// URL is where nodes download the binary from: https on port 443, and
	// it must answer with the file itself, since a node follows no redirect.
	URL string
	// Data is the binary.
	Data []byte
}

// Release is what a manifest tells the nodes.
type Release struct {
	// Version is the version the binaries were built as. A node updates
	// when it is above the node's own.
	Version string
	// MinVersion, if set, makes the update immediate for every node below
	// it, whatever RolloutPercent says.
	MinVersion string
	// RolloutPercent is how many nodes in a hundred take the update. Each
	// node's place is fixed by its id, so raising the number adds nodes and
	// never swaps them.
	RolloutPercent int
	// Issued is when the manifest is signed. A node refuses a manifest
	// older than one it has accepted.
	Issued time.Time
	// Expires is when nodes stop accepting the manifest.
	Expires time.Time
	// Binaries lists one binary for each platform.
	Binaries []Binary
}

// Sign returns the release manifest file for r, signed with key, whose
// root-signed certificate is cert. The manifest carries the certificate, so
// a node needs nothing else to check it.
func Sign(key ed25519.PrivateKey, cert agent.SignedKeyCertEntry, r Release) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("release: the release key is not an Ed25519 private key")
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	c, err := Certificate(cert)
	if err != nil {
		return nil, err
	}
	if c.GetRole() != nodev1.KeyRole_KEY_ROLE_RELEASE {
		return nil, errors.New("release: the certificate is not for a release key")
	}
	if !bytes.Equal(c.GetPublicKey(), pub) || c.GetKeyId() != protocol.KeyID(pub) {
		return nil, errors.New("release: the certificate is for another key than the release key given")
	}

	if err := checkVersion("version", r.Version); err != nil {
		return nil, err
	}
	if r.MinVersion != "" {
		if err := checkVersion("minimum version", r.MinVersion); err != nil {
			return nil, err
		}
		if versionAbove(r.MinVersion, r.Version) {
			return nil, fmt.Errorf("release: the minimum version %s is above the version %s, which no node could reach",
				r.MinVersion, r.Version)
		}
	}
	if r.RolloutPercent < 0 || r.RolloutPercent > 100 {
		return nil, fmt.Errorf("release: the rollout is %d, want 0 to 100", r.RolloutPercent)
	}
	issued, expires := r.Issued.Unix(), r.Expires.Unix()
	if issued <= 0 || expires <= issued {
		return nil, errors.New("release: the manifest would expire before it is issued")
	}
	if issued < c.GetNotBeforeUnix() || expires > c.GetNotAfterUnix() {
		return nil, fmt.Errorf("release: the manifest would be valid from %s to %s, outside the release key's certificate (%s to %s): "+
			"nodes refuse a manifest whose key has run out",
			day(issued), day(expires), day(c.GetNotBeforeUnix()), day(c.GetNotAfterUnix()))
	}

	if len(r.Binaries) == 0 {
		return nil, errors.New("release: no binary to release")
	}
	seen := make(map[string]bool)
	artifacts := make([]agent.ReleaseArtifact, 0, len(r.Binaries))
	for _, b := range r.Binaries {
		platform := b.OS + "/" + b.Arch
		if !platformName.MatchString(b.OS) || !platformName.MatchString(b.Arch) {
			return nil, fmt.Errorf("release: %q is not a platform such as linux/amd64", platform)
		}
		if seen[platform] {
			return nil, fmt.Errorf("release: two binaries for %s", platform)
		}
		seen[platform] = true
		if err := checkURL(b.URL); err != nil {
			return nil, fmt.Errorf("release: the address of the %s binary: %w", platform, err)
		}
		if len(b.Data) == 0 {
			return nil, fmt.Errorf("release: the %s binary is empty", platform)
		}
		if len(b.Data) > MaxBinaryBytes {
			return nil, fmt.Errorf("release: the %s binary has %d bytes; a node refuses more than %d",
				platform, len(b.Data), MaxBinaryBytes)
		}
		sum := sha256.Sum256(b.Data)
		artifacts = append(artifacts, agent.ReleaseArtifact{
			OS:     b.OS,
			Arch:   b.Arch,
			URL:    b.URL,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(b.Data)),
			Sig:    protocol.Sign(key, protocol.PurposeReleaseBinary, sum[:]),
		})
	}

	body, err := json.Marshal(agent.ReleaseManifest{
		Version:        r.Version,
		MinVersion:     r.MinVersion,
		IssuedUnix:     issued,
		ExpiresUnix:    expires,
		RolloutPercent: r.RolloutPercent,
		Artifacts:      artifacts,
	})
	if err != nil {
		return nil, fmt.Errorf("release: encode the manifest: %w", err)
	}
	raw, err := json.Marshal(agent.SignedReleaseManifest{
		Cert:  &cert,
		KeyID: protocol.KeyID(pub),
		Body:  body,
		Sig:   protocol.Sign(key, protocol.PurposeReleaseManifest, body),
	})
	if err != nil {
		return nil, fmt.Errorf("release: encode the signed manifest: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxManifestBytes {
		return nil, fmt.Errorf("release: the manifest has %d bytes; a node refuses more than %d", len(raw), MaxManifestBytes)
	}
	return raw, nil
}

// Pause is what a pause file tells the nodes.
type Pause struct {
	// Paused stops every node's work until Expires, or until a later file
	// says otherwise: a node cancels what it is running and refuses new
	// jobs, except those to Hopbits' own anchor names. False is the file to
	// publish while nothing is wrong.
	Paused bool
	// Reason is written into each node's log when the pause starts.
	Reason string
	// Issued is when the file is signed. A node refuses a file older than
	// one it has accepted, so a pause is ended with a new file, never with
	// an old one put back.
	Issued time.Time
	// Expires is when nodes stop accepting the file, and when a pause ends
	// by itself.
	Expires time.Time
}

// SignPause returns the pause file for p. A node accepts it only from the
// working root, root number 0, so root is that key.
func SignPause(root ed25519.PrivateKey, p Pause) ([]byte, error) {
	if len(root) != ed25519.PrivateKeySize {
		return nil, errors.New("release: the root key is not an Ed25519 private key")
	}
	issued, expires := p.Issued.Unix(), p.Expires.Unix()
	if issued <= 0 || expires <= issued {
		return nil, errors.New("release: the pause file would expire before it is issued")
	}
	body, err := json.Marshal(agent.PauseDocument{
		Paused:      p.Paused,
		IssuedUnix:  issued,
		ExpiresUnix: expires,
		Reason:      p.Reason,
	})
	if err != nil {
		return nil, fmt.Errorf("release: encode the pause file: %w", err)
	}
	raw, err := json.Marshal(agent.SignedPauseFile{
		Body: body,
		Sig:  protocol.Sign(root, protocol.PurposePauseFile, body),
	})
	if err != nil {
		return nil, fmt.Errorf("release: encode the signed pause file: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxPauseBytes {
		return nil, fmt.Errorf("release: the pause file has %d bytes; a node refuses more than %d", len(raw), MaxPauseBytes)
	}
	return raw, nil
}

// HasVersion reports whether a binary carries version as text. A build sets
// the agent's version with a linker flag, which leaves the text in the file.
// A binary without it was built as another version: once installed it would
// still report its own, see the manifest's as newer, and install itself
// again every hour. Finding the text proves less, since the same digits can
// occur elsewhere, so this is a check against the common mistake and no
// more.
func HasVersion(binary []byte, version string) bool {
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	return v != "" && bytes.Contains(binary, []byte(v))
}

var (
	// versionForm is three numbers, with an optional leading v and an
	// optional pre-release part. The agent reads looser text as zeros, so a
	// slip such as "latest" would name a version no node ever updates to.
	versionForm  = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)
	platformName = regexp.MustCompile(`^[a-z0-9]+$`)
)

func checkVersion(what, v string) error {
	if !versionForm.MatchString(v) {
		return fmt.Errorf("release: the %s %q is not of the form 1.2.3", what, v)
	}
	return nil
}

// versionAbove reports whether the three numbers of a are above those of b.
// Both have passed checkVersion.
func versionAbove(a, b string) bool {
	na, nb := versionNumbers(a), versionNumbers(b)
	for i := range na {
		if na[i] != nb[i] {
			return na[i] > nb[i]
		}
	}
	return false
}

func versionNumbers(v string) [3]int {
	var out [3]int
	m := versionForm.FindStringSubmatch(v)
	for i := range out {
		if len(m) > i+1 {
			out[i], _ = strconv.Atoi(m[i+1])
		}
	}
	return out
}

// checkURL applies the rules a node applies to a download address before it
// connects: https on port 443, no credentials, no fragment.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not an address", raw)
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%q must start with https://", raw)
	case u.Opaque != "" || u.User != nil || u.Fragment != "":
		return fmt.Errorf("%q must carry no credentials and no fragment", raw)
	case u.Hostname() == "":
		return fmt.Errorf("%q names no host", raw)
	case u.Port() != "" && u.Port() != "443":
		return fmt.Errorf("%q must use port 443", raw)
	case strings.Trim(u.Path, "/") == "":
		return fmt.Errorf("%q names no file", raw)
	}
	return nil
}

func day(unix int64) string {
	return time.Unix(unix, 0).UTC().Format("2006-01-02")
}
