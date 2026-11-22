package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

const keyFileName = "node.key"

// LoadOrCreateKey returns the node's Ed25519 device key, kept in
// dataDir/node.key as a base64 seed. On first run it creates the key with
// mode 0600 (best effort on Windows). The node id derives from this key, so
// deleting the file makes the node a new node. The key is never logged.
func LoadOrCreateKey(dataDir string) (ed25519.PrivateKey, error) {
	if dataDir == "" {
		return nil, errors.New("agent: empty data directory")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("agent: create data directory: %w", err)
	}
	path := filepath.Join(dataDir, keyFileName)
	for range 2 {
		b, err := os.ReadFile(path)
		switch {
		case err == nil && len(bytes.TrimSpace(b)) > 0:
			return parseKey(b)
		case err == nil:
			// An empty file never held a key, so replacing it changes no
			// node's identity. It is left by a crash during creation.
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("agent: remove empty device key file: %w", err)
			}
		case !errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("agent: read device key: %w", err)
		}
		key, err := createKey(path)
		if errors.Is(err, fs.ErrExist) {
			continue // created concurrently; read it on the next pass
		}
		return key, err
	}
	return nil, errors.New("agent: device key file changed while loading")
}

func parseKey(b []byte) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		// The error deliberately carries nothing from the file.
		return nil, errors.New("agent: device key file does not hold a base64 Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func createKey(path string) (ed25519.PrivateKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("agent: generate device key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("agent: create device key file: %w", err)
	}
	_, werr := f.WriteString(base64.StdEncoding.EncodeToString(seed) + "\n")
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("agent: write device key file: %w", werr)
	}
	if runtime.GOOS != "windows" {
		// The umask can only narrow 0600, but say it explicitly.
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("agent: restrict device key file: %w", err)
		}
	}
	syncDir(filepath.Dir(path))
	return ed25519.NewKeyFromSeed(seed), nil
}
