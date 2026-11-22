// Package creds resolves and stores Hopbits CLI credentials and API endpoints.
package creds

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hopbits/cli/internal/api"
)

// ErrNoAPIKey reports that no API key was found via flag, env, or credentials file.
var ErrNoAPIKey = errors.New("no API key configured; pass --api-key, set HOPBITS_API_KEY, or run 'hopbits login'")

// CredentialsPath returns the path to the stored credentials file:
//   - $HOPBITS_CREDENTIALS_FILE (if set, e.g. in tests)
//   - %APPDATA%\hopbits\credentials on Windows
//   - $XDG_CONFIG_HOME/hopbits/credentials (if XDG_CONFIG_HOME is set)
//   - ~/.config/hopbits/credentials otherwise
func CredentialsPath(getenv func(string) string) (string, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if p := strings.TrimSpace(getenv("HOPBITS_CREDENTIALS_FILE")); p != "" {
		return p, nil
	}
	if runtime.GOOS == "windows" {
		if appData := strings.TrimSpace(getenv("APPDATA")); appData != "" {
			return filepath.Join(appData, "hopbits", "credentials"), nil
		}
	}
	if xdg := strings.TrimSpace(getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "hopbits", "credentials"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("cannot determine home directory for credentials: %w", err)
	}
	return filepath.Join(home, ".config", "hopbits", "credentials"), nil
}

// Stored holds credentials saved on disk by 'hopbits login'.
type Stored struct {
	APIKey string `json:"api_key"`
	APIURL string `json:"api_url,omitempty"`
}

// Load reads credentials from path. Accepts JSON ({"api_key":"..."}) or a
// plain single-line/key=value token format. Returns (Stored{}, nil) when the
// file does not exist.
func Load(path string) (Stored, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Stored{}, nil
	}
	if err != nil {
		return Stored{}, fmt.Errorf("reading %s: %w", path, err)
	}
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		return Stored{}, nil
	}
	if trimmed[0] == '{' {
		var s Stored
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return Stored{}, fmt.Errorf("parsing %s: %w", path, err)
		}
		s.APIKey = strings.TrimSpace(s.APIKey)
		s.APIURL = strings.TrimSpace(s.APIURL)
		return s, nil
	}
	var out Stored
	sc := bufio.NewScanner(bytes.NewReader(trimmed))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			k = strings.ToLower(strings.TrimSpace(k))
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			switch k {
			case "api_key", "hopbits_api_key", "hopbits_key", "token":
				out.APIKey = v
			case "api_url", "hopbits_api_url", "url":
				out.APIURL = v
			}
			continue
		}
		if out.APIKey == "" {
			out.APIKey = line
		}
	}
	return out, nil
}

// Save writes Stored to path with mode 0600 (creating parent directories with
// mode 0700). Uses atomic temp-file + rename in the target directory.
func Save(path string, s Stored) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	s.APIKey = strings.TrimSpace(s.APIKey)
	s.APIURL = strings.TrimSpace(s.APIURL)
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".credentials-*")
	if err != nil {
		return fmt.Errorf("creating temporary credentials file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("setting permissions on %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("saving %s: %w", path, err)
	}
	cleanup = false
	_ = os.Chmod(path, 0o600)
	return nil
}

// Resolved holds the resolved API key, base URL, and where the key came from.
type Resolved struct {
	APIKey string
	APIURL string
	Source string // "--api-key", "HOPBITS_API_KEY", "HOPBITS_KEY", or credentials path
}

// Resolve resolves auth and endpoint in priority order:
//  1. flagKey -> HOPBITS_API_KEY -> HOPBITS_KEY -> credentials file
//  2. flagURL -> HOPBITS_API_URL -> credentials file api_url -> https://api.hopbits.io
func Resolve(flagKey, flagURL string, getenv func(string) string) (Resolved, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	var stored Stored
	var credPath string
	if p, err := CredentialsPath(getenv); err == nil {
		credPath = p
		if s, lErr := Load(p); lErr == nil {
			stored = s
		}
	}

	var res Resolved
	switch {
	case strings.TrimSpace(flagKey) != "":
		res.APIKey = strings.TrimSpace(flagKey)
		res.Source = "--api-key"
	case strings.TrimSpace(getenv("HOPBITS_API_KEY")) != "":
		res.APIKey = strings.TrimSpace(getenv("HOPBITS_API_KEY"))
		res.Source = "HOPBITS_API_KEY"
	case strings.TrimSpace(getenv("HOPBITS_KEY")) != "":
		res.APIKey = strings.TrimSpace(getenv("HOPBITS_KEY"))
		res.Source = "HOPBITS_KEY"
	case stored.APIKey != "":
		res.APIKey = stored.APIKey
		res.Source = credPath
	}

	switch {
	case strings.TrimSpace(flagURL) != "":
		res.APIURL = strings.TrimRight(strings.TrimSpace(flagURL), "/")
	case strings.TrimSpace(getenv("HOPBITS_API_URL")) != "":
		res.APIURL = strings.TrimRight(strings.TrimSpace(getenv("HOPBITS_API_URL")), "/")
	case stored.APIURL != "" && res.Source == credPath:
		res.APIURL = strings.TrimRight(stored.APIURL, "/")
	default:
		res.APIURL = api.DefaultBaseURL
	}

	if res.APIKey == "" {
		return res, ErrNoAPIKey
	}
	return res, nil
}
