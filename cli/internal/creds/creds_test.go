package creds

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolvePriorityAndSaveLoad(t *testing.T) {
	dir := t.TempDir()
	credFile := filepath.Join(dir, "hopbits", "credentials")

	if err := Save(credFile, Stored{APIKey: "hb_saved_key", APIURL: "https://saved.example.com/"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(credFile)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("expected 0600 permissions, got %o", perm)
		}
	}

	env := map[string]string{
		"HOPBITS_CREDENTIALS_FILE": credFile,
	}
	getenv := func(k string) string { return env[k] }

	// 1. Credentials file fallback
	r, err := Resolve("", "", getenv)
	if err != nil {
		t.Fatalf("Resolve saved: %v", err)
	}
	if r.APIKey != "hb_saved_key" || r.APIURL != "https://saved.example.com" {
		t.Fatalf("unexpected saved resolve: %+v", r)
	}

	// 2. HOPBITS_KEY alias overrides saved credentials
	env["HOPBITS_KEY"] = "hb_alias_key"
	r, err = Resolve("", "", getenv)
	if err != nil || r.APIKey != "hb_alias_key" || r.Source != "HOPBITS_KEY" {
		t.Fatalf("expected HOPBITS_KEY alias, got %+v err=%v", r, err)
	}

	// 3. HOPBITS_API_KEY overrides HOPBITS_KEY
	env["HOPBITS_API_KEY"] = "hb_primary_env"
	env["HOPBITS_API_URL"] = "https://env.example.com/"
	r, err = Resolve("", "", getenv)
	if err != nil || r.APIKey != "hb_primary_env" || r.APIURL != "https://env.example.com" {
		t.Fatalf("expected HOPBITS_API_KEY + HOPBITS_API_URL, got %+v err=%v", r, err)
	}

	// 4. --api-key and --api-url flags override everything
	r, err = Resolve("hb_flag_key", "https://flag.example.com/", getenv)
	if err != nil || r.APIKey != "hb_flag_key" || r.APIURL != "https://flag.example.com" || r.Source != "--api-key" {
		t.Fatalf("expected flag priority, got %+v err=%v", r, err)
	}
}
