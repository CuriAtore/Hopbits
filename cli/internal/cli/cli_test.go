package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/hopbits/cli/internal/api"
	"github.com/hopbits/cli/internal/cli"
)

// mockBackend simulates the Hopbits /v1 REST contract in memory for end-to-end CLI tests.
type mockBackend struct {
	mu          sync.Mutex
	apiKey      string
	userAgents  []string
	credits     api.Credits
	checks      []api.Check
	putCalls    []api.CheckSpec
	deleteCalls []string
	patchCalls  map[string]string

	measReq       api.MeasurementRequest
	measPolls     int
	lastWaitQuery string
	measInProg    *api.Measurement
	measFinished  api.Measurement
}

func newMockBackend(apiKey string) *mockBackend {
	return &mockBackend{
		apiKey: apiKey,
		credits: api.Credits{
			Available:      4000,
			GrantAvailable: 1000,
			Reserved:       0,
			TotalAvailable: 5000,
			Currency:       "credits",
		},
		patchCalls: make(map[string]string),
	}
}

func (b *mockBackend) handler() http.Handler {
	mux := http.NewServeMux()

	authOK := func(w http.ResponseWriter, r *http.Request) bool {
		b.mu.Lock()
		b.userAgents = append(b.userAgents, r.Header.Get("User-Agent"))
		b.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+b.apiKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]string{"code": "unauthorized", "message": "invalid API key"},
			})
			return false
		}
		return true
	}

	mux.HandleFunc("GET /v1/credits", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		writeJSONResp(w, http.StatusOK, b.credits)
	})

	mux.HandleFunc("GET /v1/network", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]any{
			"online_nodes": 14,
			"countries": []map[string]any{
				{"country": "DE", "nodes": 6},
				{"country": "US", "nodes_online": 5},
				{"country": "SG", "count": "3"},
			},
		})
	})

	mux.HandleFunc("GET /v1/checks", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		writeJSONResp(w, http.StatusOK, map[string]any{"checks": b.checks})
	})

	mux.HandleFunc("PATCH /v1/checks/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		id := r.PathValue("id")
		var body struct {
			Key *string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Key == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		for i := range b.checks {
			if b.checks[i].ID == id {
				b.checks[i].Key = *body.Key
				b.patchCalls[id] = *body.Key
				writeJSONResp(w, http.StatusOK, b.checks[i])
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc("POST /v1/checks/plan", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		var req api.PlanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()

		existingByKey := map[string]api.Check{}
		for _, c := range b.checks {
			if c.Key != "" {
				existingByKey[c.Key] = c
			}
		}
		seen := map[string]bool{}
		var actions []api.PlanAction
		var sum api.PlanSummary

		for _, spec := range req.Checks {
			seen[spec.Key] = true
			cpr := max(1, len(spec.Locations)) * 3
			perDay := int64(0)
			if !spec.Paused && spec.IntervalSeconds > 0 {
				perDay = (int64(cpr) * 86400) / int64(spec.IntervalSeconds)
			}
			ex, exists := existingByKey[spec.Key]
			if !exists {
				sum.Create++
				sum.EstimatedCreditsPerDay += perDay
				actions = append(actions, api.PlanAction{
					Key:                    spec.Key,
					Name:                   spec.Name,
					Target:                 spec.Target,
					Action:                 api.ActionCreate,
					ChangedFields:          []string{},
					CreditsPerRun:          cpr,
					EstimatedCreditsPerDay: perDay,
				})
				continue
			}
			changed := diffSpec(ex, spec)
			if len(changed) == 0 {
				sum.Unchanged++
				sum.EstimatedCreditsPerDay += perDay
				actions = append(actions, api.PlanAction{
					Key:                    spec.Key,
					ID:                     ex.ID,
					Name:                   spec.Name,
					Target:                 spec.Target,
					Action:                 api.ActionUnchanged,
					ChangedFields:          []string{},
					CreditsPerRun:          cpr,
					EstimatedCreditsPerDay: perDay,
				})
			} else {
				sum.Update++
				sum.EstimatedCreditsPerDay += perDay
				actions = append(actions, api.PlanAction{
					Key:                    spec.Key,
					ID:                     ex.ID,
					Name:                   spec.Name,
					Target:                 spec.Target,
					Action:                 api.ActionUpdate,
					ChangedFields:          changed,
					CreditsPerRun:          cpr,
					EstimatedCreditsPerDay: perDay,
				})
			}
		}

		if req.Prune {
			// Unkeyed checks (c.Key == "") are NEVER marked delete!
			for _, c := range b.checks {
				if c.Key != "" && !seen[c.Key] {
					sum.Delete++
					actions = append(actions, api.PlanAction{
						Key:           c.Key,
						ID:            c.ID,
						Name:          c.Name,
						Target:        c.Target,
						Action:        api.ActionDelete,
						ChangedFields: []string{},
					})
				}
			}
		}

		writeJSONResp(w, http.StatusOK, api.Plan{Actions: actions, Summary: sum})
	})

	mux.HandleFunc("PUT /v1/checks/by-key/{key}", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		key := r.PathValue("key")
		var spec api.CheckSpec
		if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		spec.Key = key
		b.mu.Lock()
		defer b.mu.Unlock()
		b.putCalls = append(b.putCalls, spec)

		port := uint16(443)
		if spec.Port != nil {
			port = *spec.Port
		} else if spec.Type == "icmp_ping" {
			port = 0
		}

		for i := range b.checks {
			if b.checks[i].Key == key {
				b.checks[i].Name = spec.Name
				b.checks[i].Type = spec.Type
				b.checks[i].Target = spec.Target
				b.checks[i].Port = port
				b.checks[i].Family = spec.Family
				b.checks[i].Method = spec.Method
				b.checks[i].Path = spec.Path
				b.checks[i].IntervalSeconds = spec.IntervalSeconds
				b.checks[i].Locations = slices.Clone(spec.Locations)
				b.checks[i].AlertEmail = spec.AlertEmail
				b.checks[i].WebhookURL = spec.WebhookURL
				if spec.WebhookURL == "" {
					b.checks[i].HasWebhookSecret = false
				} else if spec.WebhookSecret != "" {
					b.checks[i].HasWebhookSecret = true
				}
				b.checks[i].Paused = spec.Paused
				writeJSONResp(w, http.StatusOK, b.checks[i])
				return
			}
		}

		created := api.Check{
			ID:               "chk_new_" + key,
			Key:              key,
			Name:             spec.Name,
			Type:             spec.Type,
			Target:           spec.Target,
			Port:             port,
			Family:           spec.Family,
			Method:           spec.Method,
			Path:             spec.Path,
			IntervalSeconds:  spec.IntervalSeconds,
			Locations:        slices.Clone(spec.Locations),
			AlertEmail:       spec.AlertEmail,
			WebhookURL:       spec.WebhookURL,
			HasWebhookSecret: spec.WebhookSecret != "",
			Paused:           spec.Paused,
			Status:           "healthy",
		}
		b.checks = append(b.checks, created)
		writeJSONResp(w, http.StatusCreated, created)
	})

	mux.HandleFunc("DELETE /v1/checks/by-key/{key}", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		key := r.PathValue("key")
		b.mu.Lock()
		defer b.mu.Unlock()
		b.deleteCalls = append(b.deleteCalls, key)
		for i := range b.checks {
			if b.checks[i].Key == key {
				b.checks = append(b.checks[:i], b.checks[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc("POST /v1/measurements", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		var req api.MeasurementRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		b.measReq = req
		b.measPolls = 0
		assigned := b.measFinished.Assigned
		reqCount := b.measFinished.Requested
		b.mu.Unlock()

		writeJSONResp(w, http.StatusAccepted, api.MeasurementCreated{
			ID:              "meas_test_1",
			Requested:       reqCount,
			Assigned:        assigned,
			CreditsReserved: int64(assigned),
		})
	})

	mux.HandleFunc("GET /v1/measurements/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(w, r) {
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		b.measPolls++
		b.lastWaitQuery = r.URL.Query().Get("wait")
		if b.measPolls == 1 && b.measInProg != nil {
			writeJSONResp(w, http.StatusOK, b.measInProg)
			return
		}
		writeJSONResp(w, http.StatusOK, b.measFinished)
	})

	return mux
}

func diffSpec(ex api.Check, spec api.CheckSpec) []string {
	var out []string
	if ex.Name != spec.Name {
		out = append(out, "name")
	}
	if ex.Type != spec.Type {
		out = append(out, "type")
	}
	if ex.Target != spec.Target {
		out = append(out, "target")
	}
	wantPort := uint16(443)
	if spec.Type == "icmp_ping" {
		wantPort = 0
	}
	if spec.Port != nil {
		wantPort = *spec.Port
	}
	if ex.Port != wantPort {
		out = append(out, "port")
	}
	if ex.Family != spec.Family {
		out = append(out, "family")
	}
	if ex.Method != spec.Method {
		out = append(out, "method")
	}
	if ex.Path != spec.Path {
		out = append(out, "path")
	}
	if ex.IntervalSeconds != spec.IntervalSeconds {
		out = append(out, "interval_seconds")
	}
	if !slices.Equal(ex.Locations, spec.Locations) {
		out = append(out, "locations")
	}
	if ex.AlertEmail != spec.AlertEmail {
		out = append(out, "alert_email")
	}
	if ex.WebhookURL != spec.WebhookURL {
		out = append(out, "webhook_url")
	}
	if spec.WebhookSecret != "" {
		out = append(out, "webhook_secret")
	}
	if ex.Paused != spec.Paused {
		out = append(out, "paused")
	}
	return out
}

func writeJSONResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func runCLI(t *testing.T, srv *httptest.Server, envMap map[string]string, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := cli.Run(context.Background(), args, cli.Env{
		Stdin:      strings.NewReader(stdin),
		Stdout:     &stdout,
		Stderr:     &stderr,
		HTTPClient: srv.Client(),
		Version:    "0.1.0-test",
		Getenv: func(k string) string {
			return envMap[k]
		},
	})
	return code, stdout.String(), stderr.String()
}

func TestVersionLoginAndWhoami(t *testing.T) {
	mb := newMockBackend("hb_live_valid123")
	mb.checks = []api.Check{
		{ID: "chk_1", Key: "api", Name: "API", Type: "http", Target: "api.example.com", Paused: false},
		{ID: "chk_2", Name: "Legacy Console Check", Type: "http", Target: "old.example.com", Paused: true},
	}
	srv := httptest.NewServer(mb.handler())
	defer srv.Close()

	credPath := filepath.Join(t.TempDir(), "hopbits", "credentials")
	env := map[string]string{
		"HOPBITS_CREDENTIALS_FILE": credPath,
		"HOPBITS_API_URL":          srv.URL,
	}

	// 1. version & --version
	code, out, _ := runCLI(t, srv, env, "", "--version")
	if code != 0 || !strings.Contains(out, "hopbits 0.1.0-test") {
		t.Fatalf("unexpected --version: code=%d out=%q", code, out)
	}

	// 2. login with invalid key fails and does not create credentials file
	code, _, errOut := runCLI(t, srv, env, "hb_live_wrong\n", "login")
	if code != 1 || !strings.Contains(errOut, "401") {
		t.Fatalf("expected login failure on bad key: code=%d stderr=%q", code, errOut)
	}
	if _, statErr := os.Stat(credPath); !os.IsNotExist(statErr) {
		t.Fatalf("credentials file must not be written when verification fails")
	}

	// 3. login with valid key verifies GET /v1/credits and saves credentials
	code, out, errOut = runCLI(t, srv, env, "hb_live_valid123\n", "login")
	if code != 0 || !strings.Contains(out, "5000 credits") {
		t.Fatalf("login failed: code=%d out=%q err=%q", code, out, errOut)
	}

	// 4. whoami uses saved credentials and sends User-Agent: hopbits-cli/0.1.0-test
	delete(env, "HOPBITS_API_URL") // saved credentials also stored custom srv.URL!
	code, out, errOut = runCLI(t, srv, env, "", "whoami", "--json")
	if code != 0 {
		t.Fatalf("whoami --json failed: code=%d err=%q", code, errOut)
	}
	var who struct {
		Credits api.Credits `json:"credits"`
		Checks  struct {
			Total  int `json:"total"`
			Active int `json:"active"`
			Paused int `json:"paused"`
		} `json:"checks"`
		Network struct {
			OnlineNodes     int `json:"online_nodes"`
			CountriesOnline int `json:"countries_online"`
		} `json:"network"`
	}
	if err := json.Unmarshal([]byte(out), &who); err != nil {
		t.Fatalf("decode whoami json: %v\n%s", err, out)
	}
	if who.Credits.TotalAvailable != 5000 || who.Checks.Total != 2 || who.Checks.Active != 1 || who.Checks.Paused != 1 {
		t.Fatalf("unexpected whoami counts: %+v", who)
	}
	if who.Network.OnlineNodes != 14 || who.Network.CountriesOnline != 3 {
		t.Fatalf("unexpected whoami network: %+v", who.Network)
	}
	mb.mu.Lock()
	ua := mb.userAgents[len(mb.userAgents)-1]
	mb.mu.Unlock()
	if ua != "hopbits-cli/0.1.0-test" {
		t.Fatalf("expected User-Agent hopbits-cli/0.1.0-test, got %q", ua)
	}
}

func TestPlanDetailedExitCodeAndApplyPruneSafety(t *testing.T) {
	mb := newMockBackend("hb_live_ci")
	mb.checks = []api.Check{
		{
			ID:              "chk_keep",
			Key:             "unchanged-mon",
			Name:            "Unchanged",
			Type:            "http",
			Target:          "ok.example.com",
			Port:            443,
			Method:          "HEAD",
			IntervalSeconds: 300,
			Locations:       []string{"ANY"},
			AlertEmail:      true,
			Paused:          false,
		},
		{
			ID:              "chk_upd",
			Key:             "paused-mon",
			Name:            "Paused Mon",
			Type:            "http",
			Target:          "paused.example.com",
			Port:            443,
			Method:          "HEAD",
			IntervalSeconds: 300,
			Locations:       []string{"DE"},
			AlertEmail:      true,
			Paused:          true, // removing paused: true in YAML must unpause it!
		},
		{
			ID:              "chk_stale_keyed",
			Key:             "obsolete-service",
			Name:            "Obsolete Service",
			Type:            "http",
			Target:          "old.example.com",
			Port:            443,
			Method:          "HEAD",
			IntervalSeconds: 300,
			Locations:       []string{"ANY"},
		},
		{
			ID:              "chk_unkeyed_console",
			Key:             "", // Unkeyed Console monitor: MUST NEVER be deleted by --prune!
			Name:            "Manual Console Check",
			Type:            "http",
			Target:          "manual.example.com",
			Port:            443,
			Method:          "HEAD",
			IntervalSeconds: 300,
			Locations:       []string{"ANY"},
		},
	}
	srv := httptest.NewServer(mb.handler())
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hopbits.yaml")
	yamlContent := `version: 1
monitors:
  - key: unchanged-mon
    name: Unchanged
    target: ok.example.com
    interval: 5m

  - key: paused-mon
    name: Paused Mon
    target: paused.example.com
    locations: [DE]
    interval: 5m

  - key: new-checkout
    name: New Checkout
    target: https://checkout.example.com/healthz
    method: GET
    interval: 1m
    locations: [DE, US]
`
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	env := map[string]string{
		"HOPBITS_KEY":     "hb_live_ci", // test HOPBITS_KEY fallback alias!
		"HOPBITS_API_URL": srv.URL,
	}

	// 1. plan --detailed-exitcode --prune exits 2 when create+update+delete > 0
	code, out, errOut := runCLI(t, srv, env, "", "plan", "-f", cfgPath, "--prune", "--detailed-exitcode")
	if code != 2 {
		t.Fatalf("expected exit code 2 for pending changes, got %d\nout:\n%s\nerr:\n%s", code, out, errOut)
	}
	for _, want := range []string{"+ create", "~ update", "= unchanged", "- delete", "obsolete-service", "changed: paused"} {
		if !strings.Contains(out, want) {
			t.Fatalf("plan output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Manual Console Check") {
		t.Fatalf("unkeyed console check must never appear in --prune delete plan:\n%s", out)
	}

	// 2. apply --dry-run makes zero PUT or DELETE mutations
	code, out, errOut = runCLI(t, srv, env, "", "apply", "-f", cfgPath, "--prune", "--dry-run")
	if code != 0 || len(mb.putCalls) != 0 || len(mb.deleteCalls) != 0 {
		t.Fatalf("dry-run must not mutate: code=%d puts=%d deletes=%d err=%q", code, len(mb.putCalls), len(mb.deleteCalls), errOut)
	}

	// 3. apply --prune reconciles ONLY create + update + keyed delete, leaving unkeyed untouched
	code, out, errOut = runCLI(t, srv, env, "", "apply", "-f", cfgPath, "--prune")
	if code != 0 {
		t.Fatalf("apply --prune failed: code=%d err=%q\nout:\n%s", code, errOut, out)
	}
	if len(mb.putCalls) != 2 {
		t.Fatalf("expected exactly 2 PUT calls (create + update, skipping unchanged), got %d: %+v", len(mb.putCalls), mb.putCalls)
	}
	if len(mb.deleteCalls) != 1 || mb.deleteCalls[0] != "obsolete-service" {
		t.Fatalf("expected exactly 1 DELETE for obsolete-service, got %+v", mb.deleteCalls)
	}

	// Verify unkeyed check survived AND paused-mon was unpaused (Paused == false)!
	var sawUnkeyed, sawUnpaused bool
	for _, c := range mb.checks {
		if c.ID == "chk_unkeyed_console" {
			sawUnkeyed = true
		}
		if c.Key == "paused-mon" && !c.Paused {
			sawUnpaused = true
		}
	}
	if !sawUnkeyed || !sawUnpaused {
		t.Fatalf("expected unkeyed check preserved (%v) and paused-mon unpaused (%v): %+v", sawUnkeyed, sawUnpaused, mb.checks)
	}

	// 4. Subsequent plan --detailed-exitcode --prune exits 0 (idempotent zero-diff)!
	code, out, errOut = runCLI(t, srv, env, "", "plan", "-f", cfgPath, "--prune", "--detailed-exitcode")
	if code != 0 {
		t.Fatalf("expected exit 0 after apply converged, got %d\nout:\n%s\nerr:\n%s", code, out, errOut)
	}
}

func TestExportAdoptPreservesExistingMonitorsInPlace(t *testing.T) {
	mb := newMockBackend("hb_live_export")
	mb.checks = []api.Check{
		{
			ID:               "chk_legacy_1",
			Key:              "",
			Name:             "Billing API",
			Type:             "http",
			Target:           "billing.example.com",
			Port:             443,
			Method:           "GET",
			Path:             "/readyz",
			IntervalSeconds:  60,
			Locations:        []string{"DE", "US"},
			AlertEmail:       true,
			WebhookURL:       "https://hooks.example.com/billing",
			HasWebhookSecret: true,
		},
		{
			ID:              "chk_legacy_2",
			Key:             "",
			Name:            "Billing API", // Duplicate display name -> must deduplicate to billing-api-2!
			Type:            "tcp_connect",
			Target:          "billing-db.example.com",
			Port:            5432,
			IntervalSeconds: 600,
			Locations:       []string{"DE"},
			AlertEmail:      false,
		},
	}
	srv := httptest.NewServer(mb.handler())
	defer srv.Close()

	env := map[string]string{
		"HOPBITS_API_KEY": "hb_live_export",
		"HOPBITS_API_URL": srv.URL,
	}

	outFile := filepath.Join(t.TempDir(), "hopbits.yaml")
	if err := os.WriteFile(outFile, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Refuses to overwrite without --force AND makes zero PATCH calls!
	code, _, errOut := runCLI(t, srv, env, "", "export", "--adopt", "-o", outFile)
	if code != 1 || !strings.Contains(errOut, "--force") || len(mb.patchCalls) != 0 {
		t.Fatalf("expected overwrite refusal before any PATCH: code=%d patches=%d err=%q", code, len(mb.patchCalls), errOut)
	}

	// With --force --adopt, assigns keys via PATCH and writes clean YAML
	code, out, errOut := runCLI(t, srv, env, "", "export", "--adopt", "--force", "-o", outFile)
	if code != 0 {
		t.Fatalf("export --adopt --force failed: code=%d err=%q out=%q", code, errOut, out)
	}
	if mb.patchCalls["chk_legacy_1"] != "billing-api" || mb.patchCalls["chk_legacy_2"] != "billing-api-2" {
		t.Fatalf("unexpected PATCH adoptions: %+v", mb.patchCalls)
	}

	// Running plan --detailed-exitcode against exported file shows 0 changes (adopted in place!)
	code, planOut, errOut := runCLI(t, srv, env, "", "plan", "-f", outFile, "--prune", "--detailed-exitcode")
	if code != 0 {
		t.Fatalf("expected 0 changes right after export --adopt, got code=%d\nplan:\n%s\nerr:\n%s", code, planOut, errOut)
	}
}

func TestProbePollingAndAssertions(t *testing.T) {
	mb := newMockBackend("hb_live_probe")
	mb.measInProg = &api.Measurement{
		ID:        "meas_test_1",
		Type:      "http",
		Target:    "api.example.com",
		Status:    "in-progress",
		Requested: 3,
		Assigned:  3,
		Results: []api.MeasurementResult{
			{Country: "DE", ASN: 3320, NetworkClass: "residential", Outcome: "ok", Result: json.RawMessage(`{"status_code":200,"phases":{"total_us":42000}}`)},
		},
	}
	mb.measFinished = api.Measurement{
		ID:             "meas_test_1",
		Type:           "http",
		Target:         "api.example.com",
		Status:         "finished",
		Requested:      3,
		Assigned:       3,
		CreditsCharged: 3,
		Results: []api.MeasurementResult{
			{Country: "DE", ASN: 3320, NetworkClass: "residential", Outcome: "ok", Result: json.RawMessage(`{"status_code":200,"phases":{"total_us":42000}}`)},
			{Country: "US", ASN: 7922, NetworkClass: "residential", Outcome: "ok", Result: json.RawMessage(`{"status_code":200,"phases":{"total_us":118000}}`)},
			{Country: "SG", ASN: 4773, NetworkClass: "mobile", Outcome: "ok", Result: json.RawMessage(`{"status_code":200,"phases":{"total_us":245000}}`)},
		},
	}
	srv := httptest.NewServer(mb.handler())
	defer srv.Close()

	env := map[string]string{
		"HOPBITS_API_KEY": "hb_live_probe",
		"HOPBITS_API_URL": srv.URL,
	}

	// 1. Passing gate (flags placed AFTER positional URL!)
	code, out, errOut := runCLI(t, srv, env, "", "probe", "https://api.example.com/healthz",
		"--from", "DE,US,SG", "--network", "residential", "--expect-status", "200", "--max-p95", "300ms", "--min-ok", "3")
	if code != 0 {
		t.Fatalf("expected probe to pass: code=%d err=%q\nout:\n%s", code, errOut, out)
	}
	if mb.measPolls < 2 {
		t.Fatalf("expected probe to re-poll in-progress measurement, polls=%d", mb.measPolls)
	}
	if mb.measReq.Target != "api.example.com" || mb.measReq.Params["path"] != "/healthz" {
		t.Fatalf("expected URL host/path extraction in measurement request: %+v", mb.measReq)
	}
	for _, want := range []string{"COUNTRY", "NETWORK", "ASN", "STATUS", "RTT", "AS3320", "42.0ms", "p95: 245.0ms", "credits: 3"} {
		if !strings.Contains(out, want) {
			t.Fatalf("probe table missing %q:\n%s", want, out)
		}
	}

	// 2. Failing --max-p95 threshold exits 1
	code, _, errOut = runCLI(t, srv, env, "", "probe", "https://api.example.com/healthz", "--max-p95", "150ms")
	if code != 1 || !strings.Contains(errOut, "p95 latency 245.0ms exceeds --max-p95 150ms") {
		t.Fatalf("expected p95 failure exit 1: code=%d err=%q", code, errOut)
	}

	// 3. Failing --expect-status exits 1
	mb.measFinished.Results[2].Result = json.RawMessage(`{"status_code":503,"phases":{"total_us":90000}}`)
	code, _, errOut = runCLI(t, srv, env, "", "probe", "https://api.example.com/healthz", "--expect-status", "200")
	if code != 1 || !strings.Contains(errOut, "SG returned HTTP 503 (expected 200)") {
		t.Fatalf("expected HTTP status assertion failure: code=%d err=%q", code, errOut)
	}

	// 4. Failing --min-ok / 0 ok probes exits 1
	mb.measInProg = nil
	mb.measFinished.Results = []api.MeasurementResult{
		{Country: "DE", Outcome: "timeout", Error: "deadline_exceeded"},
	}
	code, _, errOut = runCLI(t, srv, env, "", "probe", "https://api.example.com/healthz")
	if code != 1 || !strings.Contains(errOut, "0 probes succeeded") {
		t.Fatalf("expected 0 ok probes to exit 1: code=%d err=%q", code, errOut)
	}
}

func TestZeroCGOCrossCompileMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-compile check in -short mode")
	}
	targets := []struct {
		goos   string
		goarch string
		ext    string
	}{
		{"linux", "amd64", ""},
		{"linux", "arm64", ""},
		{"darwin", "amd64", ""},
		{"darwin", "arm64", ""},
		{"windows", "amd64", ".exe"},
	}

	outDir := t.TempDir()
	modRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}

	for _, tg := range targets {
		bin := filepath.Join(outDir, "hopbits-"+tg.goos+"-"+tg.goarch+tg.ext)
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w -X main.version=0.2.0", "-o", bin, "./cmd/hopbits")
		cmd.Dir = modRoot
		cmd.Env = append(os.Environ(),
			"CGO_ENABLED=0",
			"GOWORK=off",
			"GOOS="+tg.goos,
			"GOARCH="+tg.goarch,
		)
		if out, bErr := cmd.CombinedOutput(); bErr != nil {
			t.Fatalf("cross-compile %s/%s failed: %v\n%s", tg.goos, tg.goarch, bErr, string(out))
		}
		info, sErr := os.Stat(bin)
		if sErr != nil || info.Size() == 0 {
			t.Fatalf("missing built binary for %s/%s: %v", tg.goos, tg.goarch, sErr)
		}
	}
}

func TestProbeDiagnosticsKindsAndWait(t *testing.T) {
	mb := newMockBackend("hb_live_diag")
	srv := httptest.NewServer(mb.handler())
	defer srv.Close()

	env := map[string]string{
		"HOPBITS_API_KEY": "hb_live_diag",
		"HOPBITS_API_URL": srv.URL,
	}

	// 1. DNS lookup (_dmarc.hopbits.io TXT via ISP resolver)
	mb.measFinished = api.Measurement{
		ID:             "meas_dns_1",
		Type:           "dns",
		Target:         "_dmarc.hopbits.io",
		Status:         "finished",
		Requested:      2,
		Assigned:       2,
		CreditsCharged: 2,
		Results: []api.MeasurementResult{
			{
				Country:      "DE",
				ASN:          3320,
				NetworkClass: "residential",
				Outcome:      "ok",
				Result:       json.RawMessage(`{"qname":"_dmarc.hopbits.io","qtype":"TXT","resolver":"isp","protocol":"udp","rcode":"NOERROR","rcode_num":0,"rtt_us":14200,"answers":[{"name":"_dmarc.hopbits.io","type":"TXT","ttl":300,"data":"v=DMARC1; p=reject"}]}`),
			},
			{
				Country:      "US",
				ASN:          7922,
				NetworkClass: "residential",
				Outcome:      "ok",
				Result:       json.RawMessage(`{"qname":"_dmarc.hopbits.io","qtype":"TXT","resolver":"isp","protocol":"tcp","rcode":"NXDOMAIN","rcode_num":3,"rtt_us":22500}`),
			},
		},
	}
	code, out, errOut := runCLI(t, srv, env, "", "probe", "_dmarc.hopbits.io", "--type", "dns", "--qtype", "TXT", "--resolver", "isp", "--proto", "udp")
	if code != 0 {
		t.Fatalf("dns probe failed: code=%d err=%q\nout:\n%s", code, errOut, out)
	}
	if mb.measReq.Type != "dns" || mb.measReq.Target != "_dmarc.hopbits.io" || mb.measReq.Params["qtype"] != "TXT" || mb.measReq.Params["resolver"] != "isp" {
		t.Fatalf("unexpected dns request: %+v", mb.measReq)
	}
	for _, want := range []string{"RESOLVER", "ANSWERS", "ISP", "NOERROR", "NXDOMAIN", "v=DMARC1; p=reject (300s)", "14.2ms"} {
		if !strings.Contains(out, want) {
			t.Fatalf("dns output missing %q:\n%s", want, out)
		}
	}

	// 2. Traceroute (redacted Hop 1 + enriched intermediate hop + destination reached)
	mb.measFinished = api.Measurement{
		ID:             "meas_tr_1",
		Type:           "traceroute",
		Target:         "hopbits.io",
		Status:         "finished",
		Requested:      1,
		Assigned:       1,
		CreditsCharged: 1,
		Results: []api.MeasurementResult{
			{
				Country:      "DE",
				ASN:          3320,
				NetworkClass: "residential",
				Outcome:      "ok",
				Result: json.RawMessage(`{
					"protocol":"udp","destination_reached":true,"total_hops":3,"rtt_us":18400,
					"hops":[
						{"hop":1,"redacted":true,"sent":3,"received":3,"rtt_us":[1200,1300,1400],"min_us":1200,"median_us":1300,"max_us":1400},
						{"hop":2,"ip":"80.81.192.1","asn":6695,"as_name":"DE-CIX","country":"DE","city":"Frankfurt","sent":3,"received":2,"rtt_us":[8200,null,8600],"min_us":8200,"median_us":8400,"max_us":8600},
						{"hop":3,"ip":"104.21.48.12","asn":13335,"as_name":"Cloudflare","country":"DE","city":"Frankfurt","sent":3,"received":3,"rtt_us":[18100,18400,18900],"min_us":18100,"median_us":18400,"max_us":18900}
					]
				}`),
			},
		},
	}
	code, out, errOut = runCLI(t, srv, env, "", "probe", "hopbits.io", "--type", "traceroute", "--proto", "udp", "--max-hops", "24", "--wait", "22")
	if code != 0 {
		t.Fatalf("traceroute probe failed: code=%d err=%q\nout:\n%s", code, errOut, out)
	}
	if mb.lastWaitQuery != "22" {
		t.Fatalf("expected ?wait=22 on GET /v1/measurements, got %q", mb.lastWaitQuery)
	}
	for _, want := range []string{"local gateway (hidden)", "AS6695 DE-CIX", "Frankfurt, DE", "destination reached", "18.4ms"} {
		if !strings.Contains(out, want) {
			t.Fatalf("traceroute output missing %q:\n%s", want, out)
		}
	}

	// 3. MTR (--cycles 5, auto ?wait=20, loss% & stdev table)
	mb.measFinished = api.Measurement{
		ID:             "meas_mtr_1",
		Type:           "mtr",
		Target:         "hopbits.io",
		Status:         "finished",
		Requested:      1,
		Assigned:       1,
		CreditsCharged: 2,
		Results: []api.MeasurementResult{
			{
				Country:      "LT",
				ASN:          8764,
				NetworkClass: "residential",
				Outcome:      "ok",
				Result: json.RawMessage(`{
					"protocol":"icmp","cycles":5,"destination_reached":true,"total_hops":2,"rtt_us":12600,
					"hops":[
						{"hop":1,"redacted":true,"sent":5,"received":5,"loss_pct":0,"last_us":1100,"min_us":950,"avg_us":1080,"max_us":1250,"stdev_us":110},
						{"hop":2,"ip":"104.21.48.12","asn":13335,"as_name":"Cloudflare","country":"LT","city":"Vilnius","sent":5,"received":4,"loss_pct":20.0,"last_us":12600,"min_us":12100,"avg_us":12500,"max_us":13100,"stdev_us":400}
					]
				}`),
			},
		},
	}
	code, out, errOut = runCLI(t, srv, env, "", "probe", "hopbits.io", "--type", "mtr", "--proto", "icmp", "--cycles", "5", "--max-hops", "20")
	if code != 0 {
		t.Fatalf("mtr probe failed: code=%d err=%q\nout:\n%s", code, errOut, out)
	}
	if mb.lastWaitQuery != "20" {
		t.Fatalf("expected default ?wait=20 for mtr, got %q", mb.lastWaitQuery)
	}
	for _, want := range []string{"LOSS%", "STDEV", "5 cycles", "20.0%", "Vilnius, LT", "credits: 2"} {
		if !strings.Contains(out, want) {
			t.Fatalf("mtr output missing %q:\n%s", want, out)
		}
	}
}
