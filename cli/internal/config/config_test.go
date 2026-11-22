package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/hopbits/cli/internal/api"
)

func TestParseBytesYAMLAndEnvInterpolation(t *testing.T) {
	yamlDoc := `
# Comment mentioning ${DO_NOT_EXPAND_COMMENT} must NEVER fail!
version: 1 # inline comment ${ALSO_IGNORED}
monitors:
  - key: checkout-api
    name: Checkout API
    type: http
    target: https://api.example.com:8443/healthz
    method: GET
    interval: 1m
    locations: [de, us]
    webhook_url: https://hooks.example.com/${HOOK_PATH:-default-hook}
    webhook_secret: ${CHECKOUT_SECRET}
    alert_email: false

  - key: edge-tcp
    type: tcp
    target: edge.example.com
    port: 443
    interval_seconds: 900
    paused: true

  - key: core-icmp
    type: icmp
    target: 2001:db8::1
    family: ipv6
    interval: 1h
`
	env := map[string]string{
		"CHECKOUT_SECRET": "whsec_live_secret_$123",
	}
	cfg, err := ParseBytes("hopbits.yaml", []byte(yamlDoc), func(k string) string {
		return env[k]
	})
	if err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}
	if cfg.Version != 1 || len(cfg.Monitors) != 3 {
		t.Fatalf("unexpected parsed file: version=%d len=%d", cfg.Version, len(cfg.Monitors))
	}

	m0 := cfg.Monitors[0]
	if m0.Key != "checkout-api" || m0.Name != "Checkout API" || m0.Type != "http" {
		t.Fatalf("unexpected m0 identity: %+v", m0)
	}
	if m0.Target != "api.example.com" || m0.Port == nil || *m0.Port != 8443 || m0.Path != "/healthz" || m0.Method != "GET" {
		t.Fatalf("unexpected URL extraction on m0: target=%q port=%v path=%q method=%q", m0.Target, m0.Port, m0.Path, m0.Method)
	}
	if m0.IntervalSeconds != 60 {
		t.Fatalf("expected interval 60s, got %d", m0.IntervalSeconds)
	}
	if strings.Join(m0.Locations, ",") != "DE,US" {
		t.Fatalf("expected locations DE,US, got %v", m0.Locations)
	}
	if m0.WebhookURL != "https://hooks.example.com/default-hook" {
		t.Fatalf("expected default fallback in webhook_url, got %q", m0.WebhookURL)
	}
	if m0.WebhookSecret != "whsec_live_secret_$123" {
		t.Fatalf("expected expanded secret with preserved $, got %q", m0.WebhookSecret)
	}
	if m0.AlertEmail || m0.Paused {
		t.Fatalf("expected alert_email=false paused=false, got alert_email=%v paused=%v", m0.AlertEmail, m0.Paused)
	}

	m1 := cfg.Monitors[1]
	if m1.Name != "edge-tcp" || m1.Type != "tcp_connect" || m1.IntervalSeconds != 900 || !m1.Paused || !m1.AlertEmail {
		t.Fatalf("unexpected m1 defaults/normalization: %+v", m1)
	}
	if strings.Join(m1.Locations, ",") != "ANY" {
		t.Fatalf("expected default location [ANY], got %v", m1.Locations)
	}

	m2 := cfg.Monitors[2]
	if m2.Type != "icmp_ping" || m2.Target != "2001:db8::1" || m2.Family != "ipv6" || m2.IntervalSeconds != 3600 {
		t.Fatalf("unexpected m2 icmp ipv6 normalization: %+v", m2)
	}
}

func TestTargetURLOverridePrecedence(t *testing.T) {
	yamlDoc := `
version: 1
monitors:
  - key: override-test
    target: http://example.com:8080/from-url
    port: 8443
    path: /explicit-path
  - key: http-default-port
    target: http://plain.example.com/ready
`
	cfg, err := ParseBytes("hopbits.yaml", []byte(yamlDoc), func(string) string { return "" })
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	if *cfg.Monitors[0].Port != 8443 || cfg.Monitors[0].Path != "/explicit-path" || cfg.Monitors[0].Target != "example.com" {
		t.Fatalf("explicit port/path must override URL values, got %+v", cfg.Monitors[0])
	}
	if cfg.Monitors[1].Port == nil || *cfg.Monitors[1].Port != 80 || cfg.Monitors[1].Path != "/ready" {
		t.Fatalf("http:// URL without port must default port=80, got %+v", cfg.Monitors[1])
	}
}

func TestMissingEnvVarFailsFast(t *testing.T) {
	yamlDoc := `
version: 1
monitors:
  - key: billing-api
    target: billing.example.com
    webhook_url: https://hooks.example.com/alerts
    webhook_secret: ${MISSING_WEBHOOK_SECRET}
`
	_, err := ParseBytes("hopbits.yaml", []byte(yamlDoc), func(string) string { return "" })
	if err == nil {
		t.Fatal("expected MissingEnvError for unset ${MISSING_WEBHOOK_SECRET}, got nil")
	}
	var me *MissingEnvError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MissingEnvError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "MISSING_WEBHOOK_SECRET") {
		t.Fatalf("expected error message to name MISSING_WEBHOOK_SECRET, got: %v", err)
	}
}

func TestJSONConfigSupport(t *testing.T) {
	jsonDoc := `{
  "version": 1,
  "monitors": [
    {
      "key": "json_check_1",
      "target": "status.example.com",
      "interval": "30m",
      "locations": ["NL"]
    }
  ]
}`
	cfg, err := ParseBytes("hopbits.json", []byte(jsonDoc), func(string) string { return "" })
	if err != nil {
		t.Fatalf("ParseBytes JSON failed: %v", err)
	}
	if len(cfg.Monitors) != 1 || cfg.Monitors[0].Key != "json_check_1" || cfg.Monitors[0].IntervalSeconds != 1800 {
		t.Fatalf("unexpected JSON monitor: %+v", cfg.Monitors)
	}
}

func TestValidationRejectsInvalidConfigs(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "bad key uppercase",
			yaml: "version: 1\nmonitors:\n  - key: BadKey\n    target: example.com\n",
			want: "key",
		},
		{
			name: "duplicate key",
			yaml: "version: 1\nmonitors:\n  - key: dup\n    target: a.example.com\n  - key: dup\n    target: b.example.com\n",
			want: "duplicate key",
		},
		{
			name: "interval out of range",
			yaml: "version: 1\nmonitors:\n  - key: fast\n    target: example.com\n    interval: 10s\n",
			want: "between 30s and 1h",
		},
		{
			name: "unknown field",
			yaml: "version: 1\nmonitors:\n  - key: typo\n    target: example.com\n    intervl: 5m\n",
			want: "field intervl not found",
		},
		{
			name: "bad version",
			yaml: "version: 2\nmonitors: []\n",
			want: "unsupported version 2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseBytes("hopbits.yaml", []byte(tc.yaml), func(string) string { return "" })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestGenerateSlugAndRenderYAML(t *testing.T) {
	used := map[string]bool{"existing-key": true}
	s1 := GenerateSlug("Checkout API (Prod)!", "api.example.com", used)
	s2 := GenerateSlug("Checkout API (Prod)!", "api2.example.com", used)
	s3 := GenerateSlug("!!!", "https://edge.example.com/v1", used)

	if s1 != "checkout-api-prod" {
		t.Fatalf("expected checkout-api-prod, got %q", s1)
	}
	if s2 != "checkout-api-prod-2" {
		t.Fatalf("expected checkout-api-prod-2, got %q", s2)
	}
	if s3 != "edge-example-com-v1" {
		t.Fatalf("expected edge-example-com-v1, got %q", s3)
	}

	out, err := RenderYAML([]api.Check{
		{
			ID:               "chk_1",
			Key:              s1,
			Name:             "Checkout API",
			Type:             "http",
			Target:           "api.example.com",
			Port:             443,
			Method:           "GET",
			Path:             "/healthz",
			IntervalSeconds:  300,
			Locations:        []string{"DE", "US"},
			AlertEmail:       true,
			WebhookURL:       "https://hooks.example.com/hopbits",
			HasWebhookSecret: true,
		},
	})
	if err != nil {
		t.Fatalf("RenderYAML failed: %v", err)
	}
	rendered := string(out)
	if !strings.Contains(rendered, "interval: 5m") {
		t.Fatalf("expected human interval 5m in rendered YAML:\n%s", rendered)
	}
	if !strings.Contains(rendered, "HOPBITS_WEBHOOK_SECRET_CHECKOUT_API_PROD") {
		t.Fatalf("expected webhook secret comment in rendered YAML:\n%s", rendered)
	}
	// Round-trip parse back!
	parsed, err := ParseBytes("hopbits.yaml", out, func(string) string { return "" })
	if err != nil {
		t.Fatalf("round-trip ParseBytes failed: %v\nYAML:\n%s", err, rendered)
	}
	if len(parsed.Monitors) != 1 || parsed.Monitors[0].Key != s1 || parsed.Monitors[0].IntervalSeconds != 300 {
		t.Fatalf("unexpected round-trip monitor: %+v", parsed.Monitors)
	}
}
