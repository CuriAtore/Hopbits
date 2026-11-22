package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/hopbits/cli/internal/api"
)

var keyPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$`)

// ValidateKey checks that key matches ^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$.
func ValidateKey(key string) error {
	if !keyPattern.MatchString(key) {
		return fmt.Errorf("key %q must be 1..63 lowercase ASCII letters, digits, hyphens, or underscores, starting and ending with a letter or digit", key)
	}
	return nil
}

// ResolveFilePath picks the config path when -f is omitted: hopbits.yaml,
// falling back to hopbits.yml or hopbits.json if present.
func ResolveFilePath(flagPath string) string {
	if strings.TrimSpace(flagPath) != "" {
		return strings.TrimSpace(flagPath)
	}
	for _, candidate := range []string{"hopbits.yaml", "hopbits.yml", "hopbits.json"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return "hopbits.yaml"
}

// File is a parsed and validated hopbits.yaml / hopbits.json configuration.
type File struct {
	Path     string
	Version  int
	Monitors []api.CheckSpec
}

type rawFile struct {
	Version  *int         `yaml:"version" json:"version"`
	Monitors []rawMonitor `yaml:"monitors" json:"monitors"`
}

type rawInterval struct {
	set     bool
	seconds int
}

func (iv *rawInterval) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("interval must be a duration string (e.g. 5m) or integer seconds")
	}
	sec, err := ParseIntervalString(value.Value)
	if err != nil {
		return err
	}
	iv.set = true
	iv.seconds = sec
	return nil
}

type rawMonitor struct {
	Key             string       `yaml:"key" json:"key"`
	Name            string       `yaml:"name" json:"name"`
	Type            string       `yaml:"type" json:"type"`
	Target          string       `yaml:"target" json:"target"`
	Port            *int         `yaml:"port" json:"port"`
	Family          string       `yaml:"family" json:"family"`
	Method          string       `yaml:"method" json:"method"`
	Path            string       `yaml:"path" json:"path"`
	Interval        rawInterval  `yaml:"interval" json:"interval"`
	IntervalSeconds *int         `yaml:"interval_seconds" json:"interval_seconds"`
	Locations       []string     `yaml:"locations" json:"locations"`
	AlertEmail      *bool        `yaml:"alert_email" json:"alert_email"`
	WebhookURL      string       `yaml:"webhook_url" json:"webhook_url"`
	WebhookSecret   string       `yaml:"webhook_secret" json:"webhook_secret"`
	Paused          *bool        `yaml:"paused" json:"paused"`
}

// ParseIntervalString parses human interval strings ("30s", "60s", "1m", "5m",
// "10m", "15m", "30m", "1h") or integer seconds ("300").
func ParseIntervalString(raw string) (int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, errors.New("interval cannot be empty")
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n < 30 || n > 3600 {
			return 0, fmt.Errorf("interval %d must be between 30 and 3600 seconds", n)
		}
		return n, nil
	}
	d, err := time.ParseDuration(strings.ToLower(s))
	if err != nil {
		return 0, fmt.Errorf("invalid interval %q (use e.g. 30s, 1m, 5m, 10m, 15m, 30m, 1h, or seconds 30..3600)", raw)
	}
	if d <= 0 || d%time.Second != 0 {
		return 0, fmt.Errorf("interval %q must be a whole number of seconds", raw)
	}
	sec := int(d / time.Second)
	if sec < 30 || sec > 3600 {
		return 0, fmt.Errorf("interval %q (%ds) must be between 30s and 1h (30..3600s)", raw, sec)
	}
	return sec, nil
}

// FormatInterval formats seconds into a clean duration string ("30s", "5m", "1h").
func FormatInterval(sec int) string {
	switch {
	case sec <= 0:
		return "5m"
	case sec%3600 == 0:
		return fmt.Sprintf("%dh", sec/3600)
	case sec%60 == 0:
		return fmt.Sprintf("%dm", sec/60)
	default:
		return fmt.Sprintf("%ds", sec)
	}
}

// LoadFile reads, interpolates, and validates a YAML or JSON config file.
func LoadFile(path string, getenv func(string) string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return ParseBytes(path, data, getenv)
}

// ParseBytes parses, interpolates, and validates raw YAML or JSON config bytes.
func ParseBytes(filename string, data []byte, getenv func(string) string) (*File, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if filename == "" {
		filename = "hopbits.yaml"
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%s: config file is empty", filename)
	}

	isJSON := strings.EqualFold(filepath.Ext(filename), ".json")
	if isJSON {
		var js any
		if err := json.Unmarshal(trimmed, &js); err != nil {
			return nil, fmt.Errorf("%s: invalid JSON: %w", filename, err)
		}
	}

	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: config file is empty", filename)
		}
		return nil, fmt.Errorf("%s: %w", filename, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("%s: multiple YAML documents are not supported", filename)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}

	var missing []MissingVar
	if err := expandNode(&doc, "", getenv, &missing); err != nil {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}
	if len(missing) > 0 {
		return nil, &MissingEnvError{File: filename, Vars: missing}
	}

	// Re-encode and decode with KnownFields(true) so unknown keys fail fast.
	normalizedBytes, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}
	var rf rawFile
	strictDec := yaml.NewDecoder(bytes.NewReader(normalizedBytes))
	strictDec.KnownFields(true)
	if err := strictDec.Decode(&rf); err != nil {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}

	version := 1
	if rf.Version != nil {
		if *rf.Version != 1 {
			return nil, fmt.Errorf("%s: unsupported version %d (expected version: 1)", filename, *rf.Version)
		}
		version = *rf.Version
	}

	specs := make([]api.CheckSpec, 0, len(rf.Monitors))
	seenKeys := make(map[string]int, len(rf.Monitors))
	for i, m := range rf.Monitors {
		spec, err := normalizeMonitor(i, m)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filename, err)
		}
		if prevIdx, dup := seenKeys[spec.Key]; dup {
			return nil, fmt.Errorf("%s: monitors[%d]: duplicate key %q (already defined at monitors[%d])", filename, i, spec.Key, prevIdx)
		}
		seenKeys[spec.Key] = i
		specs = append(specs, spec)
	}

	return &File{
		Path:     filename,
		Version:  version,
		Monitors: specs,
	}, nil
}

func expandNode(n *yaml.Node, fieldPath string, getenv func(string) string, missing *[]MissingVar) error {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.DocumentNode:
		for _, child := range n.Content {
			if err := expandNode(child, fieldPath, getenv, missing); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			kNode := n.Content[i]
			vNode := n.Content[i+1]
			nextPath := kNode.Value
			if fieldPath != "" {
				nextPath = fieldPath + "." + kNode.Value
			}
			if err := expandNode(vNode, nextPath, getenv, missing); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for idx, child := range n.Content {
			nextPath := fmt.Sprintf("%s[%d]", fieldPath, idx)
			if fieldPath == "" {
				nextPath = fmt.Sprintf("[%d]", idx)
			}
			if err := expandNode(child, nextPath, getenv, missing); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		// Only expand string scalars; YAML comments live on HeadComment/LineComment/FootComment
		// and are never touched here.
		if n.Tag == "!!str" || (n.Style != 0 && strings.Contains(n.Value, "$")) {
			hadRef := strings.Contains(n.Value, "${")
			expanded, miss, err := Expand(n.Value, getenv)
			if err != nil {
				loc := fieldPath
				if loc == "" {
					loc = fmt.Sprintf("line %d", n.Line)
				}
				return fmt.Errorf("%s: %w", loc, err)
			}
			for _, name := range miss {
				loc := fieldPath
				if loc == "" {
					loc = "value"
				}
				*missing = append(*missing, MissingVar{
					Name:  name,
					Field: loc,
					Line:  n.Line,
				})
			}
			n.Value = expanded
			// Allow unquoted scalars like `port: ${PORT:-8443}` to resolve to YAML ints/bools.
			if hadRef && n.Style == 0 {
				n.Tag = ""
			}
		}
	}
	return nil
}

// ParsedTarget holds extracted target components.
type ParsedTarget struct {
	Host   string
	Port   *uint16
	Path   string
	Scheme string // "http" or "https" if input was a URL
}

// ParseTarget extracts host, optional port, path, and scheme from a hostname,
// IP literal, host:port, or http(s):// URL. Explicit port/path override URL values.
func ParseTarget(rawTarget, checkType string, explicitPort *uint16, explicitPath string) (ParsedTarget, error) {
	raw := strings.TrimSpace(rawTarget)
	if raw == "" {
		return ParsedTarget{}, errors.New("target is required")
	}

	out := ParsedTarget{
		Port: explicitPort,
		Path: strings.TrimSpace(explicitPath),
	}

	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		if checkType != "http" {
			return ParsedTarget{}, fmt.Errorf("URL target %q is only supported for type http (got %s)", raw, checkType)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return ParsedTarget{}, fmt.Errorf("invalid target URL %q", raw)
		}
		if u.User != nil {
			return ParsedTarget{}, fmt.Errorf("target URL %q must not contain userinfo credentials", raw)
		}
		if u.Fragment != "" {
			return ParsedTarget{}, fmt.Errorf("target URL %q must not contain a #fragment", raw)
		}
		out.Scheme = strings.ToLower(u.Scheme)
		out.Host = strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		if out.Port == nil {
			if pStr := u.Port(); pStr != "" {
				pNum, err := strconv.ParseUint(pStr, 10, 16)
				if err != nil || pNum == 0 {
					return ParsedTarget{}, fmt.Errorf("invalid port %q in target URL %q", pStr, raw)
				}
				p16 := uint16(pNum)
				out.Port = &p16
			} else if out.Scheme == "http" {
				p80 := uint16(80)
				out.Port = &p80
			}
		}
		if out.Path == "" {
			reqPath := u.EscapedPath()
			if u.RawQuery != "" {
				if reqPath == "" {
					reqPath = "/"
				}
				reqPath += "?" + u.RawQuery
			}
			if reqPath != "" && reqPath != "/" {
				out.Path = reqPath
			} else if reqPath == "/" && strings.HasSuffix(strings.SplitN(raw, "?", 2)[0], "/") {
				// Preserve explicit "/" if written, or keep "/" clean.
				out.Path = "/"
			}
		}
		return out, nil
	}

	if strings.Contains(raw, "://") {
		return ParsedTarget{}, fmt.Errorf("unsupported URL scheme in target %q (expected hostname, IP, or http(s):// URL)", raw)
	}
	if strings.ContainsAny(raw, "/?# \t\r\n") {
		return ParsedTarget{}, fmt.Errorf("invalid target %q (pass a hostname, IP address, or http(s):// URL)", raw)
	}

	// Check bare IP literal first (including IPv6 like 2001:db8::1).
	if addr, err := netip.ParseAddr(raw); err == nil {
		out.Host = addr.Unmap().String()
		return out, nil
	}

	// Support bracketed [ipv6] or host:port convenience when not a bare IPv6.
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		if addr, err := netip.ParseAddr(raw[1 : len(raw)-1]); err == nil {
			out.Host = addr.Unmap().String()
			return out, nil
		}
	}
	if h, pStr, err := net.SplitHostPort(raw); err == nil && h != "" {
		switch checkType {
		case "icmp_ping", "dns", "traceroute", "mtr":
			return ParsedTarget{}, fmt.Errorf("%s target %q must not include a port", checkType, raw)
		}
		pNum, pErr := strconv.ParseUint(pStr, 10, 16)
		if pErr != nil || pNum == 0 {
			return ParsedTarget{}, fmt.Errorf("invalid port %q in target %q", pStr, raw)
		}
		if out.Port == nil {
			p16 := uint16(pNum)
			out.Port = &p16
		}
		if addr, aErr := netip.ParseAddr(h); aErr == nil {
			out.Host = addr.Unmap().String()
		} else {
			out.Host = strings.ToLower(strings.TrimSuffix(h, "."))
		}
		return out, nil
	}

	out.Host = strings.ToLower(strings.TrimSuffix(raw, "."))
	return out, nil
}

// NormalizeType maps user-friendly check type aliases to API monitor kind names.
func NormalizeType(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "http":
		return "http", nil
	case "tcp", "tcp_connect":
		return "tcp_connect", nil
	case "icmp", "icmp_ping", "ping":
		return "icmp_ping", nil
	default:
		return "", fmt.Errorf("unsupported type %q (expected http, tcp, or icmp)", raw)
	}
}

// NormalizeProbeType maps user-friendly on-demand probe type aliases to API kind names.
func NormalizeProbeType(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "http":
		return "http", nil
	case "tcp", "tcp_connect":
		return "tcp_connect", nil
	case "icmp", "icmp_ping", "ping":
		return "icmp_ping", nil
	case "dns":
		return "dns", nil
	case "traceroute", "trace":
		return "traceroute", nil
	case "mtr":
		return "mtr", nil
	default:
		return "", fmt.Errorf("unsupported probe type %q (expected http, tcp, icmp, dns, traceroute, or mtr)", raw)
	}
}

func normalizeMonitor(idx int, m rawMonitor) (api.CheckSpec, error) {
	prefix := fmt.Sprintf("monitors[%d]", idx)
	key := strings.TrimSpace(m.Key)
	if key == "" {
		return api.CheckSpec{}, fmt.Errorf("%s: key is required", prefix)
	}
	if err := ValidateKey(key); err != nil {
		return api.CheckSpec{}, fmt.Errorf("%s (%s): %w", prefix, key, err)
	}
	prefix = fmt.Sprintf("monitors[%d] (%s)", idx, key)

	checkType, err := NormalizeType(m.Type)
	if err != nil {
		return api.CheckSpec{}, fmt.Errorf("%s: %w", prefix, err)
	}

	var explicitPort *uint16
	if m.Port != nil {
		if *m.Port < 1 || *m.Port > 65535 {
			return api.CheckSpec{}, fmt.Errorf("%s: port %d must be between 1 and 65535", prefix, *m.Port)
		}
		if checkType == "icmp_ping" {
			return api.CheckSpec{}, fmt.Errorf("%s: icmp monitor cannot specify port", prefix)
		}
		p := uint16(*m.Port)
		explicitPort = &p
	}

	pt, err := ParseTarget(m.Target, checkType, explicitPort, m.Path)
	if err != nil {
		return api.CheckSpec{}, fmt.Errorf("%s: %w", prefix, err)
	}

	name := strings.TrimSpace(m.Name)
	if name == "" {
		name = key
	}

	family := strings.ToLower(strings.TrimSpace(m.Family))
	switch family {
	case "", "ipv4", "ipv6":
	default:
		return api.CheckSpec{}, fmt.Errorf("%s: family %q must be ipv4 or ipv6", prefix, m.Family)
	}

	method := strings.ToUpper(strings.TrimSpace(m.Method))
	pathVal := pt.Path
	if checkType == "http" {
		if method == "" {
			method = "HEAD"
		}
		if method != "HEAD" && method != "GET" {
			return api.CheckSpec{}, fmt.Errorf("%s: method %q must be HEAD or GET", prefix, m.Method)
		}
		if pathVal != "" && !strings.HasPrefix(pathVal, "/") {
			pathVal = "/" + pathVal
		}
	} else if method != "" || pathVal != "" {
		return api.CheckSpec{}, fmt.Errorf("%s: method and path are only valid for http monitors", prefix)
	}

	if m.Interval.set && m.IntervalSeconds != nil {
		return api.CheckSpec{}, fmt.Errorf("%s: specify either interval or interval_seconds, not both", prefix)
	}
	intervalSec := 300
	switch {
	case m.Interval.set:
		intervalSec = m.Interval.seconds
	case m.IntervalSeconds != nil:
		if *m.IntervalSeconds < 30 || *m.IntervalSeconds > 3600 {
			return api.CheckSpec{}, fmt.Errorf("%s: interval_seconds %d must be between 30 and 3600", prefix, *m.IntervalSeconds)
		}
		intervalSec = *m.IntervalSeconds
	}

	locs, err := normalizeLocations(m.Locations)
	if err != nil {
		return api.CheckSpec{}, fmt.Errorf("%s: %w", prefix, err)
	}

	alertEmail := true
	if m.AlertEmail != nil {
		alertEmail = *m.AlertEmail
	}
	paused := false
	if m.Paused != nil {
		paused = *m.Paused
	}

	webhookURL := strings.TrimSpace(m.WebhookURL)
	webhookSecret := m.WebhookSecret
	if webhookURL == "" && webhookSecret != "" {
		return api.CheckSpec{}, fmt.Errorf("%s: webhook_secret requires webhook_url", prefix)
	}

	return api.CheckSpec{
		Key:             key,
		Name:            name,
		Type:            checkType,
		Target:          pt.Host,
		Port:            pt.Port,
		Family:          family,
		Method:          method,
		Path:            pathVal,
		IntervalSeconds: intervalSec,
		Locations:       locs,
		AlertEmail:      alertEmail,
		WebhookURL:      webhookURL,
		WebhookSecret:   webhookSecret,
		Paused:          paused,
	}, nil
}

func normalizeLocations(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return []string{"ANY"}, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, item := range raw {
		cc := strings.ToUpper(strings.TrimSpace(item))
		if cc == "" {
			continue
		}
		if cc == "*" {
			cc = "ANY"
		}
		if cc != "ANY" && (len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z') {
			return nil, fmt.Errorf("invalid location %q (expected 2-letter ISO country code like DE or ANY)", item)
		}
		if !seen[cc] {
			seen[cc] = true
			out = append(out, cc)
		}
	}
	if len(out) == 0 {
		return []string{"ANY"}, nil
	}
	if seen["ANY"] && len(out) > 1 {
		return nil, errors.New("location ANY cannot be combined with specific country codes")
	}
	if len(out) > 3 {
		return nil, fmt.Errorf("at most 3 locations per monitor are allowed (got %d)", len(out))
	}
	return out, nil
}
