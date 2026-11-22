package config

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/hopbits/cli/internal/api"
)

// GenerateSlug produces a valid unique monitor key from name or target,
// deduplicating collisions with -2, -3, etc. and updating used.
func GenerateSlug(name, target string, used map[string]bool) string {
	base := slugify(name)
	if base == "" {
		base = slugify(target)
	}
	if base == "" {
		base = "monitor"
	}
	if len(base) > 63 {
		base = strings.TrimRight(base[:63], "-_")
		if base == "" {
			base = "monitor"
		}
	}
	if !used[base] {
		used[base] = true
		return base
	}
	for n := 2; ; n++ {
		suffix := "-" + strconv.Itoa(n)
		stem := base
		if len(stem)+len(suffix) > 63 {
			stem = strings.TrimRight(stem[:63-len(suffix)], "-_")
			if stem == "" {
				stem = "monitor"
			}
		}
		cand := stem + suffix
		if !used[cand] {
			used[cand] = true
			return cand
		}
	}
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, prefix := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, prefix)
	}
	var b strings.Builder
	prevSep := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
			prevSep = false
			continue
		}
		if !prevSep {
			b.WriteByte('-')
			prevSep = true
		}
	}
	return strings.Trim(b.String(), "-_")
}

// EnvSecretName converts a monitor key into a clean uppercase env var suffix.
func EnvSecretName(key string) string {
	var b strings.Builder
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - 'a' + 'A')
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

// RenderYAML renders checks into a clean, idiomatic hopbits.yaml document.
// Every check must already have a non-empty Key assigned.
func RenderYAML(checks []api.Check) ([]byte, error) {
	root := &yaml.Node{Kind: yaml.MappingNode}
	addScalar(root, "version", "1", yaml.ScalarNode, "!!int")

	seq := &yaml.Node{Kind: yaml.SequenceNode}
	for _, c := range checks {
		m := &yaml.Node{Kind: yaml.MappingNode}
		addString(m, "key", c.Key)
		if c.Name != "" && c.Name != c.Key {
			addString(m, "name", c.Name)
		}

		shortType := shortTypeName(c.Type)
		if shortType != "http" {
			addString(m, "type", shortType)
		}
		addString(m, "target", c.Target)

		if c.Port != 0 && !isDefaultPort(shortType, c.Port) {
			addScalar(m, "port", strconv.Itoa(int(c.Port)), yaml.ScalarNode, "!!int")
		}
		if c.Family != "" {
			addString(m, "family", c.Family)
		}
		if shortType == "http" {
			if mth := strings.ToUpper(strings.TrimSpace(c.Method)); mth != "" && mth != "HEAD" {
				addString(m, "method", mth)
			}
			if c.Path != "" {
				addString(m, "path", c.Path)
			}
		}

		addString(m, "interval", FormatInterval(c.IntervalSeconds))

		locSeq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
		locs := c.Locations
		if len(locs) == 0 {
			locs = []string{"ANY"}
		}
		for _, loc := range locs {
			locSeq.Content = append(locSeq.Content, &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: loc,
			})
		}
		m.Content = append(m.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "locations"},
			locSeq,
		)

		if !c.AlertEmail {
			addScalar(m, "alert_email", "false", yaml.ScalarNode, "!!bool")
		}
		if c.WebhookURL != "" {
			kNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "webhook_url"}
			vNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: c.WebhookURL}
			if c.HasWebhookSecret {
				vNode.FootComment = fmt.Sprintf(
					"Set HOPBITS_WEBHOOK_SECRET_%s (webhook_secret: ${HOPBITS_WEBHOOK_SECRET_%s}) or preserve existing secret by omitting webhook_secret",
					EnvSecretName(c.Key), EnvSecretName(c.Key),
				)
			}
			m.Content = append(m.Content, kNode, vNode)
		}
		if c.Paused {
			addScalar(m, "paused", "true", yaml.ScalarNode, "!!bool")
		}

		seq.Content = append(seq.Content, m)
	}

	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "monitors"},
		seq,
	)

	var buf bytes.Buffer
	buf.WriteString("# Hopbits Monitoring-as-Code configuration\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func shortTypeName(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "", "http":
		return "http"
	case "tcp", "tcp_connect":
		return "tcp"
	case "icmp", "icmp_ping":
		return "icmp"
	default:
		return strings.ToLower(strings.TrimSpace(t))
	}
}

func isDefaultPort(shortType string, port uint16) bool {
	return (shortType == "http" || shortType == "tcp") && port == 443
}

func addString(m *yaml.Node, k, v string) {
	addScalar(m, k, v, yaml.ScalarNode, "!!str")
}

func addScalar(m *yaml.Node, k, v string, kind yaml.Kind, tag string) {
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
		&yaml.Node{Kind: kind, Tag: tag, Value: v},
	)
}
