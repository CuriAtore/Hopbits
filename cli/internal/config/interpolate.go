package config

import (
	"fmt"
	"sort"
	"strings"
)

// MissingVar is one ${VAR} reference that had no value and no default.
type MissingVar struct {
	Name  string // the environment variable
	Field string // where it was used, e.g. monitors[0].webhook_secret
	Line  int    // 1-based line in the config file, 0 when unknown
}

// MissingEnvError reports every ${VAR} reference that resolved to nothing,
// so CI fails before anything is deployed with an empty secret.
type MissingEnvError struct {
	File string
	Vars []MissingVar
}

func (e *MissingEnvError) Error() string {
	names := e.Names()
	var b strings.Builder
	if len(names) == 1 {
		fmt.Fprintf(&b, "%s: environment variable %s is not set (and has no ${%s:-default})", e.File, names[0], names[0])
	} else {
		fmt.Fprintf(&b, "%s: environment variables not set: %s", e.File, strings.Join(names, ", "))
	}
	for _, v := range e.Vars {
		loc := v.Field
		if v.Line > 0 {
			loc = fmt.Sprintf("line %d, %s", v.Line, v.Field)
		}
		fmt.Fprintf(&b, "\n  ${%s} used at %s", v.Name, loc)
	}
	return b.String()
}

// Names returns the distinct missing variable names, sorted.
func (e *MissingEnvError) Names() []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range e.Vars {
		if !seen[v.Name] {
			seen[v.Name] = true
			out = append(out, v.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Expand replaces ${VAR} and ${VAR:-default} references in s with values
// from getenv. "$${" is an escape for a literal "${"; any other "$" is kept
// as is, so secrets containing "$" survive untouched. It returns the names
// of variables that were unset or empty and had no default; the caller
// decides how to report them.
func Expand(s string, getenv func(string) string) (string, []string, error) {
	if !strings.Contains(s, "$") {
		return s, nil, nil
	}
	var (
		b       strings.Builder
		missing []string
	)
	for i := 0; i < len(s); {
		c := s[i]
		if c != '$' {
			b.WriteByte(c)
			i++
			continue
		}
		// "$${" -> literal "${"
		if strings.HasPrefix(s[i:], "$${") {
			b.WriteString("${")
			i += 3
			continue
		}
		if !strings.HasPrefix(s[i:], "${") {
			b.WriteByte(c)
			i++
			continue
		}
		end := strings.IndexByte(s[i+2:], '}')
		if end < 0 {
			return "", nil, fmt.Errorf("unterminated ${ in %q", short(s))
		}
		inner := s[i+2 : i+2+end]
		name, def, hasDef := strings.Cut(inner, ":-")
		if !validVarName(name) {
			return "", nil, fmt.Errorf("invalid variable reference ${%s}: names use letters, digits and underscores", short(inner))
		}
		val := getenv(name)
		switch {
		case val != "":
			b.WriteString(val)
		case hasDef:
			b.WriteString(def)
		default:
			missing = append(missing, name)
		}
		i += 2 + end + 1
	}
	return b.String(), missing, nil
}

func validVarName(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		switch {
		case c == '_', 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z':
		case '0' <= c && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func short(s string) string {
	if len(s) <= 48 {
		return s
	}
	return s[:48] + "..."
}
