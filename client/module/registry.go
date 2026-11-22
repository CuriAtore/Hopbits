package module

import (
	"fmt"
	"slices"
)

type key struct {
	kind    string
	version uint32
}

// Registry holds the modules compiled into a client.
type Registry struct {
	byKey map[key]Module
	order []Module
}

// NewRegistry builds a registry, refusing duplicate kind versions.
func NewRegistry(mods ...Module) (*Registry, error) {
	r := &Registry{byKey: make(map[key]Module, len(mods))}
	for _, m := range mods {
		k := key{m.Kind(), m.Version()}
		if k.kind == "" || k.version == 0 {
			return nil, fmt.Errorf("module: invalid kind %q version %d", k.kind, k.version)
		}
		if _, dup := r.byKey[k]; dup {
			return nil, fmt.Errorf("module: %s v%d registered twice", k.kind, k.version)
		}
		r.byKey[k] = m
		r.order = append(r.order, m)
	}
	return r, nil
}

// Lookup finds the module for a kind version.
func (r *Registry) Lookup(kind string, version uint32) (Module, bool) {
	m, ok := r.byKey[key{kind, version}]
	return m, ok
}

// HasKind reports whether any version of a kind is registered.
func (r *Registry) HasKind(kind string) bool {
	for _, m := range r.order {
		if m.Kind() == kind {
			return true
		}
	}
	return false
}

// Modules lists the registered modules in registration order.
func (r *Registry) Modules() []Module {
	return slices.Clone(r.order)
}

// Without returns a registry minus the named kinds, for an operator who
// switches modules off locally.
func (r *Registry) Without(kinds ...string) *Registry {
	out := &Registry{byKey: make(map[key]Module, len(r.order))}
	for _, m := range r.order {
		if slices.Contains(kinds, m.Kind()) {
			continue
		}
		out.byKey[key{m.Kind(), m.Version()}] = m
		out.order = append(out.order, m)
	}
	return out
}
