package provider

import (
	"context"
	"fmt"
	"sync"
)

// Registry resolves a model class to a concrete Provider through an ordered
// fallback chain. Proactive fallback: if the primary provider for a class is
// unavailable (rate-limited/missing binary), the next provider in the class
// chain is chosen before invoking. This is the class → provider indirection that
// keeps routing provider-agnostic (§7.4).
type Registry struct {
	mu      sync.RWMutex
	byClass map[string][]Provider // ordered fallback chain per class
	order   []string              // global provider preference order (config.providers.order)
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	return &Registry{byClass: map[string][]Provider{}}
}

// Register adds p to its class's fallback chain (appended: first registered is
// preferred). A provider may be registered under several classes by calling
// Register once per class-satisfying provider.
func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byClass[p.Class()] = append(r.byClass[p.Class()], p)
}

// SetOrder records the global provider name preference (config.providers.order),
// used to sort within a class so an org can prefer, e.g., a local model.
func (r *Registry) SetOrder(order []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = append([]string(nil), order...)
}

// Resolve returns the first AVAILABLE provider for class, honoring the fallback
// chain. It returns an error when the class is unknown or every provider in its
// chain is unavailable — a clear, audited failure, never a silent hang (§18).
func (r *Registry) Resolve(ctx context.Context, class string) (Provider, error) {
	r.mu.RLock()
	chain := append([]Provider(nil), r.byClass[class]...)
	order := append([]string(nil), r.order...)
	r.mu.RUnlock()

	if len(chain) == 0 {
		return nil, fmt.Errorf("provider: no adapter registered for class %q", class)
	}
	chain = sortByOrder(chain, order)
	var last error
	for _, p := range chain {
		if p.Available(ctx) {
			return p, nil
		}
		last = fmt.Errorf("provider %q unavailable", p.Name())
	}
	if last == nil {
		last = fmt.Errorf("no available provider")
	}
	return nil, fmt.Errorf("provider: class %q exhausted: %w", class, last)
}

// Classes lists the classes with at least one registered provider.
func (r *Registry) Classes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.byClass))
	for c := range r.byClass {
		out = append(out, c)
	}
	return out
}

// sortByOrder is a stable reorder of chain so providers whose name appears
// earlier in order come first; unlisted providers keep their registration order
// after listed ones.
func sortByOrder(chain []Provider, order []string) []Provider {
	if len(order) == 0 {
		return chain
	}
	rank := map[string]int{}
	for i, n := range order {
		rank[n] = i
	}
	out := append([]Provider(nil), chain...)
	// simple stable insertion sort by rank (chains are short)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			rj := rankOf(rank, out[j].Name())
			rjm := rankOf(rank, out[j-1].Name())
			if rj < rjm {
				out[j], out[j-1] = out[j-1], out[j]
			} else {
				break
			}
		}
	}
	return out
}

func rankOf(rank map[string]int, name string) int {
	if r, ok := rank[name]; ok {
		return r
	}
	return 1 << 30
}
