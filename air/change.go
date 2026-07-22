package air

import (
	"fmt"
	"sort"
	"strings"
)

// Air · Change — what changed on my reachable mesh since last I looked.
//
// Discovery answers "what can I reach right now"; Change answers "what is
// different from the snapshot I saved" — a backend appeared or left, or one
// flipped a capability (its transport, whether it is steerable or resumable, or
// its address moved). This file is the pure diff over two catalogs; the CLI that
// fetches a live catalog over the mesh and renders the delta lives in the main
// package. Keeping the diff here makes it unit-testable without a mesh, like the
// rest of the air/ core.

// EntryChange records that a still-present backend changed between two catalogs,
// naming exactly which fields differ so a viewer can show "steerable: false →
// true" rather than an opaque "changed".
type EntryChange struct {
	Name   string       `json:"name"`
	ID     string       `json:"id,omitempty"`
	From   CatalogEntry `json:"from"`
	To     CatalogEntry `json:"to"`
	Fields []string     `json:"fields"` // stable ordered names from changedFields
}

// CatalogDelta is the difference between an older and a current catalog:
// endpoints that appeared, that vanished, and that changed capability. Each list
// is ordered by name for a stable, reproducible view.
type CatalogDelta struct {
	Added   []CatalogEntry `json:"added"`
	Removed []CatalogEntry `json:"removed"`
	Changed []EntryChange  `json:"changed"`
}

// Empty reports whether nothing changed between the two catalogs.
func (d CatalogDelta) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// DiffCatalogs computes what changed from old to cur. Component cards are
// matched by stable ID first, so a rename or address move remains one component
// change. Unmatched entries fall back to Name only when at least one side has
// no ID, preserving comparisons against legacy snapshots without allowing two
// different non-empty IDs with the same display name to collapse together.
func DiffCatalogs(old, cur Catalog) CatalogDelta {
	var d CatalogDelta
	matchedCur := make([]bool, len(cur.Endpoints))
	for _, oe := range old.Endpoints {
		j := matchingEntry(oe, cur.Endpoints, matchedCur)
		if j < 0 {
			d.Removed = append(d.Removed, oe)
			continue
		}
		matchedCur[j] = true
		ce := cur.Endpoints[j]
		if fields := changedFields(oe, ce); len(fields) > 0 {
			id := ce.ID
			if id == "" {
				id = oe.ID
			}
			name := ce.Name
			if name == "" {
				name = oe.Name
			}
			d.Changed = append(d.Changed, EntryChange{ID: id, Name: name, From: oe, To: ce, Fields: fields})
		}
	}
	for i, ce := range cur.Endpoints {
		if !matchedCur[i] {
			d.Added = append(d.Added, ce)
		}
	}

	sort.Slice(d.Added, func(i, j int) bool { return entryLess(d.Added[i], d.Added[j]) })
	sort.Slice(d.Removed, func(i, j int) bool { return entryLess(d.Removed[i], d.Removed[j]) })
	sort.Slice(d.Changed, func(i, j int) bool {
		if d.Changed[i].Name != d.Changed[j].Name {
			return d.Changed[i].Name < d.Changed[j].Name
		}
		return d.Changed[i].ID < d.Changed[j].ID
	})
	return d
}

// matchingEntry returns the first unmatched current entry representing old.
// Stable IDs are authoritative. Name fallback is only a legacy bridge.
func matchingEntry(old CatalogEntry, current []CatalogEntry, used []bool) int {
	if old.ID != "" {
		for i, e := range current {
			if !used[i] && e.ID == old.ID {
				return i
			}
		}
	}
	for i, e := range current {
		if used[i] || e.Name != old.Name {
			continue
		}
		if old.ID == "" || e.ID == "" {
			return i
		}
	}
	return -1
}

func entryLess(a, b CatalogEntry) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.ID != b.ID {
		return a.ID < b.ID
	}
	return a.Address < b.Address
}

// changedFields returns the names of the capability fields that differ between
// two same-named entries, in a stable order.
func changedFields(a, b CatalogEntry) []string {
	var f []string
	if a.ID != b.ID {
		f = append(f, "id")
	}
	if a.Name != b.Name {
		f = append(f, "name")
	}
	if a.Kind != b.Kind {
		f = append(f, "kind")
	}
	if a.Version != b.Version {
		f = append(f, "version")
	}
	if a.Owner.normalized() != b.Owner.normalized() {
		f = append(f, "owner")
	}
	if a.Address != b.Address {
		f = append(f, "address")
	}
	if a.Transport != b.Transport {
		f = append(f, "transport")
	}
	if featureKey(a.Features) != featureKey(b.Features) {
		f = append(f, "features")
	}
	if a.Lifecycle.normalized() != b.Lifecycle.normalized() {
		f = append(f, "lifecycle")
	}
	if a.Steerable != b.Steerable {
		f = append(f, "steerable")
	}
	if a.Resumable != b.Resumable {
		f = append(f, "resumable")
	}
	return f
}

// Summary renders a one-line, human-readable count of the delta, e.g.
// "+2 -1 ~3" (added, removed, changed) or "no changes".
func (d CatalogDelta) Summary() string {
	if d.Empty() {
		return "no changes"
	}
	parts := make([]string, 0, 3)
	if len(d.Added) > 0 {
		parts = append(parts, fmt.Sprintf("+%d", len(d.Added)))
	}
	if len(d.Removed) > 0 {
		parts = append(parts, fmt.Sprintf("-%d", len(d.Removed)))
	}
	if len(d.Changed) > 0 {
		parts = append(parts, fmt.Sprintf("~%d", len(d.Changed)))
	}
	return strings.Join(parts, " ")
}
