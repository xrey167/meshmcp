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
	From   CatalogEntry `json:"from"`
	To     CatalogEntry `json:"to"`
	Fields []string     `json:"fields"` // address | transport | steerable | resumable
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

// DiffCatalogs computes what changed from old to cur, keyed by endpoint name.
// A name present only in cur is Added; only in old is Removed; in both with any
// differing field is Changed (with the differing field names). Endpoints are
// matched by Name — a rename reads as one removed + one added, which is the
// honest interpretation without a stable id.
func DiffCatalogs(old, cur Catalog) CatalogDelta {
	oldByName := index(old)
	curByName := index(cur)

	var d CatalogDelta
	for name, oe := range oldByName {
		ce, ok := curByName[name]
		if !ok {
			d.Removed = append(d.Removed, oe)
			continue
		}
		if fields := changedFields(oe, ce); len(fields) > 0 {
			d.Changed = append(d.Changed, EntryChange{Name: name, From: oe, To: ce, Fields: fields})
		}
	}
	for name, ce := range curByName {
		if _, ok := oldByName[name]; !ok {
			d.Added = append(d.Added, ce)
		}
	}

	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].Name < d.Added[j].Name })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].Name < d.Removed[j].Name })
	sort.Slice(d.Changed, func(i, j int) bool { return d.Changed[i].Name < d.Changed[j].Name })
	return d
}

// index maps endpoint name to entry. On a duplicate name (a malformed catalog)
// the last wins, matching how a client resolving by name would see it.
func index(c Catalog) map[string]CatalogEntry {
	m := make(map[string]CatalogEntry, len(c.Endpoints))
	for _, e := range c.Endpoints {
		m[e.Name] = e
	}
	return m
}

// changedFields returns the names of the capability fields that differ between
// two same-named entries, in a stable order.
func changedFields(a, b CatalogEntry) []string {
	var f []string
	if a.Address != b.Address {
		f = append(f, "address")
	}
	if a.Transport != b.Transport {
		f = append(f, "transport")
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
