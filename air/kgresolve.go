package air

// Alias / sameAs canonicalization for the knowledge graph (Air Knowledge
// System, Phase 1). Entity resolution is modeled AS TRIPLES — `sameAs` and
// `alias` edges — so it inherits audit, CRDT merge, and time-travel with no
// side table, and a merge decision stays disputable and reversible by
// tombstone (never a destructive rewrite).
//
// This file is the pure fold over those triples: BuildAliasIndex turns an
// active triple set into a name→canonical map once, and Canonical is then an
// O(chain-length) lookup — the index exists precisely so canonicalization is
// not O(active-set) per name. The governed, cached wrapper lives in
// air/knowstore (the facade rebuilds the index only when the store head moves).

// aliasPredicates are the two edge shapes the fold reads:
//
//	(X, sameAs, Y)   — X resolves to canonical Y
//	(C, alias, "N")  — surface name N resolves to canonical C
const (
	PredicateSameAs = "sameAs"
	PredicateAlias  = "alias"
)

// BuildAliasIndex folds the active triple set into a name→canonical map.
// Deterministic in input order: the FIRST mapping for a name wins, so replaying
// the same active set always yields the same index. Self-mappings are dropped.
// Cycle safety is Canonical's job (the index itself may legitimately contain a
// cycle asserted by adversarial or careless writers).
func BuildAliasIndex(triples []KGTriple) map[string]string {
	idx := make(map[string]string)
	put := func(from, to string) {
		if from == "" || to == "" || from == to {
			return
		}
		if _, dup := idx[from]; !dup {
			idx[from] = to
		}
	}
	for _, t := range triples {
		switch t.P {
		case PredicateSameAs:
			put(t.S, t.O)
		case PredicateAlias:
			put(t.O, t.S)
		}
	}
	return idx
}

// Canonical resolves name through the alias index, following sameAs chains to
// their end. An unknown name returns itself (resolution never fabricates), and
// a cycle terminates deterministically at the point the walk would re-enter a
// visited name — a hostile a↔b loop can never hang the caller.
func Canonical(idx map[string]string, name string) string {
	seen := map[string]bool{}
	cur := name
	for {
		next, ok := idx[cur]
		if !ok || seen[cur] {
			return cur
		}
		seen[cur] = true
		cur = next
	}
}
