package air

// KGTriple is one edge in a knowledge subgraph: a subject/predicate/object fact
// stamped with the WireGuard identity that asserted it (Peer). It is the pure,
// wire-safe shape the air-kg verb assembles k-hop neighborhoods from —
// deliberately free of any store/chain internals (Seq, Hash, PrevHash), so the
// traversal logic here stays unit-testable without importing the kg store. The
// caller (the served air-kg backend) converts governed kg.Record reads into these
// before assembling a subgraph.
type KGTriple struct {
	S    string `json:"s"`
	P    string `json:"p"`
	O    string `json:"o"`
	Peer string `json:"peer,omitempty"`
}

// KGSubgraph is a bounded k-hop neighborhood around a seed entity: the edges
// reachable within Hops expansions of Seed, capped at Max total edges. Truncated
// reports whether the Max cap cut the traversal short — so a caller can tell a
// complete neighborhood from one bounded by the fan-out limit rather than by the
// graph's own edges.
type KGSubgraph struct {
	Seed      string     `json:"seed"`
	Hops      int        `json:"hops"`
	Max       int        `json:"max"`
	Triples   []KGTriple `json:"triples"`
	Truncated bool       `json:"truncated"`
}

// Subgraph assembles the bounded k-hop neighborhood of seed from an active triple
// set. It is a pure, deterministic breadth-first traversal — same input order in,
// same edge order out — so the served backend can hand it the exact governed
// read it just audited and get a stable, receipt-matching result.
//
// Bounds (both load-bearing, so a hostile or dense graph cannot exhaust the
// caller):
//
//   - hops caps DEPTH: how many expansion layers out from seed the walk goes. A
//     non-positive hops (or an empty seed) yields an empty neighborhood — a walk
//     of zero hops discovers nothing, matching deny-by-default framing.
//   - max caps BREADTH/total: at most max edges are ever collected; on hitting
//     the cap the walk stops and marks Truncated. A non-positive max means no cap.
//
// Cycles are safe: each node is expanded at most once (visited set) and each edge
// is emitted at most once (a triple is comparable, so it keys the seen set
// directly), so a cyclic graph terminates and never double-counts an edge.
func Subgraph(active []KGTriple, seed string, hops, max int) KGSubgraph {
	sg := KGSubgraph{Seed: seed, Hops: hops, Max: max}
	if seed == "" || hops <= 0 {
		return sg
	}

	// Index every edge by the nodes it touches, so each expansion is O(incident)
	// rather than a full scan per frontier node. A self-loop (S == O) is indexed
	// once, so it is neither missed nor double-collected.
	incident := map[string][]KGTriple{}
	for _, t := range active {
		incident[t.S] = append(incident[t.S], t)
		if t.O != t.S {
			incident[t.O] = append(incident[t.O], t)
		}
	}

	visited := map[string]bool{seed: true}
	seenEdge := map[KGTriple]bool{}
	frontier := []string{seed}

	for h := 0; h < hops && len(frontier) > 0; h++ {
		var next []string
		for _, node := range frontier {
			for _, t := range incident[node] {
				if seenEdge[t] {
					continue
				}
				if max > 0 && len(sg.Triples) >= max {
					sg.Truncated = true
					return sg
				}
				seenEdge[t] = true
				sg.Triples = append(sg.Triples, t)
				// Queue the edge's other endpoint(s) for the next layer, first time
				// seen only — this is what bounds a cyclic graph.
				for _, endpoint := range [2]string{t.S, t.O} {
					if endpoint != "" && !visited[endpoint] {
						visited[endpoint] = true
						next = append(next, endpoint)
					}
				}
			}
		}
		frontier = next
	}
	return sg
}
