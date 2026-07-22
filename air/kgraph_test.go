package air

import "testing"

// edges is a small fixture builder: a chain atlas -> platform -> dana plus a
// branch platform -> mesh, so depth and fan-out are both observable.
func kgFixture() []KGTriple {
	return []KGTriple{
		{S: "atlas", P: "ownedBy", O: "platform", Peer: "wg:a"},
		{S: "platform", P: "leads", O: "dana", Peer: "wg:b"},
		{S: "platform", P: "dependsOn", O: "mesh", Peer: "wg:c"},
		{S: "dana", P: "reportsTo", O: "erin", Peer: "wg:d"},
		{S: "unrelated", P: "x", O: "y", Peer: "wg:e"},
	}
}

// TestSubgraph_DepthCap proves hops bounds distance from the seed: one hop
// reaches only atlas's direct edges, two hops reach the next layer, and the
// unrelated edge is never included.
func TestSubgraph_DepthCap(t *testing.T) {
	recs := kgFixture()

	one := Subgraph(recs, "atlas", 1, 0)
	if len(one.Triples) != 1 || one.Triples[0].O != "platform" {
		t.Fatalf("1-hop = %+v, want just atlas->platform", one.Triples)
	}

	two := Subgraph(recs, "atlas", 2, 0)
	// atlas->platform, platform->dana, platform->mesh (3 edges); dana->erin is 3 hops.
	if len(two.Triples) != 3 {
		t.Fatalf("2-hop = %d edges, want 3: %+v", len(two.Triples), two.Triples)
	}
	for _, tr := range two.Triples {
		if tr.S == "unrelated" || tr.O == "erin" {
			t.Fatalf("2-hop leaked an out-of-range edge: %+v", tr)
		}
	}
}

// TestSubgraph_FanoutCap proves max bounds the total edges collected and flags
// the result Truncated when it bites.
func TestSubgraph_FanoutCap(t *testing.T) {
	recs := kgFixture()
	sg := Subgraph(recs, "atlas", 3, 2)
	if len(sg.Triples) != 2 {
		t.Fatalf("max=2 returned %d edges, want 2", len(sg.Triples))
	}
	if !sg.Truncated {
		t.Fatalf("max cap hit but Truncated is false: %+v", sg)
	}

	// A max larger than the reachable set is not a truncation.
	full := Subgraph(recs, "atlas", 9, 100)
	if full.Truncated {
		t.Fatalf("generous max should not truncate: %+v", full)
	}
}

// TestSubgraph_CycleTerminates proves a cyclic graph terminates and emits each
// edge exactly once (no infinite loop, no double-count).
func TestSubgraph_CycleTerminates(t *testing.T) {
	recs := []KGTriple{
		{S: "a", P: "r", O: "b"},
		{S: "b", P: "r", O: "c"},
		{S: "c", P: "r", O: "a"}, // closes the cycle
	}
	sg := Subgraph(recs, "a", 10, 0)
	if len(sg.Triples) != 3 {
		t.Fatalf("cycle = %d edges, want 3 (each once): %+v", len(sg.Triples), sg.Triples)
	}
}

// TestSubgraph_EmptyAndZeroHops proves the deny-ish edges: an empty seed, zero
// hops, and a seed absent from the graph all yield an empty neighborhood.
func TestSubgraph_EmptyAndZeroHops(t *testing.T) {
	recs := kgFixture()
	for _, tc := range []struct {
		name       string
		seed       string
		hops, want int
	}{
		{"empty seed", "", 2, 0},
		{"zero hops", "atlas", 0, 0},
		{"absent seed", "ghost", 2, 0},
	} {
		if sg := Subgraph(recs, tc.seed, tc.hops, 0); len(sg.Triples) != tc.want {
			t.Errorf("%s: got %d edges, want %d", tc.name, len(sg.Triples), tc.want)
		}
	}
}

// TestSubgraph_ObjectSeed proves the seed matches on the object side too — the
// graph is undirected for reachability (atlas is only ever an object of nothing,
// but platform is reached as an object and expands outward).
func TestSubgraph_ObjectSeed(t *testing.T) {
	recs := kgFixture()
	sg := Subgraph(recs, "dana", 1, 0)
	// dana appears as object (platform->dana) and subject (dana->erin): both edges.
	if len(sg.Triples) != 2 {
		t.Fatalf("dana 1-hop = %d edges, want 2 (in + out): %+v", len(sg.Triples), sg.Triples)
	}
}
