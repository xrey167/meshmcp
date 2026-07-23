package air

import (
	"reflect"
	"testing"
)

// TestBuildAliasIndex_FoldsSameAs proves both edge shapes fold correctly:
// (X sameAs Y) maps X→Y, and (C alias N) maps the surface name N→C.
func TestBuildAliasIndex_FoldsSameAs(t *testing.T) {
	idx := BuildAliasIndex([]KGTriple{
		{S: "alice-smith", P: "sameAs", O: "e_alice"},
		{S: "e_alice", P: "alias", O: "Alice Smith"},
		{S: "e_alice", P: "worksOn", O: "atlas"}, // unrelated predicate ignored
	})
	if got := Canonical(idx, "alice-smith"); got != "e_alice" {
		t.Fatalf("sameAs fold: Canonical(alice-smith) = %q, want e_alice", got)
	}
	if got := Canonical(idx, "Alice Smith"); got != "e_alice" {
		t.Fatalf("alias fold: Canonical(Alice Smith) = %q, want e_alice", got)
	}
	if len(idx) != 2 {
		t.Fatalf("index size = %d, want 2 (unrelated predicates must not fold)", len(idx))
	}
}

// TestBuildAliasIndex_ChainsResolveToFinalCanonical proves a chain a→b→c
// resolves to c in one Canonical call.
func TestBuildAliasIndex_ChainsResolveToFinalCanonical(t *testing.T) {
	idx := BuildAliasIndex([]KGTriple{
		{S: "a", P: "sameAs", O: "b"},
		{S: "b", P: "sameAs", O: "c"},
	})
	if got := Canonical(idx, "a"); got != "c" {
		t.Fatalf("Canonical(a) = %q, want c (chain follow)", got)
	}
}

// TestCanonical_CycleSafe proves a hostile a↔b sameAs loop terminates.
func TestCanonical_CycleSafe(t *testing.T) {
	idx := BuildAliasIndex([]KGTriple{
		{S: "a", P: "sameAs", O: "b"},
		{S: "b", P: "sameAs", O: "a"},
	})
	got := Canonical(idx, "a")
	if got != "a" && got != "b" {
		t.Fatalf("cycle walk escaped the cycle: %q", got)
	}
	// And deterministically: same input, same answer.
	if again := Canonical(idx, "a"); again != got {
		t.Fatalf("cycle resolution not deterministic: %q vs %q", got, again)
	}
}

// TestBuildAliasIndex_Deterministic proves first-mapping-wins and replay
// stability: the same triple order always builds the same index.
func TestBuildAliasIndex_Deterministic(t *testing.T) {
	triples := []KGTriple{
		{S: "x", P: "sameAs", O: "first"},
		{S: "x", P: "sameAs", O: "second"}, // later conflicting claim loses
		{S: "y", P: "sameAs", O: "z"},
	}
	idx := BuildAliasIndex(triples)
	if idx["x"] != "first" {
		t.Fatalf("first mapping must win: idx[x] = %q", idx["x"])
	}
	if again := BuildAliasIndex(triples); !reflect.DeepEqual(idx, again) {
		t.Fatalf("index not replay-stable: %v vs %v", idx, again)
	}
}

// TestCanonical_UnknownNameReturnsItself proves resolution never fabricates.
func TestCanonical_UnknownNameReturnsItself(t *testing.T) {
	if got := Canonical(map[string]string{}, "nobody"); got != "nobody" {
		t.Fatalf("Canonical over empty index = %q, want the name itself", got)
	}
	if got := Canonical(nil, "nobody"); got != "nobody" {
		t.Fatalf("Canonical over nil index = %q, want the name itself", got)
	}
}

// TestBuildAliasIndex_DropsDegenerateEdges proves empty and self mappings are
// never indexed (a self-loop must not shadow a real mapping later).
func TestBuildAliasIndex_DropsDegenerateEdges(t *testing.T) {
	idx := BuildAliasIndex([]KGTriple{
		{S: "", P: "sameAs", O: "x"},
		{S: "x", P: "sameAs", O: ""},
		{S: "x", P: "sameAs", O: "x"},
		{S: "x", P: "sameAs", O: "real"},
	})
	if idx["x"] != "real" {
		t.Fatalf("degenerate edges must not occupy the slot: idx[x] = %q", idx["x"])
	}
}
