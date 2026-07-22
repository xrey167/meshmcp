package rag

import (
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/embed"
)

// --- chunking -------------------------------------------------------------

func TestChunkDocument_OverlapAndParents(t *testing.T) {
	text := "alpha beta gamma delta epsilon zeta eta theta"
	chunks, parents := ChunkDocument("doc1", "corp", text, 3, 1)
	if len(chunks) == 0 {
		t.Fatal("no chunks produced")
	}
	// Every chunk points at a parent that exists in the parents map.
	for _, c := range chunks {
		if _, ok := parents[c.ParentID]; !ok {
			t.Fatalf("chunk %s has dangling parent %s", c.ID, c.ParentID)
		}
		if c.DocID != "doc1" || c.Corpus != "corp" {
			t.Fatalf("chunk metadata wrong: %+v", c)
		}
	}
	// Overlap: consecutive windows in the same section share the tail/head token.
	if len(chunks) >= 2 {
		first := strings.Fields(chunks[0].Text)
		second := strings.Fields(chunks[1].Text)
		if first[len(first)-1] != second[0] {
			t.Fatalf("expected 1-token overlap, got %q then %q", chunks[0].Text, chunks[1].Text)
		}
	}
	// No dropped tail: the last token appears in the last chunk.
	last := chunks[len(chunks)-1].Text
	if !strings.Contains(last, "theta") {
		t.Fatalf("tail token dropped; last chunk = %q", last)
	}
}

func TestChunkDocument_SectionsBecomeParents(t *testing.T) {
	text := "first section one two three\n\nsecond section four five six"
	chunks, parents := ChunkDocument("d", "c", text, 100, 0)
	if len(parents) != 2 {
		t.Fatalf("expected 2 parent sections, got %d: %v", len(parents), parents)
	}
	// A small-to-big return: the parent text is the whole enclosing section, which
	// is larger than (or equal to) any single child chunk.
	for _, c := range chunks {
		if len(parents[c.ParentID]) < len(c.Text) {
			t.Fatalf("parent should be >= child; parent=%q child=%q", parents[c.ParentID], c.Text)
		}
	}
}

func TestChunkDocument_EmptyAndEdgeInputs(t *testing.T) {
	if c, _ := ChunkDocument("d", "c", "", 10, 2); len(c) != 0 {
		t.Fatalf("empty text should yield no chunks, got %d", len(c))
	}
	// overlap >= size must not loop forever; it is clamped.
	c, _ := ChunkDocument("d", "c", "a b c d e", 2, 9)
	if len(c) == 0 {
		t.Fatal("expected chunks with clamped overlap")
	}
}

// --- BM25 -----------------------------------------------------------------

func tok(s string) []string { return embed.Tokenize(s) }

func TestBM25_RanksExactTokenMatch(t *testing.T) {
	m := NewBM25()
	m.Add("err", tok("error code E4021 rotation failure on the primary"))
	m.Add("prose", tok("a gentle description of how things generally work"))
	m.Add("noise", tok("kubernetes pods schedule onto cluster nodes"))
	got := m.Search(tok("E4021"), 3)
	if len(got) == 0 || got[0].ID != "err" {
		t.Fatalf("exact identifier match should rank first, got %+v", got)
	}
}

func TestBM25_IDFMonotonicAndEmptySafe(t *testing.T) {
	m := NewBM25()
	m.Add("a", tok("common common rare"))
	m.Add("b", tok("common common common"))
	// "rare" appears in one doc, "common" in both — the doc with the rare term
	// should win a query for both terms.
	got := m.Search(tok("common rare"), 2)
	if len(got) == 0 || got[0].ID != "a" {
		t.Fatalf("rarer term should lift doc a, got %+v", got)
	}
	if m.Search(nil, 5) != nil {
		t.Fatal("empty query must return nil")
	}
	if NewBM25().Search(tok("x"), 5) != nil {
		t.Fatal("empty index must return nil")
	}
}

// --- RRF fusion -----------------------------------------------------------

func TestFuseRRF_RankInvariantAndDeterministic(t *testing.T) {
	// Fusion must depend on rank, not raw score: two runs with wildly different
	// score scales but identical ordering fuse to that ordering.
	dense := []Scored{{"x", 0.9}, {"y", 0.8}, {"z", 0.1}}
	lex := []Scored{{"x", 100}, {"y", 50}, {"z", 1}}
	a := FuseRRF([][]Scored{dense, lex}, 60)
	b := FuseRRF([][]Scored{lex, dense}, 60) // input order swapped
	if len(a) != 3 || a[0].ID != "x" {
		t.Fatalf("unexpected fusion: %+v", a)
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("fusion not order-independent: %+v vs %+v", a, b)
		}
	}
}

// TestFuseRRF_KeywordOnlyBeatsDenseNearMiss is the load-bearing claim: a chunk
// that only the KEYWORD arm finds (a synonym/identifier the lexical embedder
// scores ~0 on) can outrank a chunk that only the dense arm ranks marginally.
func TestFuseRRF_KeywordOnlyBeatsDenseNearMiss(t *testing.T) {
	// dense arm: it ranks a shared hit first and only reaches the near-miss "dn"
	// at rank 2 — the true answer never appears in it (the synonym problem).
	dense := []Scored{{"other", 0.05}, {"dn", 0.02}}
	// keyword arm: the true answer "kw" is the top exact-token hit.
	lex := []Scored{{"kw", 12.0}, {"other", 3.0}}
	fused := FuseRRF([][]Scored{dense, lex}, 60)
	pos := map[string]int{}
	for i, s := range fused {
		pos[s.ID] = i
	}
	if pos["kw"] > pos["dn"] {
		t.Fatalf("keyword-only true hit should not rank below dense-only near-miss: %+v", fused)
	}
	// "other", present in BOTH arms, should win overall (fusion rewards agreement).
	if fused[0].ID != "other" {
		t.Fatalf("cross-arm agreement should top fusion, got %+v", fused)
	}
}

func TestFuseRRF_EmptySafe(t *testing.T) {
	if FuseRRF(nil, 60) != nil {
		t.Fatal("nil runs must fuse to nil")
	}
	if FuseRRF([][]Scored{{}, {}}, 0) != nil {
		t.Fatal("empty runs must fuse to nil")
	}
}
