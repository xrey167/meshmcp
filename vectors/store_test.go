package vectors

import (
	"path/filepath"
	"testing"

	"github.com/xrey167/meshmcp/embed"
)

func newIndex(t *testing.T) *Index {
	t.Helper()
	ix, err := Open(filepath.Join(t.TempDir(), "v.jsonl"), embed.NewHashing(256))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return ix
}

func TestSearchRanksByRelevance(t *testing.T) {
	ix := newIndex(t)
	ix.Upsert("d1", "the cat sat on the warm mat by the fire", "", "K")
	ix.Upsert("d2", "kubernetes pods schedule onto cluster nodes", "", "K")
	ix.Upsert("d3", "a kitten and a cat played on the mat", "", "K")

	hits := ix.Search("cat on a mat", 3, "")
	if len(hits) == 0 {
		t.Fatal("no hits")
	}
	// The two cat/mat docs should outrank the kubernetes doc.
	top := map[string]bool{hits[0].Doc.ID: true, hits[1].Doc.ID: true}
	if !top["d1"] || !top["d3"] {
		t.Fatalf("expected d1 and d3 on top, got %s, %s", hits[0].Doc.ID, hits[1].Doc.ID)
	}
	if hits[0].Score <= 0 {
		t.Errorf("top score should be positive, got %v", hits[0].Score)
	}
}

func TestUpsertProvenanceAndPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v.jsonl")
	ix, _ := Open(path, embed.NewHashing(256))
	d, err := ix.Upsert("doc-1", "hello mesh knowledge", "legal", "PUBKEYX")
	if err != nil {
		t.Fatal(err)
	}
	if d.Peer != "PUBKEYX" || d.Hash == "" {
		t.Errorf("missing provenance: peer=%q hash=%q", d.Peer, d.Hash)
	}

	// Reload from disk and confirm the doc (and its corpus) survived.
	ix2, err := Open(path, embed.NewHashing(256))
	if err != nil {
		t.Fatal(err)
	}
	if ix2.Count() != 1 {
		t.Fatalf("reloaded count = %d, want 1", ix2.Count())
	}
	hits := ix2.Search("knowledge", 5, "legal")
	if len(hits) != 1 || hits[0].Doc.Peer != "PUBKEYX" {
		t.Fatalf("corpus-scoped search failed: %+v", hits)
	}
	// A different corpus filter returns nothing.
	if h := ix2.Search("knowledge", 5, "medical"); len(h) != 0 {
		t.Errorf("corpus filter leaked: got %d hits", len(h))
	}
}

func TestUpsertReplaces(t *testing.T) {
	ix := newIndex(t)
	ix.Upsert("d1", "first version", "", "K")
	ix.Upsert("d1", "second version", "", "K")
	if ix.Count() != 1 {
		t.Fatalf("upsert should replace, count = %d", ix.Count())
	}
	hits := ix.Search("second version", 1, "")
	if hits[0].Doc.Text != "second version" {
		t.Errorf("upsert did not replace text: %q", hits[0].Doc.Text)
	}
}

func TestEmbedderDeterministic(t *testing.T) {
	e := embed.NewHashing(128)
	a := e.Embed("repeatable input")
	b := e.Embed("repeatable input")
	if embed.Cosine(a, b) < 0.999 {
		t.Errorf("embedder not deterministic: cosine = %v", embed.Cosine(a, b))
	}
	if e.Dim() != 128 {
		t.Errorf("dim = %d, want 128", e.Dim())
	}
}
