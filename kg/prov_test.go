package kg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAssertProv_PersistsCorpusSourceValidFrom_ChainCovered proves the extended
// record fields are persisted, survive a reload, and are covered by the hash
// chain: tampering with any of them in the file makes Verify fail.
func TestAssertProv_PersistsCorpusSourceValidFrom_ChainCovered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kg.jsonl")
	st, err := Open(path, func() string { return "t" })
	if err != nil {
		t.Fatal(err)
	}
	rec, err := st.AssertProv("atlas", "ownedBy", "platform", "wg:alice", "acme/product", "roadmap.md", "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Corpus != "acme/product" || rec.Source != "roadmap.md" || rec.ValidFrom != "2026-01-01T00:00:00Z" {
		t.Fatalf("returned record missing provenance fields: %+v", rec)
	}

	// Reload from disk: the fields are persisted and the chain verifies.
	st2, err := Open(path, func() string { return "t" })
	if err != nil {
		t.Fatal(err)
	}
	got := st2.Query("atlas", "", "", 0)
	if len(got) != 1 || got[0].Corpus != "acme/product" || got[0].Source != "roadmap.md" || got[0].ValidFrom != "2026-01-01T00:00:00Z" {
		t.Fatalf("reloaded record = %+v, want persisted corpus/source/valid_from", got)
	}
	if err := st2.Verify(); err != nil {
		t.Fatalf("clean provenance record must verify: %v", err)
	}

	// Tamper with the Corpus field on disk: Verify must fail — the new fields
	// are inside the chain hash, not decoration beside it.
	raw, _ := os.ReadFile(path)
	tampered := strings.Replace(string(raw), `"corpus":"acme/product"`, `"corpus":"acme/stolenx"`, 1)
	if tampered == string(raw) {
		t.Fatal("could not locate corpus field to tamper")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	st3, err := Open(path, func() string { return "t" })
	if err != nil {
		t.Fatal(err)
	}
	if err := st3.Verify(); err == nil {
		t.Fatal("Verify must FAIL when a record's corpus is tampered")
	}
}

// TestVerify_BackwardCompatOldRecords proves chain compatibility: records
// written through the legacy Assert path (no corpus/source/valid_from) marshal
// with the new fields omitted, so an old-format log reopened under the extended
// code still verifies, and its bytes carry no trace of the new fields.
func TestVerify_BackwardCompatOldRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kg.jsonl")
	st, err := Open(path, func() string { return "t" })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Assert("a", "b", "c", "K"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Assert("d", "e", "f", "K"); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path)
	for _, field := range []string{`"corpus"`, `"source"`, `"valid_from"`} {
		if strings.Contains(string(raw), field) {
			t.Fatalf("legacy Assert leaked new field %s into the record bytes:\n%s", field, raw)
		}
	}

	st2, err := Open(path, func() string { return "t" })
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.Verify(); err != nil {
		t.Fatalf("old-format records must still verify: %v", err)
	}
}
