package knowstore

import (
	"encoding/json"
	"strings"
	"testing"
)

// auditRecords decodes the JSONL audit buffer into loose maps for assertions.
func auditRecords(t *testing.T, log string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// provenanceOf returns the Provenance list of the LAST audit record with the
// given method+decision.
func provenanceOf(t *testing.T, log, method, decision string) []string {
	t.Helper()
	var prov []string
	for _, m := range auditRecords(t, log) {
		if m["method"] == method && m["decision"] == decision {
			prov = nil
			if raw, ok := m["provenance"].([]any); ok {
				for _, p := range raw {
					prov = append(prov, p.(string))
				}
			}
		}
	}
	return prov
}

// TestReceiptRoundTrip_AssertHashEqualsRetrieveProvenance closes the S2 receipt
// defect: a fact asserted WITH Source and ValidFrom must yield a retrieve
// provenance hash equal to its assert receipt — because the store now persists
// the full hash preimage on the record.
func TestReceiptRoundTrip_AssertHashEqualsRetrieveProvenance(t *testing.T) {
	f, buf := newFacade(t)
	writer := grant("wg:author", "notes")

	receipt, err := f.Assert(writer, AssertRequest{
		Corpus: "notes", S: "atlas", P: "ownedBy", O: "platform",
		Source: "roadmap.md", ValidFrom: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("assert: %v", err)
	}
	if !receipt.Verify() {
		t.Fatal("assert receipt does not verify")
	}

	recs, err := f.Query(writer, "notes", "atlas", "", "", 0)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(recs) != 1 || recs[0].Source != "roadmap.md" || recs[0].ValidFrom != "2026-01-01T00:00:00Z" {
		t.Fatalf("read back = %+v, want the persisted source/valid_from", recs)
	}

	prov := provenanceOf(t, buf.String(), "know.retrieve", "allow")
	if len(prov) != 1 || prov[0] != receipt.KnowHash {
		t.Fatalf("retrieve provenance = %v, want exactly the assert receipt hash %s", prov, receipt.KnowHash)
	}
}

// TestQuery_TwoCorporaOneStore_MutuallyInvisible is the top-priority scoping
// slice: two corpora granted to different callers on ONE store must be mutually
// invisible — corpus B's records never appear in corpus A's results, and B's
// hashes never appear in A's audit provenance.
func TestQuery_TwoCorporaOneStore_MutuallyInvisible(t *testing.T) {
	f, buf := newFacade(t)
	alice := grant("wg:alice", "corpus-a")
	bob := grant("wg:bob", "corpus-b")

	if _, err := f.Assert(alice, AssertRequest{Corpus: "corpus-a", S: "a-fact", P: "is", O: "private-a"}); err != nil {
		t.Fatal(err)
	}
	bReceipt, err := f.Assert(bob, AssertRequest{Corpus: "corpus-b", S: "b-fact", P: "is", O: "private-b"})
	if err != nil {
		t.Fatal(err)
	}

	// Alice's wildcard read of corpus-a sees ONLY corpus-a.
	recs, err := f.Query(alice, "corpus-a", "", "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].S != "a-fact" {
		t.Fatalf("corpus-a read = %+v, want only the corpus-a fact", recs)
	}
	for _, r := range recs {
		if r.Corpus == "corpus-b" {
			t.Fatalf("corpus-b record leaked into a corpus-a read: %+v", r)
		}
	}
	// And B's stable hash never entered A's retrieve provenance.
	prov := provenanceOf(t, buf.String(), "know.retrieve", "allow")
	for _, p := range prov {
		if p == bReceipt.KnowHash {
			t.Fatalf("corpus-b hash %s leaked into corpus-a's audit provenance", p)
		}
	}
}

// TestLegacyCorpuslessRecord_PrivateToAssertingPeer: a record written without a
// corpus (the legacy path, e.g. the old cmd/kg binary) lands in its asserting
// peer's default subgraph — visible when the query corpus IS that peer id,
// invisible to every other corpus. Deny-by-default for old data.
func TestLegacyCorpuslessRecord_PrivateToAssertingPeer(t *testing.T) {
	f, _ := newFacade(t)
	// Reach under the facade the way legacy writers did: no corpus label.
	if _, err := f.store.Assert("old-fact", "is", "legacy", "wg:legacy-peer"); err != nil {
		t.Fatal(err)
	}

	// Visible under the peer's own default subgraph.
	owner := grant("wg:owner", "wg:legacy-peer")
	recs, err := f.Query(owner, "wg:legacy-peer", "", "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].S != "old-fact" {
		t.Fatalf("default-subgraph read = %+v, want the legacy fact", recs)
	}

	// Invisible under any foreign corpus, even with a covering grant.
	stranger := grant("wg:stranger", "notes")
	recs, err = f.Query(stranger, "notes", "", "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("legacy corpus-less record leaked into corpus %q: %+v", "notes", recs)
	}
}

// TestNeighbors_ScopedByRecordCorpus proves the entity-centric read applies the
// same record-level filter: a shared node's edges from another corpus stay
// invisible.
func TestNeighbors_ScopedByRecordCorpus(t *testing.T) {
	f, _ := newFacade(t)
	alice := grant("wg:alice", "corpus-a")
	bob := grant("wg:bob", "corpus-b")

	// Both corpora assert edges touching the SAME node.
	if _, err := f.Assert(alice, AssertRequest{Corpus: "corpus-a", S: "shared-node", P: "ownedBy", O: "team-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Assert(bob, AssertRequest{Corpus: "corpus-b", S: "shared-node", P: "watchedBy", O: "team-b"}); err != nil {
		t.Fatal(err)
	}

	recs, err := f.Neighbors(alice, "corpus-a", "shared-node", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].O != "team-a" {
		t.Fatalf("neighbors = %+v, want only the corpus-a edge of the shared node", recs)
	}
}

// TestDelta_TombstoneRidesWithItsCorpus proves the sender-side delta resolves a
// tombstone's corpus through its target fact: corpus-a's delete ships in
// corpus-a's delta and NOT in corpus-b's.
func TestDelta_TombstoneRidesWithItsCorpus(t *testing.T) {
	f, _ := newFacade(t)
	alice := grant("wg:alice", "corpus-a")
	bob := grant("wg:bob", "corpus-b")

	if _, err := f.Assert(alice, AssertRequest{Corpus: "corpus-a", S: "s", P: "p", O: "o"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Assert(bob, AssertRequest{Corpus: "corpus-b", S: "x", P: "y", O: "z"}); err != nil {
		t.Fatal(err)
	}
	// Tombstone the corpus-a fact.
	aRecs, _ := f.Query(alice, "corpus-a", "", "", "", 0)
	if err := f.Delete(alice, "corpus-a", aRecs[0].ID); err != nil {
		t.Fatal(err)
	}

	aDelta, err := f.Delta(alice, "corpus-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(aDelta) != 2 || aDelta[1].Op != "delete" {
		t.Fatalf("corpus-a delta = %+v, want its assert + its tombstone", aDelta)
	}
	bDelta, err := f.Delta(bob, "corpus-b", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range bDelta {
		if r.Op == "delete" {
			t.Fatalf("corpus-a's tombstone leaked into corpus-b's delta: %+v", bDelta)
		}
	}
	if len(bDelta) != 1 || bDelta[0].S != "x" {
		t.Fatalf("corpus-b delta = %+v, want only its own assert", bDelta)
	}
}
