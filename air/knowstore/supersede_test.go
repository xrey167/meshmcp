package knowstore

import (
	"errors"
	"strings"
	"testing"
)

// TestSupersede_OldInactiveNewActive_HistoryPreserved proves the bi-temporal
// contract: after a supersede the old fact is inactive and the new one active,
// while an as-of read BEFORE the supersession still replays the old fact —
// invalidated, never erased.
func TestSupersede_OldInactiveNewActive_HistoryPreserved(t *testing.T) {
	f, _ := newFacade(t)
	writer := grant("wg:author", "notes")

	if _, err := f.Assert(writer, AssertRequest{Corpus: "notes", S: "acme", P: "exposure", O: "LOW"}); err != nil {
		t.Fatal(err)
	}
	before, _ := f.Query(writer, "notes", "acme", "", "", 0)
	if len(before) != 1 {
		t.Fatalf("seed = %d recs", len(before))
	}
	oldID := before[0].ID
	asOfBefore := f.Head()

	receipt, err := f.Supersede(writer, oldID, AssertRequest{
		Corpus: "notes", S: "acme", P: "exposure", O: "HIGH", Source: "incident-42",
	})
	if err != nil {
		t.Fatalf("supersede: %v", err)
	}
	if !receipt.Verify() {
		t.Fatal("supersede receipt does not verify")
	}

	// Now: only the new fact is active.
	now, _ := f.Query(writer, "notes", "acme", "exposure", "", 0)
	if len(now) != 1 || now[0].O != "HIGH" {
		t.Fatalf("post-supersede active = %+v, want just HIGH", now)
	}
	// As of before the supersession: the old fact still replays.
	past, _ := f.Query(writer, "notes", "acme", "exposure", "", asOfBefore)
	if len(past) != 1 || past[0].O != "LOW" {
		t.Fatalf("as-of history = %+v, want the original LOW fact", past)
	}
	if err := f.Verify(); err != nil {
		t.Fatalf("chain after supersede: %v", err)
	}
}

// TestSupersede_DeniedWithoutExactWriteGrant_StoreUntouched proves the write
// gate: a broad read glob cannot supersede, nothing is written, and the deny is
// audited as know.supersede.
func TestSupersede_DeniedWithoutExactWriteGrant_StoreUntouched(t *testing.T) {
	f, buf := newFacade(t)
	writer := grant("wg:author", "notes")
	if _, err := f.Assert(writer, AssertRequest{Corpus: "notes", S: "a", P: "b", O: "c"}); err != nil {
		t.Fatal(err)
	}
	recs, _ := f.Query(writer, "notes", "", "", "", 0)
	head := f.Head()

	attacker := grant("wg:attacker", "*") // glob: read power only
	if _, err := f.Supersede(attacker, recs[0].ID, AssertRequest{Corpus: "notes", S: "a", P: "b", O: "POISON"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("supersede error = %v, want ErrDenied", err)
	}
	if f.Head() != head {
		t.Fatalf("denied supersede advanced the store: %d -> %d", head, f.Head())
	}
	log := buf.String()
	if !strings.Contains(log, `"method":"know.supersede"`) || !strings.Contains(log, `"decision":"deny"`) {
		t.Fatalf("denied supersede not audited:\n%s", log)
	}
}

// TestSupersede_CannotCrossCorpusBoundary proves a write grant on corpus A
// cannot tombstone corpus B's fact, and the refusal is indistinguishable from a
// missing id (no existence leak).
func TestSupersede_CannotCrossCorpusBoundary(t *testing.T) {
	f, _ := newFacade(t)
	bob := grant("wg:bob", "corpus-b")
	bRecs := func() string {
		if _, err := f.Assert(bob, AssertRequest{Corpus: "corpus-b", S: "x", P: "y", O: "z"}); err != nil {
			t.Fatal(err)
		}
		recs, _ := f.Query(bob, "corpus-b", "", "", "", 0)
		return recs[0].ID
	}()

	alice := grant("wg:alice", "corpus-a")
	head := f.Head()
	_, errForeign := f.Supersede(alice, bRecs, AssertRequest{Corpus: "corpus-a", S: "x", P: "y", O: "hijacked"})
	_, errMissing := f.Supersede(alice, "t_does_not_exist", AssertRequest{Corpus: "corpus-a", S: "x", P: "y", O: "hijacked"})
	if !errors.Is(errForeign, ErrDenied) || !errors.Is(errMissing, ErrDenied) {
		t.Fatalf("cross-corpus=%v missing=%v, want ErrDenied for both", errForeign, errMissing)
	}
	// Indistinguishable refusals: same message shape modulo the id.
	fe := strings.ReplaceAll(errForeign.Error(), bRecs, "<id>")
	me := strings.ReplaceAll(errMissing.Error(), "t_does_not_exist", "<id>")
	if fe != me {
		t.Fatalf("existence leak: foreign=%q missing=%q", fe, me)
	}
	if f.Head() != head {
		t.Fatal("refused supersede touched the store")
	}
	// B's fact is still active.
	recs, _ := f.Query(bob, "corpus-b", "", "", "", 0)
	if len(recs) != 1 || recs[0].O != "z" {
		t.Fatalf("corpus-b fact damaged by refused cross-corpus supersede: %+v", recs)
	}
}

// TestSupersede_SingleAuditRecordCarriesBothRefs proves one know.supersede
// allow record carries the new fact's KnowHash AND the tombstoned old id.
func TestSupersede_SingleAuditRecordCarriesBothRefs(t *testing.T) {
	f, buf := newFacade(t)
	writer := grant("wg:author", "notes")
	if _, err := f.Assert(writer, AssertRequest{Corpus: "notes", S: "a", P: "b", O: "c"}); err != nil {
		t.Fatal(err)
	}
	recs, _ := f.Query(writer, "notes", "", "", "", 0)
	oldID := recs[0].ID

	receipt, err := f.Supersede(writer, oldID, AssertRequest{Corpus: "notes", S: "a", P: "b", O: "d"})
	if err != nil {
		t.Fatal(err)
	}
	prov := provenanceOf(t, buf.String(), "know.supersede", "allow")
	if len(prov) != 2 || prov[0] != receipt.KnowHash || prov[1] != "tombstoned:"+oldID {
		t.Fatalf("supersede provenance = %v, want [%s tombstoned:%s]", prov, receipt.KnowHash, oldID)
	}
}

// TestFacade_AliasCacheInvalidatesOnWrite proves the cached alias index follows
// the store head: a sameAs asserted AFTER the first Canonical call is seen by
// the next one.
func TestFacade_AliasCacheInvalidatesOnWrite(t *testing.T) {
	f, _ := newFacade(t)
	writer := grant("wg:author", "notes")

	// Warm the cache with an empty index.
	got, err := f.Canonical(writer, "notes", "Atlas")
	if err != nil {
		t.Fatal(err)
	}
	if got != "Atlas" {
		t.Fatalf("pre-alias Canonical = %q, want the name itself", got)
	}

	if _, err := f.Assert(writer, AssertRequest{Corpus: "notes", S: "Atlas", P: "sameAs", O: "e_atlas"}); err != nil {
		t.Fatal(err)
	}
	got, err = f.Canonical(writer, "notes", "Atlas")
	if err != nil {
		t.Fatal(err)
	}
	if got != "e_atlas" {
		t.Fatalf("post-write Canonical = %q, want e_atlas (cache must invalidate on head move)", got)
	}
}

// TestFacade_CanonicalGovernedAndScoped proves Canonical is a governed read:
// deny-by-default without a grant, and the index is built ONLY from records
// visible in the named corpus — a foreign corpus's sameAs cannot steer it.
func TestFacade_CanonicalGovernedAndScoped(t *testing.T) {
	f, _ := newFacade(t)
	bob := grant("wg:bob", "corpus-b")
	if _, err := f.Assert(bob, AssertRequest{Corpus: "corpus-b", S: "Atlas", P: "sameAs", O: "e_bobs_atlas"}); err != nil {
		t.Fatal(err)
	}

	// No grant → deny.
	if _, err := f.Canonical(grant("wg:nobody"), "corpus-b", "Atlas"); !errors.Is(err, ErrDenied) {
		t.Fatalf("ungranted Canonical error = %v, want ErrDenied", err)
	}
	// A corpus-a reader is NOT steered by corpus-b's sameAs edge.
	alice := grant("wg:alice", "corpus-a")
	got, err := f.Canonical(alice, "corpus-a", "Atlas")
	if err != nil {
		t.Fatal(err)
	}
	if got != "Atlas" {
		t.Fatalf("foreign-corpus sameAs steered resolution: %q", got)
	}
}
