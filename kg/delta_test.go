package kg

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "kg.jsonl"), func() string { return "t" })
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return st
}

func activeIDs(st *Store) []string {
	var out []string
	for _, r := range st.Active(0) {
		out = append(out, r.ID)
	}
	sort.Strings(out)
	return out
}

// TestApplyDelta_TombstoneSurvivesSyncRoundTrip is the spec-named test: a fact
// asserted on A, synced to B, deleted on B, and synced BACK to A ends up
// inactive on both replicas — the tombstone rides the delta and survives the
// round trip, so a deletion can never be resurrected by sync.
func TestApplyDelta_TombstoneSurvivesSyncRoundTrip(t *testing.T) {
	a, b := openTemp(t), openTemp(t)

	rec, err := a.AssertProv("atlas", "ownedBy", "platform", "wg:alice", "acme", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// A -> B: the fact appears on B.
	if n, err := b.ApplyDelta(a.DeltaSince(0)); err != nil || n != 1 {
		t.Fatalf("sync A->B: applied=%d err=%v, want 1 nil", n, err)
	}
	if got := activeIDs(b); len(got) != 1 || got[0] != rec.ID {
		t.Fatalf("B active = %v, want [%s]", got, rec.ID)
	}

	// B deletes it; B -> A: the tombstone must survive the return trip.
	if _, err := b.Delete(rec.ID, "wg:bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ApplyDelta(b.DeltaSince(0)); err != nil {
		t.Fatal(err)
	}
	if got := activeIDs(a); len(got) != 0 {
		t.Fatalf("A active after tombstone sync = %v, want empty (deletion resurrected!)", got)
	}
	if got := activeIDs(b); len(got) != 0 {
		t.Fatalf("B active = %v, want empty", got)
	}
	for name, st := range map[string]*Store{"A": a, "B": b} {
		if err := st.Verify(); err != nil {
			t.Fatalf("replica %s chain broken after sync: %v", name, err)
		}
	}
}

// TestApplyDelta_ConvergesEitherOrder_AndReverifies lifts the Merge convergence
// proof to store level: two replicas with divergent offline edits apply each
// other's deltas (in opposite orders) and converge to the same active set, and
// both locally-rebuilt chains still verify.
func TestApplyDelta_ConvergesEitherOrder_AndReverifies(t *testing.T) {
	a, b := openTemp(t), openTemp(t)

	ra, _ := a.AssertProv("alice", "knows", "bob", "KA", "team", "", "")
	rb1, _ := b.AssertProv("carol", "knows", "dave", "KB", "team", "", "")
	rb2, _ := b.AssertProv("erin", "role", "eng", "KB", "team", "", "")
	if _, err := b.Delete(rb2.ID, "KB"); err != nil { // B tombstones its own second fact
		t.Fatal(err)
	}

	deltaA, deltaB := a.DeltaSince(0), b.DeltaSince(0)
	if _, err := a.ApplyDelta(deltaB); err != nil { // A applies B's delta
		t.Fatal(err)
	}
	if _, err := b.ApplyDelta(deltaA); err != nil { // B applies A's delta (reverse order)
		t.Fatal(err)
	}

	wantIDs := []string{ra.ID, rb1.ID}
	sort.Strings(wantIDs)
	if got := activeIDs(a); !reflect.DeepEqual(got, wantIDs) {
		t.Fatalf("A converged to %v, want %v", got, wantIDs)
	}
	if !reflect.DeepEqual(activeIDs(a), activeIDs(b)) {
		t.Fatalf("replicas diverged: A=%v B=%v", activeIDs(a), activeIDs(b))
	}
	// Content (not just ids) survived the trip, corpus label included.
	got := b.Query("alice", "knows", "bob", 0)
	if len(got) != 1 || got[0].Peer != "KA" || got[0].Corpus != "team" {
		t.Fatalf("replicated record lost content/provenance: %+v", got)
	}
	if err := a.Verify(); err != nil {
		t.Fatalf("A chain after apply: %v", err)
	}
	if err := b.Verify(); err != nil {
		t.Fatalf("B chain after apply: %v", err)
	}
}

// TestApplyDelta_Idempotent proves re-applying the same delta appends nothing.
func TestApplyDelta_Idempotent(t *testing.T) {
	a, b := openTemp(t), openTemp(t)
	a.AssertProv("s", "p", "o", "K", "c", "", "")
	delta := a.DeltaSince(0)

	if n, err := b.ApplyDelta(delta); err != nil || n != 1 {
		t.Fatalf("first apply: n=%d err=%v", n, err)
	}
	head := b.Head()
	if n, err := b.ApplyDelta(delta); err != nil || n != 0 {
		t.Fatalf("re-apply must be a no-op: n=%d err=%v", n, err)
	}
	if b.Head() != head {
		t.Fatalf("idempotent apply moved the head: %d -> %d", head, b.Head())
	}
}

// TestDeltaSince_Watermark proves the watermark semantics: only records above
// the since sequence are returned, in order; a head watermark returns nothing.
func TestDeltaSince_Watermark(t *testing.T) {
	st := openTemp(t)
	st.Assert("a", "p", "o", "K")
	st.Assert("b", "p", "o", "K")
	st.Assert("c", "p", "o", "K")

	all := st.DeltaSince(0)
	if len(all) != 3 || all[0].Seq != 1 || all[2].Seq != 3 {
		t.Fatalf("DeltaSince(0) = %d recs, want the whole ordered log", len(all))
	}
	tail := st.DeltaSince(2)
	if len(tail) != 1 || tail[0].S != "c" {
		t.Fatalf("DeltaSince(2) = %+v, want just the third record", tail)
	}
	if rest := st.DeltaSince(st.Head()); len(rest) != 0 {
		t.Fatalf("DeltaSince(head) = %d recs, want none", len(rest))
	}
}

// TestApplyDelta_RefusesMalformedRecords proves junk replica records (no id,
// unknown op) are skipped rather than chained.
func TestApplyDelta_RefusesMalformedRecords(t *testing.T) {
	st := openTemp(t)
	n, err := st.ApplyDelta([]Record{
		{Op: "assert", ID: ""},                           // no id
		{Op: "compact", ID: "x"},                         // unknown op
		{Op: "assert", ID: "ok", S: "s", P: "p", O: "o"}, // the one valid record
	})
	if err != nil || n != 1 {
		t.Fatalf("applied=%d err=%v, want exactly the 1 well-formed record", n, err)
	}
	if err := st.Verify(); err != nil {
		t.Fatalf("chain after filtered apply: %v", err)
	}
}
