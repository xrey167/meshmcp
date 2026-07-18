package main

import (
	"reflect"
	"testing"
)

// TestMergeRecordsConverges proves the S8 CRDT property: two replicas that
// diverged offline reconcile to the same active set regardless of merge order,
// and a tombstone on either side removes the triple.
func TestMergeRecordsConverges(t *testing.T) {
	// Replica A asserted t1, t2; then deleted t2.
	a := []record{
		{Op: "assert", ID: "t1", S: "alice", P: "knows", O: "bob"},
		{Op: "assert", ID: "t2", S: "alice", P: "role", O: "eng"},
		{Op: "delete", ID: "t2"},
	}
	// Replica B (offline) asserted t3, and also deleted t1.
	b := []record{
		{Op: "assert", ID: "t3", S: "carol", P: "knows", O: "dave"},
		{Op: "delete", ID: "t1"},
	}

	ab := mergeRecords(a, b)
	ba := mergeRecords(b, a)

	// Commutative: order of replicas doesn't matter.
	if !reflect.DeepEqual(ab, ba) {
		t.Fatalf("merge not commutative:\n ab=%v\n ba=%v", ids(ab), ids(ba))
	}
	// Idempotent: re-merging changes nothing.
	if again := mergeRecords(ab, a, b); !reflect.DeepEqual(again, ab) {
		t.Fatalf("merge not idempotent: %v vs %v", ids(again), ids(ab))
	}
	// Converged set: t1 deleted by B, t2 deleted by A → only t3 survives.
	if got := ids(ab); len(got) != 1 || got[0] != "t3" {
		t.Fatalf("converged set = %v, want [t3]", got)
	}
}

func ids(recs []record) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.ID)
	}
	return out
}
