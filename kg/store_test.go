package kg

import (
	"os"
	"path/filepath"
	"testing"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "kg.jsonl"), func() string { return "t" })
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return st
}

func TestAssertQueryProvenance(t *testing.T) {
	st := newStore(t)
	if _, err := st.Assert("alice", "knows", "bob", "KEYA"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Assert("alice", "role", "engineer", "KEYB"); err != nil {
		t.Fatal(err)
	}

	got := st.Query("alice", "", "", 0)
	if len(got) != 2 {
		t.Fatalf("query alice: got %d triples, want 2", len(got))
	}
	// Provenance is stamped per triple.
	for _, r := range got {
		if r.P == "knows" && r.Peer != "KEYA" {
			t.Errorf("knows triple provenance = %q, want KEYA", r.Peer)
		}
		if r.P == "role" && r.Peer != "KEYB" {
			t.Errorf("role triple provenance = %q, want KEYB", r.Peer)
		}
	}
	if n := st.Query("", "knows", "", 0); len(n) != 1 {
		t.Errorf("predicate query: got %d, want 1", len(n))
	}
}

func TestNeighbors(t *testing.T) {
	st := newStore(t)
	st.Assert("alice", "knows", "bob", "K")
	st.Assert("carol", "knows", "alice", "K")
	st.Assert("dave", "knows", "erin", "K")

	got := st.Neighbors("alice", 0)
	if len(got) != 2 {
		t.Fatalf("neighbors(alice): got %d, want 2 (as subject and object)", len(got))
	}
}

func TestTimeTravel(t *testing.T) {
	st := newStore(t)
	r1, _ := st.Assert("x", "status", "draft", "K")
	_, _ = st.Assert("x", "status", "final", "K") // seq 2
	st.Delete(r1.ID, "K")                         // seq 3: draft tombstoned

	// Now: only "final" remains.
	now := st.Query("x", "status", "", 0)
	if len(now) != 1 || now[0].O != "final" {
		t.Fatalf("current: got %v, want just final", now)
	}
	// As of seq 1: only "draft" existed.
	past := st.Query("x", "status", "", 1)
	if len(past) != 1 || past[0].O != "draft" {
		t.Fatalf("as_of=1: got %v, want just draft", past)
	}
	// As of seq 2: both draft and final (delete not yet applied).
	if mid := st.Query("x", "status", "", 2); len(mid) != 2 {
		t.Fatalf("as_of=2: got %d, want 2", len(mid))
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kg.jsonl")
	st, _ := Open(path, func() string { return "t" })
	st.Assert("a", "b", "c", "K")
	st.Assert("d", "e", "f", "K")
	if err := st.Verify(); err != nil {
		t.Fatalf("clean store should verify: %v", err)
	}

	// Reload persisted state and confirm it still verifies (chain survives restart).
	st2, err := Open(path, func() string { return "t" })
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.Verify(); err != nil {
		t.Fatalf("reloaded store should verify: %v", err)
	}
	if st2.Head() != 2 {
		t.Fatalf("reloaded head = %d, want 2", st2.Head())
	}

	// Tamper with the file: flip a byte in the object of the first record.
	raw, _ := os.ReadFile(path)
	tampered := []byte(string(raw))
	idx := indexOf(tampered, []byte(`"o":"c"`))
	if idx < 0 {
		t.Fatal("could not locate record to tamper")
	}
	tampered[idx+5] = 'X' // change the object value "c" -> "X" (still valid JSON)
	os.WriteFile(path, tampered, 0o600)

	st3, err := Open(path, func() string { return "t" })
	if err != nil {
		t.Fatalf("reopen tampered: %v", err)
	}
	if err := st3.Verify(); err == nil {
		t.Fatal("verify should FAIL on a tampered store")
	}
}

func indexOf(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if string(hay[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}
