package kg

import (
	"path/filepath"
	"testing"
)

// TestTwoStoreHandlesOneFile_VerifyDetectsCorruption is the spec-demanded
// two-writer-append test, in its honest form: the kg package does NOT make two
// independent writers on one kg.jsonl safe (the Store mutex is within-process,
// per-handle). What the system guarantees instead is that the corruption such a
// setup produces is DETECTED — a fresh Open + Verify fails on the interleaved
// chain — which is exactly why the single-writer facade (air/knowstore) served
// by one `air kg serve` process is load-bearing, not decorative.
func TestTwoStoreHandlesOneFile_VerifyDetectsCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kg.jsonl")

	a, err := Open(path, func() string { return "t" })
	if err != nil {
		t.Fatalf("open handle A: %v", err)
	}
	b, err := Open(path, func() string { return "t" })
	if err != nil {
		t.Fatalf("open handle B: %v", err)
	}

	// Interleave appends from the two independent handles. Each handle keeps its
	// own seq counter and prev-hash cursor, so the file ends up with duplicate
	// sequence numbers and broken prev-hash links.
	if _, err := a.Assert("a1", "p", "o", "KA"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Assert("b1", "p", "o", "KB"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Assert("a2", "p", "o", "KA"); err != nil {
		t.Fatal(err)
	}

	fresh, err := Open(path, func() string { return "t" })
	if err != nil {
		t.Fatalf("reopen interleaved log: %v", err)
	}
	if err := fresh.Verify(); err == nil {
		t.Fatal("Verify must DETECT the corruption two independent writers produce on one file")
	}
}

// TestVerify_CleanSingleWriterLogPasses is the control: the same append volume
// through ONE handle produces a chain a fresh Open verifies clean.
func TestVerify_CleanSingleWriterLogPasses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kg.jsonl")
	st, err := Open(path, func() string { return "t" })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := st.Assert("s", "p", string(rune('a'+i)), "K"); err != nil {
			t.Fatal(err)
		}
	}
	fresh, err := Open(path, func() string { return "t" })
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Verify(); err != nil {
		t.Fatalf("single-writer log must verify clean: %v", err)
	}
	if fresh.Head() != 10 {
		t.Fatalf("head = %d, want 10", fresh.Head())
	}
}
