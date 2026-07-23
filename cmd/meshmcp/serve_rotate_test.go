package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

func writeRotatedLedger(t *testing.T, path string, maxBytes int64, n int) {
	t.Helper()
	sink, err := policy.OpenRotatingFileSink(path, maxBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := policy.NewAuditLog(sink, func() string { return "T" })
	for i := 0; i < n; i++ {
		if err := a.Append(policy.AuditRecord{
			Backend: "fs", Peer: "agent.mesh", Method: "tools/call",
			Tool: "read_file", Decision: "allow", Rule: 0,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}

// After rotation, a restart must resume the SAME chain: the active segment is
// verified against the newest archive's head and the seed is the absolute
// (seq, hash) across all segments.
func TestSeedAuditFromExistingResumesRotatedLedger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeRotatedLedger(t, path, 600, 8)

	archives, _ := filepath.Glob(path + ".*")
	if len(archives) == 0 {
		t.Fatal("test setup: expected at least one archive")
	}

	seq, hash, err := seedAuditFromExisting(path)
	if err != nil {
		t.Fatalf("seedAuditFromExisting on rotated ledger: %v", err)
	}
	if seq != 8 || hash == "" {
		t.Fatalf("expected resume at seq 8, got seq=%d hash=%q", seq, hash)
	}

	// Appending with that seed keeps the concatenated chain intact.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	a := policy.NewAuditLog(f, func() string { return "T" })
	a.SeedFrom(seq, hash)
	if err := a.Append(policy.AuditRecord{Backend: "fs", Peer: "p", Method: "tools/call", Tool: "t", Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	seq2, _, err := seedAuditFromExisting(path)
	if err != nil || seq2 != 9 {
		t.Fatalf("after append: seq=%d err=%v", seq2, err)
	}
}

// A rotated active segment whose archives were deleted must fail closed —
// its seq>1 start cannot be verified against anything.
func TestSeedAuditFromExistingRefusesOrphanSegment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeRotatedLedger(t, path, 600, 8)

	archives, _ := filepath.Glob(path + ".*")
	for _, a := range archives {
		if err := os.Remove(a); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := seedAuditFromExisting(path); err == nil {
		t.Fatal("an orphaned mid-chain segment must be refused")
	}
}

// Rotation crash window: archives exist but the new active file was never
// written (or is empty) — the seed must come from the newest archive's head,
// never a fresh seq-1 genesis.
func TestSeedAuditFromExistingEmptyActiveWithArchives(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeRotatedLedger(t, path, 600, 8)

	// Simulate the crash: empty active file.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	seq, hash, err := seedAuditFromExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	if seq == 0 || hash == "" {
		t.Fatalf("empty active with archives must seed from the archive head, got seq=%d hash=%q", seq, hash)
	}
}
