package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

func writeDashRecords(t *testing.T, path string, seedSeq int, seedHash string, n int, tool string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	a := policy.NewAuditLog(f, func() string { return "T" })
	if seedSeq > 0 {
		a.SeedFrom(seedSeq, seedHash)
	}
	for i := 0; i < n; i++ {
		if err := a.Append(policy.AuditRecord{
			Backend: "fs", Peer: "agent.mesh", PeerKey: "K",
			Method: "tools/call", Tool: tool, Decision: "allow", Rule: 0,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func fullAnalyze(t *testing.T, path string, recentCap int) policy.Summary {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := policy.Analyze(f, recentCap)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func sameSummary(t *testing.T, got, want policy.Summary, phase string) {
	t.Helper()
	gb, _ := json.Marshal(got)
	wb, _ := json.Marshal(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: tailing summary diverged from full Analyze\n got: %s\nwant: %s", phase, gb, wb)
	}
}

// The stateful tailer must produce byte-identical summaries to a full Analyze,
// across appends, while only reading the new bytes on each poll.
func TestAuditTailerMatchesFullAnalyze(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeDashRecords(t, path, 0, "", 5, "read_file")

	tail := newAuditTailer(path, 3)
	got, err := tail.summary()
	if err != nil {
		t.Fatal(err)
	}
	sameSummary(t, got, fullAnalyze(t, path, 3), "initial scan")

	// Append more records continuing the same chain; next poll folds only them.
	last := got.Chain
	writeDashRecords(t, path, last.Count, last.LastHash, 4, "write_file")
	got2, err := tail.summary()
	if err != nil {
		t.Fatal(err)
	}
	sameSummary(t, got2, fullAnalyze(t, path, 3), "incremental append")
	if got2.Records != 9 || !got2.Chain.OK || got2.Chain.Count != 9 {
		t.Fatalf("unexpected rollup after append: %+v", got2.Chain)
	}
}

// A partially written trailing record (torn mid-write) must not be misread; it
// is folded once completed.
func TestAuditTailerPartialTrailingLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeDashRecords(t, path, 0, "", 2, "read_file")
	// Simulate a record mid-write.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"time":"T","seq":3,`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	tail := newAuditTailer(path, 10)
	got, err := tail.summary()
	if err != nil {
		t.Fatal(err)
	}
	if got.Records != 2 || !got.Chain.OK {
		t.Fatalf("partial trailing line must be ignored, got %d records chain=%+v", got.Records, got.Chain)
	}
}

// S51 rotation: after RotatingFileSink seals the active file into a
// <path>.<timestamp> archive and reopens a fresh mid-chain segment, the tailer
// must keep whole-ledger totals and a chain verdict seeded from genesis — not
// report a healthy rotated ledger as tampered because the active segment
// starts at seq N+1.
func TestAuditTailerRotationKeepsWholeLedger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeDashRecords(t, path, 0, "", 5, "read_file")

	tail := newAuditTailer(path, 10)
	got, err := tail.summary()
	if err != nil {
		t.Fatal(err)
	}
	head := got.Chain

	// Rotate the way RotatingFileSink does: rename the sealed segment, then a
	// fresh active file continues the same chain from the archived head.
	if err := os.Rename(path, path+".20260101T000000Z"); err != nil {
		t.Fatal(err)
	}
	writeDashRecords(t, path, head.Count, head.LastHash, 3, "write_file")

	// Warm tailer: shrink detection resets it, and the rescan folds the
	// archive before the active segment.
	got2, err := tail.summary()
	if err != nil {
		t.Fatal(err)
	}
	if !got2.Chain.OK {
		t.Fatalf("rotated ledger must stay intact, got chain %+v", got2.Chain)
	}
	if got2.Records != 8 || got2.Chain.Count != 8 {
		t.Fatalf("totals must span archive + active: records=%d chain=%+v", got2.Records, got2.Chain)
	}

	// Cold tailer (dash restarted after rotation) must agree byte for byte.
	got3, err := newAuditTailer(path, 10).summary()
	if err != nil {
		t.Fatal(err)
	}
	sameSummary(t, got3, got2, "cold start after rotation")

	// Steady state after rotation is incremental again.
	writeDashRecords(t, path, got2.Chain.Count, got2.Chain.LastHash, 2, "read_file")
	got4, err := tail.summary()
	if err != nil {
		t.Fatal(err)
	}
	if !got4.Chain.OK || got4.Records != 10 || got4.Chain.Count != 10 {
		t.Fatalf("post-rotation append must keep folding: records=%d chain=%+v", got4.Records, got4.Chain)
	}
}

// Truncation/rotation of the file underneath the tailer resets its state and
// rescans from the start.
func TestAuditTailerResetOnTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeDashRecords(t, path, 0, "", 6, "read_file")

	tail := newAuditTailer(path, 10)
	if _, err := tail.summary(); err != nil {
		t.Fatal(err)
	}

	// Replace with a shorter, fresh ledger.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writeDashRecords(t, path, 0, "", 2, "list_dir")
	got, err := tail.summary()
	if err != nil {
		t.Fatal(err)
	}
	sameSummary(t, got, fullAnalyze(t, path, 10), "after truncation")
	if got.Records != 2 {
		t.Fatalf("expected reset to 2 records, got %d", got.Records)
	}
}
