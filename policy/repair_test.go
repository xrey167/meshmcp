package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildChain returns a valid n-record audit log as bytes.
func buildChain(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	a := NewAuditLog(&buf, func() string { return "T" })
	for i := 0; i < n; i++ {
		if err := a.Append(AuditRecord{Backend: "fs", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestVerifyForRepairCleanChain(t *testing.T) {
	data := buildChain(t, 5)
	res, truncateTo, torn := VerifyForRepair(data)
	if !res.OK || torn {
		t.Fatalf("clean chain: OK=%v torn=%v reason=%q", res.OK, torn, res.Reason)
	}
	if res.Count != 5 {
		t.Fatalf("count = %d, want 5", res.Count)
	}
	if truncateTo != int64(len(data)) {
		t.Fatalf("truncateTo = %d, want %d (whole file)", truncateTo, len(data))
	}
}

func TestVerifyForRepairTornTrailingLine(t *testing.T) {
	data := buildChain(t, 4)
	good := int64(len(data))
	// Simulate a torn write: append a partial (incomplete JSON) final record.
	torn := append(append([]byte{}, data...), []byte(`{"seq":5,"backend":"fs","pe`)...)

	res, truncateTo, isTorn := VerifyForRepair(torn)
	if res.OK {
		t.Fatal("a torn tail must not verify as OK")
	}
	if !isTorn {
		t.Fatalf("incomplete trailing record must be torn (recoverable); reason=%q", res.Reason)
	}
	if truncateTo != good {
		t.Fatalf("truncateTo = %d, want %d (end of last good record)", truncateTo, good)
	}
	if res.Count != 4 {
		t.Fatalf("recovered count = %d, want 4", res.Count)
	}
	// Truncating to truncateTo must leave a fully-verifying chain.
	if res2, _, _ := VerifyForRepair(torn[:truncateTo]); !res2.OK {
		t.Fatalf("truncated chain must verify: %q", res2.Reason)
	}
}

func TestVerifyForRepairTamperedRecordNeverRepairable(t *testing.T) {
	// A COMPLETE but edited record (valid JSON, wrong hash) must never be torn.
	data := buildChain(t, 4)
	tampered := []byte(strings.Replace(string(data), "read_file", "exfiltrate", 1))
	res, truncateTo, torn := VerifyForRepair(tampered)
	if res.OK {
		t.Fatal("a tampered record must not verify")
	}
	if torn {
		t.Fatal("a complete tampered record must NEVER be repairable (tamper-evidence)")
	}
	if truncateTo != 0 {
		t.Fatalf("tampered chain must not offer a truncation offset, got %d", truncateTo)
	}
}

func TestVerifyForRepairMidChainGarbageNeverRepairable(t *testing.T) {
	// Corrupt (unparseable) content BEFORE the final line is mid-chain damage,
	// not a torn tail — must fail hard.
	data := buildChain(t, 4)
	lines := bytes.SplitN(data, []byte("\n"), -1)
	// lines: [rec1, rec2, rec3, rec4, ""]. Corrupt rec2 into non-JSON.
	lines[1] = []byte("{not json")
	corrupt := bytes.Join(lines, []byte("\n"))
	_, _, torn := VerifyForRepair(corrupt)
	if torn {
		t.Fatal("garbage before the final line must not be treated as a torn tail")
	}
}

// syncFailWriter is a file-like sink whose Sync always fails.
type syncFailWriter struct{ bytes.Buffer }

func (syncFailWriter) Sync() error { return os.ErrInvalid }

func TestAuditSyncFailureSurfaces(t *testing.T) {
	w := &syncFailWriter{}
	a := NewAuditLog(w, func() string { return "T" }).WithSync(true)
	err := a.Append(AuditRecord{Backend: "fs", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow"})
	if err == nil || !strings.Contains(err.Error(), "fsync") {
		t.Fatalf("a Sync failure must surface as an error, got %v", err)
	}
}

func TestAuditSyncSkippedForNonFileSink(t *testing.T) {
	// A plain buffer has no Sync method: WithSync(true) must be a no-op, not a panic.
	var buf bytes.Buffer
	a := NewAuditLog(&buf, func() string { return "T" }).WithSync(true)
	if err := a.Append(AuditRecord{Backend: "fs", Peer: "p", Decision: "allow"}); err != nil {
		t.Fatalf("append to a non-syncable sink must succeed: %v", err)
	}
}

func TestAuditSyncOnRealFile(t *testing.T) {
	// End to end on a real *os.File: WithSync(true) writes a valid, fsync'd chain.
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	a := NewAuditLog(f, func() string { return "T" }).WithFailClosed(true).WithSync(true)
	for i := 0; i < 3; i++ {
		if err := a.Append(AuditRecord{Backend: "fs", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow"}); err != nil {
			t.Fatalf("synced append %d: %v", i, err)
		}
	}
	f.Close()
	data, _ := os.ReadFile(path)
	if res, _ := VerifyChain(bytes.NewReader(data)); !res.OK || res.Count != 3 {
		t.Fatalf("synced log must verify: OK=%v count=%d", res.OK, res.Count)
	}
}
