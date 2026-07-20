package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

// TestAuditRestartContinuity proves that a gateway restart continues the SAME
// audit + checkpoint chain (via seedAuditFromExisting / seedCheckpointFromExisting)
// rather than resetting to seq 1 with a fresh genesis and a new checkpoint root.
func TestAuditRestartContinuity(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	cpPath := filepath.Join(dir, "cp.jsonl")
	now := func() string { return "T" }

	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PubKeyHex()

	writeN := func(seedSeq int, seedHash string, seedCP int, prevCP string, n int) {
		af, err := os.OpenFile(auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer af.Close()
		cf, err := os.OpenFile(cpPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer cf.Close()

		cp := policy.NewCheckpointer(signer, cf, 4, now, nil)
		if seedCP > 0 {
			cp.SeedFrom(seedCP, prevCP)
		}
		a := policy.NewAuditLog(af, now).WithCheckpointer(cp)
		if seedSeq > 0 {
			a.SeedFrom(seedSeq, seedHash)
		}
		for i := 0; i < n; i++ {
			if err := a.Append(policy.AuditRecord{Backend: "fs", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow"}); err != nil {
				t.Fatal(err)
			}
		}
		a.Flush()
	}

	// Session 1: 4 records → 1 checkpoint.
	writeN(0, "", 0, "", 4)

	// "Restart": recover the verified tail, then continue.
	seq, lastHash, err := seedAuditFromExisting(auditPath)
	if err != nil {
		t.Fatalf("seed audit: %v", err)
	}
	if seq != 4 {
		t.Fatalf("expected to resume from seq 4, got %d", seq)
	}
	cpSeq, prevCP, err := seedCheckpointFromExisting(cpPath)
	if err != nil {
		t.Fatalf("seed checkpoints: %v", err)
	}
	if cpSeq != 1 {
		t.Fatalf("expected to resume from checkpoint 1, got %d", cpSeq)
	}

	// Session 2: 4 more records (seq 5..8) → checkpoint 2.
	writeN(seq, lastHash, cpSeq, prevCP, 4)

	// The combined file is ONE continuous, sealed, trusted chain with no
	// duplicate seq 1 and 8 contiguous records.
	auditBytes, _ := os.ReadFile(auditPath)
	cpBytes, _ := os.ReadFile(cpPath)
	res, err := policy.VerifySigned(strings.NewReader(string(auditBytes)), strings.NewReader(string(cpBytes)), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != policy.StatusSealed {
		t.Fatalf("resumed chain should be sealed+trusted, got status %q reason %q", res.Status, res.Reason)
	}
	if res.Records != 8 {
		t.Fatalf("expected 8 contiguous records across the restart, got %d", res.Records)
	}
	if res.Checkpoints != 2 {
		t.Fatalf("expected 2 checkpoints across the restart, got %d", res.Checkpoints)
	}
	if strings.Count(string(auditBytes), `"seq":1`) != 1 {
		t.Fatalf("restart created a duplicate seq 1 (chain reset), file:\n%s", auditBytes)
	}
}

// TestAuditRestartRefusesTamperedLog: a restart must refuse to append to (and
// silently reset) an existing log that no longer verifies.
func TestAuditRestartRefusesTamperedLog(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	now := func() string { return "T" }
	a := policy.NewAuditLog(mustCreate(t, auditPath), now)
	for i := 0; i < 3; i++ {
		_ = a.Append(policy.AuditRecord{Backend: "fs", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow"})
	}
	// Tamper: flip a byte in the middle record's content.
	b, _ := os.ReadFile(auditPath)
	tampered := strings.Replace(string(b), "read_file", "exfiltrate", 1)
	_ = os.WriteFile(auditPath, []byte(tampered), 0o600)

	if _, _, err := seedAuditFromExisting(auditPath); err == nil {
		t.Fatal("seeding must refuse a tampered/unverifiable existing audit log")
	}
}

func mustCreate(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
