package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

// TestAuditAttestSignedBundle builds a signed audit log + checkpoints, runs
// `audit attest`, and confirms the bundle reports a passing signed-Merkle
// verdict pinned to the signer (F32).
func TestAuditAttestSignedBundle(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cpPath := filepath.Join(dir, "cps.jsonl")

	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	lf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := os.Create(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	cp := policy.NewCheckpointer(signer, cf, 2, func() string { return "t" }, nil)
	al := policy.NewAuditLog(lf, func() string { return "t" }).WithCheckpointer(cp)
	for i := 0; i < 4; i++ {
		if err := al.Append(policy.AuditRecord{Backend: "b", Peer: "alice", Tool: "read", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	al.Flush()
	lf.Close()
	cf.Close()

	// Capture stdout from auditAttest.
	out := captureStdout(t, func() {
		if err := auditAttest([]string{"--audit", logPath, "--checkpoints", cpPath, "--pubkey", signer.PubKeyHex()}); err != nil {
			t.Fatalf("attest: %v", err)
		}
	})
	if !strings.Contains(out, `"mode": "signed-merkle"`) || !strings.Contains(out, `"ok": true`) {
		t.Fatalf("attestation missing a passing signed verdict:\n%s", out)
	}
	if !strings.Contains(out, signer.PubKeyHex()) {
		t.Fatalf("attestation did not pin the signer pubkey:\n%s", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	buf := make([]byte, 1<<16)
	n, _ := r.Read(buf)
	return string(buf[:n])
}
