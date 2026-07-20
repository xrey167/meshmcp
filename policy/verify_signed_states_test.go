package policy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// writeUnsealedChain writes n records but flushes a checkpoint only over the
// first `sealTo` of them, leaving an unsealed tail. It returns the audit and
// checkpoint buffers and the signer's public key.
func writeUnsealedChain(t *testing.T, n, sealAt int) (audit, checkpoints *bytes.Buffer, pub string) {
	t.Helper()
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	audit = &bytes.Buffer{}
	checkpoints = &bytes.Buffer{}
	// A checkpoint every `sealAt` records: after sealAt records exactly one
	// checkpoint is emitted; the remaining n-sealAt records are an unsealed tail
	// (we never call Flush).
	cp := NewCheckpointer(signer, checkpoints, sealAt, func() string { return "T" }, nil)
	a := NewAuditLog(audit, func() string { return "T" }).WithCheckpointer(cp)
	for i := 0; i < n; i++ {
		a.write(AuditRecord{Backend: "fs", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow"})
	}
	// deliberately no a.Flush(): the tail stays unsealed
	return audit, checkpoints, signer.PubKeyHex()
}

// TestSignedVerifyUnsealedTail: a chain whose last records are not covered by
// any checkpoint must NOT be reported as sealed/complete. This is the core
// regression for "audit verification cannot report completeness with an
// uncovered tail."
func TestSignedVerifyUnsealedTail(t *testing.T) {
	audit, cps, pub := writeUnsealedChain(t, 10, 4) // 1 checkpoint covers 1..4; 5..10 unsealed
	res, err := VerifySigned(bytes.NewReader(audit.Bytes()), bytes.NewReader(cps.Bytes()), pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("the covered prefix is valid, so OK should be true: %+v", res)
	}
	if res.Sealed {
		t.Fatalf("chain with a 6-record unsealed tail must not be Sealed: %+v", res)
	}
	if res.Status != StatusUnsealed {
		t.Fatalf("expected status %q, got %q (%+v)", StatusUnsealed, res.Status, res)
	}
	if res.CoveredRecords >= res.Records {
		t.Fatalf("covered (%d) must be less than total (%d)", res.CoveredRecords, res.Records)
	}
}

// TestSignedVerifySealedWhenFlushed: once the tail is flushed, the same chain
// verifies as fully sealed and trusted (pinned key).
func TestSignedVerifySealedWhenFlushed(t *testing.T) {
	audit, cps, pub := writeSignedChain(t, 10, 4) // writeSignedChain calls Flush
	res, err := VerifySigned(bytes.NewReader(audit.Bytes()), bytes.NewReader(cps.Bytes()), pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.Sealed || !res.Trusted {
		t.Fatalf("flushed, pinned chain should be OK+Sealed+Trusted: %+v", res)
	}
	if res.Status != StatusSealed {
		t.Fatalf("expected status %q, got %q", StatusSealed, res.Status)
	}
}

// TestSignedVerifyUntrustedKey: without an expected pinned key, a valid chain is
// only "cryptographically valid but signed by an untrusted key" — never trusted.
func TestSignedVerifyUntrustedKey(t *testing.T) {
	audit, cps, _ := writeSignedChain(t, 8, 4)
	res, err := VerifySigned(bytes.NewReader(audit.Bytes()), bytes.NewReader(cps.Bytes()), "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Trusted {
		t.Fatalf("no key was pinned, so the result must not be Trusted: %+v", res)
	}
	if res.Status != StatusUntrustedKey {
		t.Fatalf("expected status %q, got %q", StatusUntrustedKey, res.Status)
	}
}

// TestSignedVerifyDuplicateSeq: a log containing two records with the same
// sequence number is not a well-formed single-writer chain and must be rejected
// rather than silently collapsed.
func TestSignedVerifyDuplicateSeq(t *testing.T) {
	audit, cps, pub := writeSignedChain(t, 4, 4)
	lines := strings.Split(strings.TrimRight(audit.String(), "\n"), "\n")
	// Duplicate the second record's line (same seq appears twice).
	dup := append([]string{}, lines...)
	dup = append(dup, lines[1])
	res, err := VerifySigned(strings.NewReader(strings.Join(dup, "\n")), bytes.NewReader(cps.Bytes()), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("a duplicate sequence number must fail verification: %+v", res)
	}
	if !strings.Contains(res.Reason, "sequence") {
		t.Fatalf("expected a sequence-number reason, got %q", res.Reason)
	}
}

// TestSignedVerifyMixedSigners: when no key is pinned, a log whose checkpoints
// are signed by more than one key must be rejected (an attacker could append
// their own checkpoints signed with a different key).
func TestSignedVerifyMixedSigners(t *testing.T) {
	audit, cps, _ := writeSignedChain(t, 8, 4) // 2 checkpoints from signer A
	// Re-sign only the SECOND checkpoint with a different key B, keeping A's
	// first checkpoint. This yields a checkpoint file with two signers.
	cpLines := strings.Split(strings.TrimRight(cps.String(), "\n"), "\n")
	if len(cpLines) < 2 {
		t.Fatalf("expected >=2 checkpoints, got %d", len(cpLines))
	}
	signerB, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	var cp2 Checkpoint
	if err := json.Unmarshal([]byte(cpLines[1]), &cp2); err != nil {
		t.Fatal(err)
	}
	// Strip A's signature and re-sign the exact same checkpoint body with B.
	cp2.Sig = ""
	cp2.PubKey = ""
	cp2 = signerB.sign(cp2)
	b2, err := json.Marshal(cp2)
	if err != nil {
		t.Fatal(err)
	}
	cpLines[1] = string(b2)
	mixed := strings.Join(cpLines, "\n")

	res, err := VerifySigned(bytes.NewReader(audit.Bytes()), strings.NewReader(mixed), "")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("checkpoints signed by two different keys must fail without a pin: %+v", res)
	}
	if !strings.Contains(strings.ToLower(res.Reason), "signer") && !strings.Contains(strings.ToLower(res.Reason), "key") {
		t.Fatalf("expected a mixed-signer reason, got %q", res.Reason)
	}
}
