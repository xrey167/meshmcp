package policy

import (
	"bytes"
	"strings"
	"testing"
)

// writeSignedChain writes n records through an AuditLog with a checkpointer
// every `every` records, returning the audit JSONL, checkpoint JSONL, and the
// signer's public key.
func writeSignedChain(t *testing.T, n, every int) (audit, checkpoints *bytes.Buffer, pub string) {
	t.Helper()
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	audit = &bytes.Buffer{}
	checkpoints = &bytes.Buffer{}
	cp := NewCheckpointer(signer, checkpoints, every, func() string { return "T" }, nil)
	a := NewAuditLog(audit, func() string { return "T" }).WithCheckpointer(cp)
	for i := 0; i < n; i++ {
		a.write(AuditRecord{Backend: "fs", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow"})
	}
	a.Flush()
	return audit, checkpoints, signer.PubKeyHex()
}

func TestSignedVerifyIntact(t *testing.T) {
	audit, cps, pub := writeSignedChain(t, 10, 4) // 3 checkpoints: 4+4+2
	res, err := VerifySigned(bytes.NewReader(audit.Bytes()), bytes.NewReader(cps.Bytes()), pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("signed chain should verify: %+v", res)
	}
	if res.Checkpoints != 3 {
		t.Fatalf("expected 3 checkpoints, got %d", res.Checkpoints)
	}
	if res.CoveredRecords != 10 {
		t.Fatalf("expected all 10 records covered, got %d", res.CoveredRecords)
	}
}

func TestSignedVerifyDetectsFullRewrite(t *testing.T) {
	// The attack a plain hash chain cannot stop: an insider rewrites a record
	// AND re-hashes the whole chain to stay internally consistent. Here we
	// simulate the strongest version — edit a record's content; the plain
	// chain could be repaired, but the SIGNED Merkle root cannot.
	audit, cps, pub := writeSignedChain(t, 8, 4)
	lines := strings.Split(strings.TrimRight(audit.String(), "\n"), "\n")
	// Edit record seq 2 (covered by checkpoint 1).
	lines[1] = strings.Replace(lines[1], "read_file", "exfiltrate", 1)
	tampered := strings.Join(lines, "\n")

	res, err := VerifySigned(strings.NewReader(tampered), bytes.NewReader(cps.Bytes()), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("edited record must fail signed verification")
	}
	if !strings.Contains(res.Reason, "Merkle root mismatch") {
		t.Fatalf("expected a Merkle mismatch, got: %s", res.Reason)
	}
}

func TestSignedVerifyDetectsForgedCheckpoint(t *testing.T) {
	// An attacker without the private key cannot produce a valid checkpoint.
	audit, cps, pub := writeSignedChain(t, 4, 4)
	// Corrupt the signature of the checkpoint.
	tampered := strings.Replace(cps.String(), `"signature":"`, `"signature":"00`, 1)

	res, _ := VerifySigned(bytes.NewReader(audit.Bytes()), strings.NewReader(tampered), pub)
	if res.OK {
		t.Fatalf("a checkpoint with a broken signature must not verify")
	}
	if !strings.Contains(res.Reason, "signature") {
		t.Fatalf("expected a signature failure, got: %s", res.Reason)
	}
}

func TestSignedVerifyPinsSigner(t *testing.T) {
	audit, cps, _ := writeSignedChain(t, 4, 4)
	// Verifying against a different expected public key must fail.
	wrongPub := strings.Repeat("ab", 32)
	res, _ := VerifySigned(bytes.NewReader(audit.Bytes()), bytes.NewReader(cps.Bytes()), wrongPub)
	if res.OK {
		t.Fatalf("verification pinned to the wrong signer must fail")
	}
	if !strings.Contains(res.Reason, "unexpected key") {
		t.Fatalf("expected an unexpected-key failure, got: %s", res.Reason)
	}
}

func TestMerkleRootStableAndOrderSensitive(t *testing.T) {
	a := MerkleRoot([][]byte{[]byte("x"), []byte("y"), []byte("z")})
	b := MerkleRoot([][]byte{[]byte("x"), []byte("y"), []byte("z")})
	if a != b {
		t.Fatal("Merkle root should be deterministic")
	}
	c := MerkleRoot([][]byte{[]byte("z"), []byte("y"), []byte("x")})
	if a == c {
		t.Fatal("Merkle root should depend on leaf order")
	}
}
