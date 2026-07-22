package policy

import (
	"bytes"
	"encoding/json"
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
	// simulate the STRONGEST version — edit a record's content and repair every
	// stored hash + prev_hash link so the plain chain verifies — yet the SIGNED
	// Merkle root (over the original hashes) still cannot be forged.
	audit, cps, pub := writeSignedChain(t, 8, 4)
	recs := parseRecords(t, audit.String())
	recs[1].Tool = "exfiltrate" // edit record seq 2 (covered by checkpoint 1)
	rehashChain(recs)           // repair stored hash + prev_hash for the whole chain
	tampered := marshalRecords(t, recs)

	res, err := VerifySigned(strings.NewReader(tampered), bytes.NewReader(cps.Bytes()), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("a re-hashed rewrite must still fail against the signed Merkle root")
	}
	if !strings.Contains(res.Reason, "Merkle root mismatch") {
		t.Fatalf("expected a Merkle mismatch, got: %s", res.Reason)
	}
}

// TestSignedVerifyDetectsBrokenLinkage: editing a record's content WITHOUT
// repairing its stored hash is caught by the per-record hash-chain check (the
// stored hash no longer matches the content).
func TestSignedVerifyDetectsBrokenLinkage(t *testing.T) {
	audit, cps, pub := writeSignedChain(t, 8, 4)
	lines := strings.Split(strings.TrimRight(audit.String(), "\n"), "\n")
	lines[1] = strings.Replace(lines[1], "read_file", "exfiltrate", 1) // content only
	res, err := VerifySigned(strings.NewReader(strings.Join(lines, "\n")), bytes.NewReader(cps.Bytes()), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || !strings.Contains(res.Reason, "stored hash") {
		t.Fatalf("content edit without a stored-hash repair must fail with a stored-hash mismatch, got OK=%v reason=%q", res.OK, res.Reason)
	}
}

// TestSignedVerifyDetectsTailTamper: a tampered record in the UNSEALED tail (not
// covered by any checkpoint) is now caught by the hash-chain check, so
// "valid chain with unsealed tail" genuinely means the tail is hash-verified.
func TestSignedVerifyDetectsTailTamper(t *testing.T) {
	audit, cps, pub := writeUnsealedChain(t, 10, 4) // checkpoints cover 1..8; 9,10 unsealed
	lines := strings.Split(strings.TrimRight(audit.String(), "\n"), "\n")
	lines[9] = strings.Replace(lines[9], "read_file", "exfiltrate", 1) // edit seq 10 (tail)
	res, err := VerifySigned(strings.NewReader(strings.Join(lines, "\n")), bytes.NewReader(cps.Bytes()), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK {
		t.Fatalf("a tampered unsealed-tail record must fail verification, got status %q", res.Status)
	}
}

// parseRecords / marshalRecords / rehashChain are test helpers to build a
// self-consistent (re-hashed) chain.
func parseRecords(t *testing.T, jsonl string) []AuditRecord {
	t.Helper()
	var recs []AuditRecord
	for _, line := range strings.Split(strings.TrimRight(jsonl, "\n"), "\n") {
		var r AuditRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("parse record: %v", err)
		}
		recs = append(recs, r)
	}
	return recs
}

func rehashChain(recs []AuditRecord) {
	prev := ""
	for i := range recs {
		recs[i].PrevHash = prev
		recs[i].Hash = ""
		h, _, _ := chainHash(recs[i])
		recs[i].Hash = h
		prev = h
	}
}

func marshalRecords(t *testing.T, recs []AuditRecord) string {
	t.Helper()
	var b strings.Builder
	for _, r := range recs {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String()
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
