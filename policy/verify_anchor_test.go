package policy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// writeAnchoredChain writes n records with a checkpoint every `every`, each
// checkpoint also anchored to an in-memory FileAnchor. It does NOT flush a
// trailing partial batch, so n should be a multiple of `every` for a sealed
// log. Returns the audit, checkpoints, and anchor buffers plus the pubkey.
func writeAnchoredChain(t *testing.T, n, every int) (audit, checkpoints, anchors *bytes.Buffer, pub string) {
	t.Helper()
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	audit, checkpoints, anchors = &bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{}
	cp := NewCheckpointer(signer, checkpoints, every, func() string { return "T" }, NewFileAnchor(anchors, ""))
	a := NewAuditLog(audit, func() string { return "T" }).WithCheckpointer(cp)
	for i := 0; i < n; i++ {
		if err := a.write(AuditRecord{Backend: "fs", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	return audit, checkpoints, anchors, signer.PubKeyHex()
}

func cpMap(t *testing.T, checkpoints *bytes.Buffer) map[int]Checkpoint {
	t.Helper()
	out := map[int]Checkpoint{}
	for _, cp := range parseCheckpoints(t, checkpoints.String()) {
		out[cp.Seq] = cp
	}
	return out
}

// TestVerifyAnchorsFullyAnchored: sealed chain, every checkpoint witnessed →
// Status stays sealed and the anchor verdict is "anchored".
func TestVerifyAnchorsFullyAnchored(t *testing.T) {
	audit, cps, anchors, pub := writeAnchoredChain(t, 8, 4) // 2 checkpoints, both anchored
	res, err := VerifySigned(bytes.NewReader(audit.Bytes()), bytes.NewReader(cps.Bytes()), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusSealed {
		t.Fatalf("expected sealed, got %+v", res)
	}
	ares, err := VerifyAnchors(bytes.NewReader(anchors.Bytes()), cpMap(t, cps))
	if err != nil {
		t.Fatal(err)
	}
	if ares.Status != AnchorStatusAnchored || ares.Matched != 2 || len(ares.MismatchSeqs) != 0 {
		t.Fatalf("fully witnessed chain must be anchored: %+v", ares)
	}
}

// TestVerifyAnchorsWitnessLag: the last checkpoint is not witnessed →
// anchor_partial with the matched count intact; an empty anchor file is also
// anchor_partial (zero evidence is lag, not disagreement).
func TestVerifyAnchorsWitnessLag(t *testing.T) {
	_, cps, anchors, _ := writeAnchoredChain(t, 8, 4)
	// Drop the second (last) anchor record: the witness lagged.
	lines := strings.Split(strings.TrimRight(anchors.String(), "\n"), "\n")
	lagged := lines[0] + "\n"
	ares, err := VerifyAnchors(strings.NewReader(lagged), cpMap(t, cps))
	if err != nil {
		t.Fatal(err)
	}
	if ares.Status != AnchorStatusPartial || ares.Matched != 1 || ares.UnanchoredTail != 1 {
		t.Fatalf("lagging witness must be anchor_partial: %+v", ares)
	}

	empty, err := VerifyAnchors(strings.NewReader(""), cpMap(t, cps))
	if err != nil {
		t.Fatal(err)
	}
	if empty.Status != AnchorStatusPartial || empty.Matched != 0 {
		t.Fatalf("zero anchor records must be anchor_partial: %+v", empty)
	}
}

// TestVerifyAnchorsRollbackStillSealsInternally is the load-bearing scenario:
// an insider truncates the log to the first half and the checkpoints file to
// the first checkpoint. The truncated pair still verifies SEALED internally —
// and must keep doing so (the four states are never remapped) — but the
// witness remembers checkpoint 2, so the anchor verdict is anchor_mismatch.
func TestVerifyAnchorsRollbackStillSealsInternally(t *testing.T) {
	audit, cps, anchors, pub := writeAnchoredChain(t, 256, 128) // 2 checkpoints, both anchored

	auditLines := strings.Split(strings.TrimRight(audit.String(), "\n"), "\n")
	cpLines := strings.Split(strings.TrimRight(cps.String(), "\n"), "\n")
	if len(auditLines) != 256 || len(cpLines) != 2 {
		t.Fatalf("setup: %d records, %d checkpoints", len(auditLines), len(cpLines))
	}
	// Roll back log and checkpoints TOGETHER: 128 records + checkpoint 1.
	rolledAudit := strings.Join(auditLines[:128], "\n") + "\n"
	rolledCPs := cpLines[0] + "\n"

	res, err := VerifySigned(strings.NewReader(rolledAudit), strings.NewReader(rolledCPs), pub)
	if err != nil {
		t.Fatal(err)
	}
	// The rolled-back pair is internally consistent: without a witness this
	// rollback is undetectable, and the chain-internal verdict MUST still say
	// sealed — anchoring adds evidence, it never relaxes a state.
	if res.Status != StatusSealed || !res.OK || !res.Sealed {
		t.Fatalf("rolled-back pair must still verify sealed internally: %+v", res)
	}

	rolledMap := map[int]Checkpoint{}
	var cp1 Checkpoint
	if err := json.Unmarshal([]byte(cpLines[0]), &cp1); err != nil {
		t.Fatal(err)
	}
	rolledMap[1] = cp1
	ares, err := VerifyAnchors(bytes.NewReader(anchors.Bytes()), rolledMap)
	if err != nil {
		t.Fatal(err)
	}
	if ares.Status != AnchorStatusMismatch {
		t.Fatalf("the witness must expose the rollback: %+v", ares)
	}
	found := false
	for _, s := range ares.MismatchSeqs {
		if s == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("the mismatch must name the rolled-back checkpoint 2: %+v", ares)
	}
}

// TestVerifyAnchorsRewriteResignedWithRealKey: a full rewrite re-signed with
// the REAL key seals internally, but checkpoint 1's hash no longer matches the
// witnessed one → anchor_mismatch naming seq 1.
func TestVerifyAnchorsRewriteResignedWithRealKey(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	build := func(decision string) (audit, cps, anchors *bytes.Buffer) {
		audit, cps, anchors = &bytes.Buffer{}, &bytes.Buffer{}, &bytes.Buffer{}
		c := NewCheckpointer(signer, cps, 4, func() string { return "T" }, NewFileAnchor(anchors, ""))
		a := NewAuditLog(audit, func() string { return "T" }).WithCheckpointer(c)
		for i := 0; i < 4; i++ {
			if err := a.write(AuditRecord{Backend: "fs", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: decision}); err != nil {
				t.Fatal(err)
			}
		}
		return audit, cps, anchors
	}
	_, _, realAnchors := build("deny")                // the witnessed original
	rewrittenAudit, rewrittenCPs, _ := build("allow") // insider's re-signed rewrite

	res, err := VerifySigned(bytes.NewReader(rewrittenAudit.Bytes()), bytes.NewReader(rewrittenCPs.Bytes()), signer.PubKeyHex())
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusSealed {
		t.Fatalf("rewrite re-signed with the real key seals internally: %+v", res)
	}
	ares, err := VerifyAnchors(bytes.NewReader(realAnchors.Bytes()), cpMap(t, rewrittenCPs))
	if err != nil {
		t.Fatal(err)
	}
	if ares.Status != AnchorStatusMismatch {
		t.Fatalf("the witness must expose the rewrite: %+v", ares)
	}
	if len(ares.MismatchSeqs) == 0 || ares.MismatchSeqs[0] != 1 {
		t.Fatalf("the mismatch must name checkpoint 1: %+v", ares)
	}
}

// TestVerifyAnchorsFileTamper: editing an anchor line breaks the prev_anchor
// self-linkage of the NEXT line → anchor_mismatch; legacy records (no
// v/prev_anchor, string checkpoint_seq) still verify.
func TestVerifyAnchorsFileTamper(t *testing.T) {
	_, cps, anchors, _ := writeAnchoredChain(t, 8, 4)
	m := cpMap(t, cps)

	// Tamper: rewrite record 1's chain_head. Record 1 then mismatches AND
	// record 2's prev_anchor no longer matches the edited line's hash.
	lines := strings.Split(strings.TrimRight(anchors.String(), "\n"), "\n")
	var r1 AnchorRecord
	if err := json.Unmarshal([]byte(lines[0]), &r1); err != nil {
		t.Fatal(err)
	}
	r1.ChainHead = strings.Repeat("00", 32)
	b1, _ := json.Marshal(r1)
	tampered := string(b1) + "\n" + lines[1] + "\n"
	ares, err := VerifyAnchors(strings.NewReader(tampered), m)
	if err != nil {
		t.Fatal(err)
	}
	if ares.Status != AnchorStatusMismatch {
		t.Fatalf("edited anchor line must yield anchor_mismatch: %+v", ares)
	}

	// Legacy records: strip v/prev_anchor and stringify checkpoint_seq — the
	// shipped pre-v1 format. They carry no linkage and must still verify.
	var legacy strings.Builder
	for _, l := range lines {
		var rec AnchorRecord
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatal(err)
		}
		old := map[string]string{
			"checkpoint_seq": jsonInt(rec.Seq),
			"chain_head":     rec.ChainHead,
			"checkpoint":     rec.Checkpoint,
			"time":           rec.Time,
		}
		b, _ := json.Marshal(old)
		legacy.WriteString(string(b) + "\n")
	}
	lres, err := VerifyAnchors(strings.NewReader(legacy.String()), m)
	if err != nil {
		t.Fatal(err)
	}
	if lres.Status != AnchorStatusAnchored || lres.Matched != 2 {
		t.Fatalf("legacy anchor records must still verify: %+v", lres)
	}
}

func jsonInt(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestVerifyAnchorsDuplicateSeq: a duplicate witness record with the SAME hash
// is an idempotent re-anchor (fine); with a DIFFERENT hash it is fork evidence
// (anchor_mismatch).
func TestVerifyAnchorsDuplicateSeq(t *testing.T) {
	_, cps, anchors, _ := writeAnchoredChain(t, 8, 4)
	m := cpMap(t, cps)
	lines := strings.Split(strings.TrimRight(anchors.String(), "\n"), "\n")

	// Same-hash duplicate (a replayed anchor, e.g. via `audit anchor`). The
	// duplicate line's prev_anchor won't match — so build it WITHOUT linkage
	// (legacy-style), which is exactly what a lenient re-anchor tool emits.
	var r2 AnchorRecord
	if err := json.Unmarshal([]byte(lines[1]), &r2); err != nil {
		t.Fatal(err)
	}
	dupSame := map[string]string{"checkpoint_seq": jsonInt(r2.Seq), "chain_head": r2.ChainHead, "checkpoint": r2.Checkpoint, "time": r2.Time}
	bSame, _ := json.Marshal(dupSame)
	sameFile := strings.Join(lines, "\n") + "\n" + string(bSame) + "\n"
	res, err := VerifyAnchors(strings.NewReader(sameFile), m)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != AnchorStatusAnchored {
		t.Fatalf("idempotent same-hash duplicate must stay anchored: %+v", res)
	}

	// Different-hash duplicate: fork evidence.
	dupFork := map[string]string{"checkpoint_seq": jsonInt(r2.Seq), "chain_head": r2.ChainHead, "checkpoint": strings.Repeat("ab", 32), "time": r2.Time}
	bFork, _ := json.Marshal(dupFork)
	forkFile := strings.Join(lines, "\n") + "\n" + string(bFork) + "\n"
	fres, err := VerifyAnchors(strings.NewReader(forkFile), m)
	if err != nil {
		t.Fatal(err)
	}
	if fres.Status != AnchorStatusMismatch {
		t.Fatalf("conflicting duplicate must be anchor_mismatch: %+v", fres)
	}
}

// TestVerifyAnchorsRewriteUnderNewSignerNamesOtherRecords: an insider rewrites
// log + checkpoints under a NEW key (e.g. after losing the original). The
// witness's records are attributed to the OLD pinned signer, so none match and
// the verdict stays anchor_partial (statuses and the four chain states are
// untouched; the chain-internal verdict already fails pinning) — but the
// reason must surface the other-signer records instead of reading like plain
// witness lag that an `audit anchor` replay would heal.
func TestVerifyAnchorsRewriteUnderNewSignerNamesOtherRecords(t *testing.T) {
	// Original gateway chain, witnessed with ATTRIBUTED records (as the
	// control-plane witness writes them).
	_, cpsA, _, pubA := writeAnchoredChain(t, 8, 4)
	witness := &bytes.Buffer{}
	fa := NewFileAnchor(witness, "")
	for _, cp := range parseCheckpoints(t, cpsA.String()) {
		if err := fa.Witness(cp, pubA); err != nil {
			t.Fatal(err)
		}
	}

	// Full rewrite under a fresh signer key.
	_, cpsB, _, _ := writeAnchoredChain(t, 8, 4)

	res, err := VerifyAnchors(bytes.NewReader(witness.Bytes()), cpMap(t, cpsB))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != AnchorStatusPartial || res.Matched != 0 {
		t.Fatalf("an other-signer-only witness must stay anchor_partial: %+v", res)
	}
	if res.OtherSignerRecords != 2 {
		t.Fatalf("both witness records must be counted as other-signer: %+v", res)
	}
	if !strings.Contains(res.Reason, "other signer key(s)") || !strings.Contains(res.Reason, "rewritten under a new signer") {
		t.Fatalf("the partial reason must surface the other-signer records as possible rewrite evidence: %q", res.Reason)
	}
}

// TestVerifyAnchorsSkipsOtherSigners: witness records for a different signer
// (a shared witness file) are skipped, not treated as mismatches.
func TestVerifyAnchorsSkipsOtherSigners(t *testing.T) {
	_, cps, anchors, _ := writeAnchoredChain(t, 8, 4)
	m := cpMap(t, cps)

	otherSigner, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	otherCP := otherSigner.sign(Checkpoint{Version: 1, Seq: 1, FromSeq: 1, ToSeq: 4, Count: 4, MerkleRoot: "aa", ChainHead: "bb", Time: "T"})

	// Append the other gateway's witnessed checkpoint (with signer) to the file.
	lines := strings.Split(strings.TrimRight(anchors.String(), "\n"), "\n")
	fa := NewFileAnchor(anchors, AnchorLineHash([]byte(lines[len(lines)-1])))
	if err := fa.Witness(otherCP, otherSigner.PubKeyHex()); err != nil {
		t.Fatal(err)
	}
	shared := anchors.String()

	res, err := VerifyAnchors(strings.NewReader(shared), m)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != AnchorStatusAnchored || res.Matched != 2 {
		t.Fatalf("another signer's records must be skipped, not mismatched: %+v", res)
	}
	if res.OtherSignerRecords != 1 || res.Reason != "" {
		t.Fatalf("the skip must be counted without polluting an anchored verdict: %+v", res)
	}
}
