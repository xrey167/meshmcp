package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/control"
	"github.com/xrey167/meshmcp/policy"
)

// writeAnchoredFixture writes a sealed audit log + checkpoints + anchor file
// to dir and returns their paths plus the signer pubkey. n records, one
// checkpoint every `every`.
func writeAnchoredFixture(t *testing.T, dir string, n, every int) (logPath, cpPath, anchorPath, pub string) {
	t.Helper()
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	var audit, cps, anchors bytes.Buffer
	c := policy.NewCheckpointer(signer, &cps, every, func() string { return "T" }, policy.NewFileAnchor(&anchors, ""))
	a := policy.NewAuditLog(&audit, func() string { return "T" }).WithCheckpointer(c)
	for i := 0; i < n; i++ {
		if err := a.Append(policy.AuditRecord{Backend: "fs", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	a.Flush()
	logPath = filepath.Join(dir, "audit.jsonl")
	cpPath = filepath.Join(dir, "cps.jsonl")
	anchorPath = filepath.Join(dir, "anchors.jsonl")
	for p, b := range map[string][]byte{logPath: audit.Bytes(), cpPath: cps.Bytes(), anchorPath: anchors.Bytes()} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return logPath, cpPath, anchorPath, signer.PubKeyHex()
}

// TestAuditVerifyWithAnchors covers the CLI exit semantics: anchored (nil),
// partial (nil — warn only), and mismatch (non-zero EVEN though the rolled-back
// pair still verifies sealed internally).
func TestAuditVerifyWithAnchors(t *testing.T) {
	dir := t.TempDir()
	logPath, cpPath, anchorPath, pub := writeAnchoredFixture(t, dir, 8, 4)

	// Fully anchored, sealed: exit 0.
	if err := auditVerifySigned(logPath, cpPath, pub, anchorPath); err != nil {
		t.Fatalf("anchored+sealed must pass: %v", err)
	}

	// Witness lag: drop the last anchor record → partial, still exit 0.
	anchorBytes, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(anchorBytes), "\n"), "\n")
	laggedPath := filepath.Join(dir, "lagged.jsonl")
	if err := os.WriteFile(laggedPath, []byte(lines[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := auditVerifySigned(logPath, cpPath, pub, laggedPath); err != nil {
		t.Fatalf("anchor_partial must warn, not fail: %v", err)
	}

	// Insider rollback: truncate log to 4 records and checkpoints to cp1. The
	// pair verifies sealed internally — but the witness disagrees, and the
	// verify MUST exit non-zero.
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	recLines := strings.Split(strings.TrimRight(string(logBytes), "\n"), "\n")
	cpBytes, err := os.ReadFile(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	cpLines := strings.Split(strings.TrimRight(string(cpBytes), "\n"), "\n")
	rolledLog := filepath.Join(dir, "rolled-audit.jsonl")
	rolledCPs := filepath.Join(dir, "rolled-cps.jsonl")
	if err := os.WriteFile(rolledLog, []byte(strings.Join(recLines[:4], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rolledCPs, []byte(cpLines[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Sanity: without the witness the rollback is invisible (sealed, exit 0).
	if err := auditVerifySigned(rolledLog, rolledCPs, pub, ""); err != nil {
		t.Fatalf("rolled-back pair without a witness verifies sealed: %v", err)
	}
	// With the witness: caught.
	err = auditVerifySigned(rolledLog, rolledCPs, pub, anchorPath)
	if err == nil {
		t.Fatal("ANCHOR MISMATCH must exit non-zero even when the chain is sealed")
	}
	if !strings.Contains(err.Error(), "witness") {
		t.Fatalf("the error should name the witness disagreement: %v", err)
	}
}

// TestAuditAnchorReplay: `audit anchor` replays a checkpoints file to a
// control-plane witness idempotently — a witness that missed checkpoints is
// healed, and replaying again changes nothing.
func TestAuditAnchorReplay(t *testing.T) {
	dir := t.TempDir()
	_, cpPath, _, pub := writeAnchoredFixture(t, dir, 8, 4)

	witnessPath := filepath.Join(dir, "witness.jsonl")
	auth, err := control.NewStaticAuthorizer(map[string][]control.Role{"GW": {control.RoleAnchorSubmit}})
	if err != nil {
		t.Fatal(err)
	}
	wt, err := control.NewAnchorWitness(witnessPath, []string{pub})
	if err != nil {
		t.Fatal(err)
	}
	defer wt.Close()
	srv := &control.Server{
		Auth:     auth,
		Identify: func(string) (control.Identity, bool) { return control.Identity{PubKey: "GW", FQDN: "gw"}, true },
		Witness:  wt,
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Replay twice: the second run must be a no-op (dedup by signer/seq/hash).
	for i := 0; i < 2; i++ {
		if err := auditAnchor([]string{"--checkpoints", cpPath, "--url", ts.URL + "/v1/anchor"}); err != nil {
			t.Fatalf("replay %d failed: %v", i+1, err)
		}
	}
	f, err := os.Open(witnessPath)
	if err != nil {
		t.Fatal(err)
	}
	recs, _, err := policy.ReadAnchorRecords(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("witness must hold exactly 2 records after a double replay, got %d", len(recs))
	}

	// The witness file now verifies the original checkpoints as anchored.
	cpBySeq, err := loadCheckpointMap(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	wf, err := os.Open(witnessPath)
	if err != nil {
		t.Fatal(err)
	}
	defer wf.Close()
	ares, err := policy.VerifyAnchors(wf, cpBySeq)
	if err != nil {
		t.Fatal(err)
	}
	if ares.Status != policy.AnchorStatusAnchored || ares.Matched != 2 {
		t.Fatalf("replayed witness must verify anchored: %+v", ares)
	}
}

// TestAuditAnchorToLocalFile: `audit anchor --out` appends only the missing
// checkpoints to a local anchor file and refuses a conflicting one.
func TestAuditAnchorToLocalFile(t *testing.T) {
	dir := t.TempDir()
	_, cpPath, anchorPath, _ := writeAnchoredFixture(t, dir, 8, 4)

	// Start from a lagged copy holding only record 1.
	anchorBytes, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(anchorBytes), "\n"), "\n")
	outPath := filepath.Join(dir, "out.jsonl")
	if err := os.WriteFile(outPath, []byte(lines[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := auditAnchor([]string{"--checkpoints", cpPath, "--out", outPath}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(outPath)
	if err != nil {
		t.Fatal(err)
	}
	recs, _, err := policy.ReadAnchorRecords(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Seq != 1 || recs[1].Seq != 2 {
		t.Fatalf("gap must be healed exactly once: %+v", recs)
	}

	// A conflicting checkpoints file (different signer/content, same ordinals)
	// must be refused — a witness is never overwritten. (The existing records
	// are unattributed, so they belong to this file's own chain and DO
	// conflict; contrast with the attributed shared-file case below.)
	otherDir := t.TempDir()
	_, otherCPs, _, _ := writeAnchoredFixture(t, otherDir, 8, 4)
	if err := auditAnchor([]string{"--checkpoints", otherCPs, "--out", outPath}); err == nil {
		t.Fatal("conflicting replay into an existing witness file must fail")
	}
}

// TestAuditAnchorSharedWitnessFileSkipsOtherSigners: `audit anchor --out` into
// a shared witness file must not read another gateway's ATTRIBUTED record at
// the same ordinal as fork evidence (same skip rule as VerifyAnchors) — the
// gap heal proceeds and the other gateway's record stands untouched.
func TestAuditAnchorSharedWitnessFileSkipsOtherSigners(t *testing.T) {
	dirA := t.TempDir()
	_, cpPathA, _, _ := writeAnchoredFixture(t, dirA, 8, 4)
	dirB := t.TempDir()
	_, cpPathB, _, pubB := writeAnchoredFixture(t, dirB, 8, 4)

	// The shared file starts with gateway B's attributed record for ordinal 1
	// (as a control-plane witness would write it).
	cpB, err := loadCheckpointMap(cpPathB)
	if err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(dirA, "shared.jsonl")
	f, err := os.OpenFile(shared, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.NewFileAnchor(f, "").Witness(cpB[1], pubB); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Gateway A heals its outage gap into the shared file: must succeed even
	// though B's record occupies the same ordinal.
	if err := auditAnchor([]string{"--checkpoints", cpPathA, "--out", shared}); err != nil {
		t.Fatalf("shared-file replay must skip the other gateway's record: %v", err)
	}
	sf, err := os.Open(shared)
	if err != nil {
		t.Fatal(err)
	}
	recs, _, err := policy.ReadAnchorRecords(sf)
	sf.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || recs[0].Signer != pubB {
		t.Fatalf("expected B's record plus A's two, got %+v", recs)
	}

	// The healed shared file verifies gateway A's checkpoints as anchored.
	cpA, err := loadCheckpointMap(cpPathA)
	if err != nil {
		t.Fatal(err)
	}
	af, err := os.Open(shared)
	if err != nil {
		t.Fatal(err)
	}
	defer af.Close()
	ares, err := policy.VerifyAnchors(af, cpA)
	if err != nil {
		t.Fatal(err)
	}
	if ares.Status != policy.AnchorStatusAnchored || ares.Matched != 2 {
		t.Fatalf("healed shared file must verify anchored for gateway A: %+v", ares)
	}

	// Idempotent: a second heal appends nothing.
	if err := auditAnchor([]string{"--checkpoints", cpPathA, "--out", shared}); err != nil {
		t.Fatalf("second heal must be a no-op: %v", err)
	}
	sf2, err := os.Open(shared)
	if err != nil {
		t.Fatal(err)
	}
	recs2, _, err := policy.ReadAnchorRecords(sf2)
	sf2.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs2) != 3 {
		t.Fatalf("second heal must append nothing, got %d records", len(recs2))
	}
}

// TestAuditAnchorRefusesInFileForkEvidence: if the target anchor file already
// holds two conflicting records for one ordinal of THIS chain, the replay is
// refused loudly instead of quietly siding with either record.
func TestAuditAnchorRefusesInFileForkEvidence(t *testing.T) {
	dir := t.TempDir()
	_, cpPath, anchorPath, _ := writeAnchoredFixture(t, dir, 8, 4)

	// Append a second, conflicting record for ordinal 1 (legacy-style and
	// unattributed, so it reads as this file's own chain).
	fork := map[string]string{"checkpoint_seq": "1", "chain_head": "bb", "checkpoint": strings.Repeat("ab", 32), "time": "T"}
	b, err := json.Marshal(fork)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(anchorPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
	f.Close()

	err = auditAnchor([]string{"--checkpoints", cpPath, "--out", anchorPath})
	if err == nil || !strings.Contains(err.Error(), "conflicting records") {
		t.Fatalf("in-file fork evidence must refuse the replay: %v", err)
	}
}
