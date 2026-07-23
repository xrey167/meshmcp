package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// flakySink is a checkpoint sink whose writes can be forced to fail, so tests
// can exercise the retention path without touching the filesystem.
type flakySink struct {
	fail bool
	buf  bytes.Buffer
}

func (f *flakySink) Write(p []byte) (int, error) {
	if f.fail {
		return 0, errors.New("disk full")
	}
	return f.buf.Write(p)
}

// testLeafHex fabricates a distinct, valid record-hash hex for seq i.
func testLeafHex(i int) string {
	sum := sha256.Sum256([]byte{byte(i)})
	return hex.EncodeToString(sum[:])
}

func parseCheckpoints(t *testing.T, jsonl string) []Checkpoint {
	t.Helper()
	var out []Checkpoint
	for _, line := range strings.Split(strings.TrimRight(jsonl, "\n"), "\n") {
		if line == "" {
			continue
		}
		var cp Checkpoint
		if err := json.Unmarshal([]byte(line), &cp); err != nil {
			t.Fatalf("parse checkpoint: %v", err)
		}
		out = append(out, cp)
	}
	return out
}

// TestCheckpointerWriteFailureRetainsBatch pins the error-retention contract:
// a failed checkpoint write must NOT advance the checkpoint ordinal, drop the
// buffered leaves, or move fromSeq/prevCP — the next flush re-covers exactly
// the same records, so signed coverage stays contiguous. A variant that rolls
// state forward on failure would emit Seq 2 with FromSeq 3 here and leave
// records 1-2 uncovered forever.
func TestCheckpointerWriteFailureRetainsBatch(t *testing.T) {
	signer := mustSigner(t)
	sink := &flakySink{fail: true}
	var errs []error
	cp := NewCheckpointer(signer, sink, 2, func() string { return "T" }, nil).
		WithErrorHandler(func(err error) { errs = append(errs, err) })

	// Two adds reach the interval; the flush attempt fails.
	cp.Add(1, testLeafHex(1))
	cp.Add(2, testLeafHex(2))
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "checkpoint write") {
		t.Fatalf("expected one surfaced write error, got %v", errs)
	}
	if sink.buf.Len() != 0 {
		t.Fatal("nothing may land in the sink on a failed write")
	}

	// The sink heals; the third add re-triggers a flush covering ALL of 1..3.
	sink.fail = false
	cp.Add(3, testLeafHex(3))
	cps := parseCheckpoints(t, sink.buf.String())
	if len(cps) != 1 {
		t.Fatalf("expected exactly one checkpoint after recovery, got %d", len(cps))
	}
	got := cps[0]
	if got.Seq != 1 {
		t.Fatalf("failed flush must not consume an ordinal: Seq = %d, want 1", got.Seq)
	}
	if got.FromSeq != 1 || got.ToSeq != 3 || got.Count != 3 {
		t.Fatalf("retry must cover the retained batch plus the new record: [%d,%d] count %d", got.FromSeq, got.ToSeq, got.Count)
	}
	if got.PrevCP != "" {
		t.Fatalf("first durable checkpoint must have an empty PrevCP, got %q", got.PrevCP)
	}
	// The signed Merkle root covers all three retained leaves.
	var leaves [][]byte
	for i := 1; i <= 3; i++ {
		raw, _ := hex.DecodeString(testLeafHex(i))
		leaves = append(leaves, raw)
	}
	root := MerkleRoot(leaves)
	if got.MerkleRoot != hex.EncodeToString(root[:]) {
		t.Fatal("recovered checkpoint must commit to the retained leaves")
	}
	if err := VerifyCheckpoint(got, signer.PubKeyHex()); err != nil {
		t.Fatalf("recovered checkpoint must verify: %v", err)
	}

	// A subsequent checkpoint continues the chain: Seq 2, linked to the first.
	cp.Add(4, testLeafHex(4))
	cp.Add(5, testLeafHex(5))
	cps = parseCheckpoints(t, sink.buf.String())
	if len(cps) != 2 || cps[1].Seq != 2 || cps[1].PrevCP != cps[0].Hash() {
		t.Fatalf("post-recovery numbering/linkage wrong: %+v", cps)
	}
}

// shortSink accepts writes but reports fewer bytes than given, without error.
type shortSink struct{ calls int }

func (s *shortSink) Write(p []byte) (int, error) {
	s.calls++
	return len(p) - 1, nil
}

// TestCheckpointerShortWriteIsFailure: a short write with a nil error is a
// failed checkpoint, not a silent success — the error handler fires and the
// batch is retained (the ordinal stays unconsumed).
func TestCheckpointerShortWriteIsFailure(t *testing.T) {
	signer := mustSigner(t)
	var errs []error
	sink := &shortSink{}
	cp := NewCheckpointer(signer, sink, 1, func() string { return "T" }, nil).
		WithErrorHandler(func(err error) { errs = append(errs, err) })
	cp.Add(1, testLeafHex(1))
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "short write") {
		t.Fatalf("short write must surface as a checkpoint failure, got %v", errs)
	}
	// The retained batch retries on the next flush attempt (and fails again
	// here — proving the leaves were kept, since an empty buffer would no-op).
	cp.Flush(1, testLeafHex(1))
	if sink.calls != 2 {
		t.Fatalf("retained batch must retry the write, got %d write calls", sink.calls)
	}
}

// TestCheckpointerRetentionEndToEndSeals drives the retention path through the
// real audit pipeline: the first auto-flush fails, later records arrive, the
// sink heals, and the final coverage is still gapless — VerifySigned reports a
// fully sealed, trusted log rather than a hole where the failed batch was.
func TestCheckpointerRetentionEndToEndSeals(t *testing.T) {
	signer := mustSigner(t)
	sink := &flakySink{fail: true}
	var errs []error
	cp := NewCheckpointer(signer, sink, 4, func() string { return "T" }, nil).
		WithErrorHandler(func(err error) { errs = append(errs, err) })
	audit := &bytes.Buffer{}
	a := NewAuditLog(audit, func() string { return "T" }).WithCheckpointer(cp)

	rec := AuditRecord{Backend: "fs", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow"}
	for i := 0; i < 4; i++ { // the flush at record 4 fails
		if err := a.write(rec); err != nil {
			t.Fatal(err)
		}
	}
	if len(errs) == 0 {
		t.Fatal("the failed auto-flush must be surfaced")
	}
	sink.fail = false
	// Record 5 re-triggers the flush: the retained batch (1..4) plus record 5
	// land in one checkpoint; the rest are sealed by the final Flush.
	for i := 0; i < 4; i++ {
		if err := a.write(rec); err != nil {
			t.Fatal(err)
		}
	}
	a.Flush()
	res, err := VerifySigned(bytes.NewReader(audit.Bytes()), bytes.NewReader(sink.buf.Bytes()), signer.PubKeyHex())
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.Sealed || res.Status != StatusSealed {
		t.Fatalf("recovered log must verify sealed with no coverage gap: %+v", res)
	}
	if res.CoveredRecords != 8 {
		t.Fatalf("all 8 records must be covered, got %d", res.CoveredRecords)
	}
}

// failingAnchor always refuses to witness.
type failingAnchor struct{ calls int }

func (f *failingAnchor) Anchor(Checkpoint) error { f.calls++; return errors.New("witness down") }

// TestCheckpointerAnchorFailureDoesNotUncommit: the anchor is best-effort — a
// failed anchor is reported, but the durably written checkpoint stands and the
// chain keeps advancing (Seq increments, PrevCP links).
func TestCheckpointerAnchorFailureDoesNotUncommit(t *testing.T) {
	signer := mustSigner(t)
	sink := &flakySink{}
	anchor := &failingAnchor{}
	var errs []error
	cp := NewCheckpointer(signer, sink, 1, func() string { return "T" }, anchor).
		WithErrorHandler(func(err error) { errs = append(errs, err) })

	cp.Add(1, testLeafHex(1))
	cp.Add(2, testLeafHex(2))

	cps := parseCheckpoints(t, sink.buf.String())
	if len(cps) != 2 {
		t.Fatalf("anchor failure must not un-commit written checkpoints, got %d", len(cps))
	}
	if cps[0].Seq != 1 || cps[1].Seq != 2 || cps[1].PrevCP != cps[0].Hash() {
		t.Fatalf("chain must keep advancing past anchor failures: %+v", cps)
	}
	if anchor.calls != 2 || len(errs) != 2 || !strings.Contains(errs[0].Error(), "anchor") {
		t.Fatalf("every anchor failure must be surfaced: calls=%d errs=%v", anchor.calls, errs)
	}
}

// TestFileAnchorAppendsWitnessRecord: the anchor line commits to the
// checkpoint's own hash, chain head, ordinal, and time — enough for a witness
// to detect a later rollback — and self-links to the previous anchor line.
func TestFileAnchorAppendsWitnessRecord(t *testing.T) {
	signer := mustSigner(t)
	cp := signer.sign(Checkpoint{Version: 1, Seq: 3, FromSeq: 5, ToSeq: 8, Count: 4,
		MerkleRoot: "aa", ChainHead: "bb", PrevCP: "cc", Time: "T"})
	var buf bytes.Buffer
	fa := &FileAnchor{W: &buf}
	if err := fa.Anchor(cp); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	if !strings.HasSuffix(line, "\n") {
		t.Fatal("anchor record must be newline-terminated (append-only JSONL)")
	}
	var rec AnchorRecord
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("anchor record must be JSON: %v", err)
	}
	if rec.Checkpoint != cp.Hash() || rec.ChainHead != "bb" ||
		rec.Seq != 3 || rec.Time != "T" || rec.V != 1 {
		t.Fatalf("anchor record fields wrong: %+v", rec)
	}
	if rec.PrevAnchor != "" {
		t.Fatalf("first anchor record must have an empty prev_anchor, got %q", rec.PrevAnchor)
	}

	// A second record links to the first line's hash.
	cp2 := signer.sign(Checkpoint{Version: 1, Seq: 4, FromSeq: 9, ToSeq: 12, Count: 4,
		MerkleRoot: "dd", ChainHead: "ee", PrevCP: cp.Hash(), Time: "T"})
	if err := fa.Anchor(cp2); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	var rec2 AnchorRecord
	if err := json.Unmarshal([]byte(lines[1]), &rec2); err != nil {
		t.Fatal(err)
	}
	if rec2.PrevAnchor != AnchorLineHash([]byte(lines[0])) {
		t.Fatalf("second anchor record must link to the first line's hash: %+v", rec2)
	}
}

// TestFileAnchorLinkageAcrossRestart: seeding a fresh FileAnchor from the
// existing file's last-line hash (via ReadAnchorRecords) continues one
// self-linked witness chain across restarts.
func TestFileAnchorLinkageAcrossRestart(t *testing.T) {
	signer := mustSigner(t)
	var buf bytes.Buffer
	fa := NewFileAnchor(&buf, "")
	cp1 := signer.sign(Checkpoint{Version: 1, Seq: 1, FromSeq: 1, ToSeq: 2, Count: 2, MerkleRoot: "aa", ChainHead: "bb", Time: "T"})
	if err := fa.Anchor(cp1); err != nil {
		t.Fatal(err)
	}

	// "Restart": re-read the file, seed a new FileAnchor from the last line.
	recs, lastHash, err := ReadAnchorRecords(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Seq != 1 || recs[0].Checkpoint != cp1.Hash() {
		t.Fatalf("re-read records wrong: %+v", recs)
	}
	fa2 := NewFileAnchor(&buf, lastHash)
	cp2 := signer.sign(Checkpoint{Version: 1, Seq: 2, FromSeq: 3, ToSeq: 4, Count: 2, MerkleRoot: "cc", ChainHead: "dd", PrevCP: cp1.Hash(), Time: "T"})
	if err := fa2.Anchor(cp2); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 anchor lines, got %d", len(lines))
	}
	var rec2 AnchorRecord
	if err := json.Unmarshal([]byte(lines[1]), &rec2); err != nil {
		t.Fatal(err)
	}
	if rec2.PrevAnchor != AnchorLineHash([]byte(lines[0])) {
		t.Fatal("post-restart record must link to the pre-restart line")
	}
	// And the linkage verifies end to end.
	res, err := VerifyAnchors(bytes.NewReader(buf.Bytes()), map[int]Checkpoint{1: cp1, 2: cp2})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != AnchorStatusAnchored || res.Matched != 2 {
		t.Fatalf("restart-continued anchor chain must verify anchored: %+v", res)
	}
}

// TestCheckpointerBadHexAndEmptyFlush: a non-hex record hash is skipped (it
// cannot enter the Merkle batch), and a Flush with nothing buffered writes
// nothing.
func TestCheckpointerBadHexAndEmptyFlush(t *testing.T) {
	signer := mustSigner(t)
	sink := &flakySink{}
	cp := NewCheckpointer(signer, sink, 1, func() string { return "T" }, nil)

	cp.Flush(0, "")
	if sink.buf.Len() != 0 {
		t.Fatal("Flush with an empty buffer must write nothing")
	}
	cp.Add(1, "not-hex")
	if sink.buf.Len() != 0 {
		t.Fatal("a bad-hex leaf must not produce a checkpoint")
	}
	// A valid leaf still checkpoints normally afterwards.
	cp.Add(2, testLeafHex(2))
	cps := parseCheckpoints(t, sink.buf.String())
	if len(cps) != 1 || cps[0].Count != 1 || cps[0].Seq != 1 {
		t.Fatalf("valid leaf after a skipped one must checkpoint alone: %+v", cps)
	}
	// Nil checkpointer entry points are safe no-ops.
	var nilCP *Checkpointer
	nilCP.Add(1, testLeafHex(1))
	nilCP.Flush(1, testLeafHex(1))
}
