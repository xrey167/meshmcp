package policy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// VerifyResult reports whether an audit log's hash chain is intact.
type VerifyResult struct {
	Count    int    // records read
	OK       bool   // chain intact end to end
	BreakSeq int    // seq of the first bad record (0 if OK)
	Reason   string // why it broke (empty if OK)
	LastHash string // hash of the last record (chain head)
}

// VerifyChain walks a newline-delimited audit log and proves the hash chain
// is unbroken: each record's Hash must equal the recomputed sha256 of its own
// bytes, its PrevHash must equal the prior record's Hash, and Seq must be
// contiguous from 1. Any edit, reorder, deletion, or insertion anywhere in
// the file surfaces here as the first offending Seq — you do not need the
// original to detect that it was changed.
func VerifyChain(r io.Reader) (VerifyResult, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var res VerifyResult
	prev := ""
	expectSeq := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		res.Count++
		expectSeq++

		var rec AuditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			res.BreakSeq = expectSeq
			res.Reason = fmt.Sprintf("record %d is not valid JSON: %v", expectSeq, err)
			return res, nil
		}
		if rec.Seq != expectSeq {
			res.BreakSeq = rec.Seq
			res.Reason = fmt.Sprintf("record #%d has seq %d (expected %d): a record was inserted or removed", res.Count, rec.Seq, expectSeq)
			return res, nil
		}
		if rec.PrevHash != prev {
			res.BreakSeq = rec.Seq
			res.Reason = fmt.Sprintf("record seq %d prev_hash %q does not link to prior hash %q", rec.Seq, short(rec.PrevHash), short(prev))
			return res, nil
		}
		got := rec.Hash
		want, _, err := chainHash(rec)
		if err != nil {
			res.BreakSeq = rec.Seq
			res.Reason = fmt.Sprintf("record seq %d could not be re-hashed: %v", rec.Seq, err)
			return res, nil
		}
		if got != want {
			res.BreakSeq = rec.Seq
			res.Reason = fmt.Sprintf("record seq %d was edited: stored hash %q != recomputed %q", rec.Seq, short(got), short(want))
			return res, nil
		}
		prev = got
	}
	if err := sc.Err(); err != nil {
		return res, err
	}
	res.OK = true
	res.LastHash = prev
	return res, nil
}

// LastLink reads to the end of an audit log and returns the final record's
// Seq and Hash, so a new AuditLog can continue the same chain across a
// restart via SeedFrom. It does not verify the chain (use VerifyChain for
// that); it only needs the tail.
func LastLink(r io.Reader) (seq int, hash string, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec AuditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return seq, hash, fmt.Errorf("audit tail: bad record: %w", err)
		}
		seq, hash = rec.Seq, rec.Hash
	}
	return seq, hash, sc.Err()
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
