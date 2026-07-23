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
		if rec.SchemaVersion > auditSchemaVersion {
			res.BreakSeq = expectSeq
			res.Reason = fmt.Sprintf("record %d has schema version %d, newer than this build supports (%d) — upgrade meshmcp", expectSeq, rec.SchemaVersion, auditSchemaVersion)
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

// VerifyForRepair verifies the chain in data and, when the ONLY defect is an
// incomplete trailing record (a torn write left by a crash or power loss),
// reports the byte offset to truncate the file to so the remaining chain is
// fully intact, along with the last good (seq, hash) via res.Count/res.LastHash.
//
// It is deliberately conservative to preserve tamper-evidence: a tear is only
// recoverable when the LAST non-blank line fails to parse as JSON (a partially
// written final record) and every record before it verifies. A complete record
// whose seq, prev_hash, or hash is wrong — an edit, reorder, deletion, or
// insertion — is NEVER repairable and surfaces as a hard failure (torn=false,
// res.OK=false), the same as corruption anywhere before the final line. Because
// only the single trailing line is ever dropped and it is by construction the
// newest record, truncation can never remove a checkpoint-covered record.
func VerifyForRepair(data []byte) (res VerifyResult, truncateTo int64, torn bool) {
	return VerifyForRepairFrom(data, 0, "")
}

// VerifyForRepairFrom is VerifyForRepair for a rotated chain SEGMENT: data's
// first record is expected to carry seq seedSeq+1 and prev_hash seedHash — the
// sealed head of the previous segment (see RotatingFileSink). res.Count is the
// number of records in DATA (the caller adds seedSeq for the absolute
// sequence); res.LastHash is seedHash when data holds no records. Seeds
// (0, "") verify an unrotated log from genesis.
func VerifyForRepairFrom(data []byte, seedSeq int, seedHash string) (res VerifyResult, truncateTo int64, torn bool) {
	prev := seedHash
	expectSeq := seedSeq
	var offset int64
	n := int64(len(data))
	for offset < n {
		recStart := offset
		nl := bytes.IndexByte(data[offset:], '\n')
		var lineEnd int64
		hasNL := nl >= 0
		if hasNL {
			lineEnd = offset + int64(nl)
			offset = lineEnd + 1
		} else {
			lineEnd = n
			offset = n
		}
		line := bytes.TrimSpace(data[recStart:lineEnd])
		if len(line) == 0 {
			truncateTo = offset // keep blank lines in the good prefix
			continue
		}
		expectSeq++
		var rec AuditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			// A parse failure on the FINAL non-blank line is a torn trailing
			// write: recoverable by dropping it. Anywhere earlier it is
			// mid-chain corruption and must fail hard.
			if !hasMoreContent(data, offset) {
				res.BreakSeq = expectSeq
				res.Reason = fmt.Sprintf("incomplete trailing record %d: %v", expectSeq, err)
				return res, recStart, true
			}
			res.BreakSeq = expectSeq
			res.Reason = fmt.Sprintf("record %d is not valid JSON: %v", expectSeq, err)
			return res, 0, false
		}
		// A record from a newer format is complete and well-formed — never a torn
		// tail. Refuse it hard rather than truncating a valid future record.
		if rec.SchemaVersion > auditSchemaVersion {
			res.BreakSeq = rec.Seq
			res.Reason = fmt.Sprintf("record %d has schema version %d, newer than this build supports (%d) — upgrade meshmcp", expectSeq, rec.SchemaVersion, auditSchemaVersion)
			return res, 0, false
		}
		if rec.Seq != expectSeq {
			res.BreakSeq = rec.Seq
			res.Reason = fmt.Sprintf("record #%d has seq %d (expected %d): a record was inserted or removed", res.Count+1, rec.Seq, expectSeq)
			return res, 0, false
		}
		if rec.PrevHash != prev {
			res.BreakSeq = rec.Seq
			res.Reason = fmt.Sprintf("record seq %d prev_hash %q does not link to prior hash %q", rec.Seq, short(rec.PrevHash), short(prev))
			return res, 0, false
		}
		want, _, err := chainHash(rec)
		if err != nil {
			res.BreakSeq = rec.Seq
			res.Reason = fmt.Sprintf("record seq %d could not be re-hashed: %v", rec.Seq, err)
			return res, 0, false
		}
		if rec.Hash != want {
			res.BreakSeq = rec.Seq
			res.Reason = fmt.Sprintf("record seq %d was edited: stored hash %q != recomputed %q", rec.Seq, short(rec.Hash), short(want))
			return res, 0, false
		}
		prev = rec.Hash
		res.Count++
		res.LastHash = prev
		truncateTo = offset
	}
	res.OK = true
	res.LastHash = prev
	return res, truncateTo, false
}

// hasMoreContent reports whether any non-blank line remains in data from offset.
func hasMoreContent(data []byte, offset int64) bool {
	return len(bytes.TrimSpace(data[offset:])) > 0
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
