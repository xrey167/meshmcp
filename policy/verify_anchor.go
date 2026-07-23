package policy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// Anchor verification status values. They are ORTHOGONAL to the four chain
// states (invalid/untrusted_key/unsealed/sealed): anchoring only ever ADDS
// evidence about whether an external witness agrees with the checkpoints file —
// it never relaxes or remaps the chain-internal verdict.
const (
	// AnchorStatusAnchored: every checkpoint is witnessed and every witnessed
	// record matches the checkpoints file.
	AnchorStatusAnchored = "anchored"
	// AnchorStatusPartial: every witnessed record matches, but some checkpoints
	// are not (yet) witnessed — witness lag, honest but incomplete.
	AnchorStatusPartial = "anchor_partial"
	// AnchorStatusMismatch: the witness disagrees with the checkpoints file — a
	// witnessed checkpoint is absent (rollback), its hash/chain-head differs
	// (rewrite), two witness records for one seq conflict (fork), or the anchor
	// file's own self-linkage is broken (anchor tamper). This is the insider
	// case anchoring exists to catch: a log + checkpoints rolled back together
	// still verify "sealed" internally, but the witness remembers.
	AnchorStatusMismatch = "anchor_mismatch"
)

// AnchorVerifyResult reports how an external witness's anchor records compare
// with a checkpoints file.
type AnchorVerifyResult struct {
	AnchorRecords  int   `json:"anchor_records"`          // witness records considered
	Matched        int   `json:"matched"`                 // distinct checkpoints matched by a witness record
	MismatchSeqs   []int `json:"mismatch_seqs,omitempty"` // checkpoint ordinals the witness disagrees on
	UnanchoredTail int   `json:"unanchored_tail"`         // checkpoints newer than the last witnessed one
	// OtherSignerRecords counts witness records skipped because they are
	// attributed to a different signer key (a shared witness file holds several
	// gateways' records). When NOTHING matched but such records exist, the
	// partial reason surfaces them: they may be this gateway's history under a
	// previously pinned key — i.e. rewrite-under-a-new-signer evidence.
	OtherSignerRecords int    `json:"other_signer_records,omitempty"`
	Status             string `json:"status"` // "anchored" | "anchor_partial" | "anchor_mismatch"
	Reason             string `json:"reason,omitempty"`
}

// flexInt accepts a JSON number or a JSON string holding a number, so legacy
// anchor records (which encoded checkpoint_seq as a string) still parse.
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 1 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		*f = flexInt(n)
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexInt(n)
	return nil
}

// anchorLine is the lenient parse form of one anchor record: it accepts both
// the v1 self-linked format and the legacy format (no v/prev_anchor,
// checkpoint_seq as a string).
type anchorLine struct {
	V          int     `json:"v"`
	Seq        flexInt `json:"checkpoint_seq"`
	ChainHead  string  `json:"chain_head"`
	Checkpoint string  `json:"checkpoint"`
	Time       string  `json:"time"`
	Signer     string  `json:"signer"`
	PrevAnchor *string `json:"prev_anchor"`
}

// ReadAnchorRecords parses an anchor file leniently (v1 and legacy formats)
// and returns its records plus the AnchorLineHash of the last non-empty line
// ("" for an empty file) — the seed for continuing the self-linked witness
// chain across restarts. A line that parses as neither format is an error:
// appending to an unreadable witness file would hide whatever the bad line
// replaced.
func ReadAnchorRecords(r io.Reader) ([]AnchorRecord, string, error) {
	var out []AnchorRecord
	lastHash := ""
	n := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		n++
		var rec anchorLine
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, "", fmt.Errorf("anchor file line %d is not a valid anchor record: %w", n, err)
		}
		prev := ""
		if rec.PrevAnchor != nil {
			prev = *rec.PrevAnchor
		}
		out = append(out, AnchorRecord{
			V: rec.V, Seq: int(rec.Seq), ChainHead: rec.ChainHead,
			Checkpoint: rec.Checkpoint, Time: rec.Time, Signer: rec.Signer,
			PrevAnchor: prev,
		})
		lastHash = AnchorLineHash(line)
	}
	if err := sc.Err(); err != nil {
		return nil, "", err
	}
	return out, lastHash, nil
}

// VerifyAnchors compares an anchor file (JSONL witness records) against the
// checkpoints indexed by ordinal in cpBySeq and classifies the outcome:
//
//   - anchored: every checkpoint in cpBySeq is matched by a witness record and
//     no witness record disagrees.
//   - anchor_partial: every witness record that names one of these checkpoints
//     matches it, but some checkpoints are unwitnessed (witness lag, or an
//     empty anchor file).
//   - anchor_mismatch: a witness record names a checkpoint ordinal absent from
//     cpBySeq (the checkpoints file was rolled back past a witnessed head), or
//     its checkpoint hash / chain head disagrees (the file was rewritten —
//     even re-signed with the real key), or two witness records for the same
//     ordinal carry different hashes (fork evidence), or the anchor file's own
//     PrevAnchor self-linkage is broken (the anchor file was tampered with).
//
// Witness records whose Signer names a different key than the checkpoints'
// signer are skipped (a shared witness file can hold several gateways'
// records) but counted in OtherSignerRecords — and when no record at all
// matches this signer, the partial reason names them, because "the witness has
// never seen this gateway" and "the witness knew this gateway under a
// different key" (a full rewrite re-signed with a NEW key) must not read the
// same. Self-linkage is still enforced across every line, because it protects
// the file as a whole. Duplicate records for one ordinal with the same hash
// are idempotent re-anchors and fine.
//
// The four chain states are deliberately untouched: this function only ever
// ADDS evidence on top of VerifySigned's verdict.
func VerifyAnchors(anchorR io.Reader, cpBySeq map[int]Checkpoint) (AnchorVerifyResult, error) {
	var res AnchorVerifyResult

	// The checkpoints all share one signer (VerifySigned enforces it); witness
	// records naming another signer belong to a different gateway's chain.
	signer := ""
	for _, cp := range cpBySeq {
		signer = cp.PubKey
		break
	}

	mismatch := func(seq int, reason string) {
		res.MismatchSeqs = append(res.MismatchSeqs, seq)
		if res.Reason == "" {
			res.Reason = reason
		}
	}

	seen := map[int]string{} // anchored seq -> witnessed checkpoint hash
	maxAnchored := 0
	prevLineHash := ""
	first := true
	sc := bufio.NewScanner(anchorR)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec anchorLine
		if err := json.Unmarshal(line, &rec); err != nil {
			// An unparseable line in a witness file is not skippable: it could
			// hide an edited record.
			mismatch(0, "anchor file contains a line that is not a valid anchor record")
			break
		}
		// Self-linkage: a v1 record must link to the previous line's hash ("" on
		// the first line). Legacy records carry no linkage and are not checked,
		// but their bytes still feed the next record's expected hash.
		if rec.PrevAnchor != nil {
			want := ""
			if !first {
				want = prevLineHash
			}
			if *rec.PrevAnchor != want {
				mismatch(int(rec.Seq), fmt.Sprintf("anchor record for checkpoint %d does not link to the previous anchor line (anchor file tampered or truncated mid-chain)", int(rec.Seq)))
			}
		}
		prevLineHash = AnchorLineHash(line)
		first = false

		if rec.Signer != "" && signer != "" && rec.Signer != signer {
			res.OtherSignerRecords++ // another signer's record in a shared witness file
			continue
		}
		res.AnchorRecords++
		seq := int(rec.Seq)
		if prevHash, dup := seen[seq]; dup {
			if prevHash != rec.Checkpoint {
				mismatch(seq, fmt.Sprintf("two witness records for checkpoint %d carry different hashes (fork evidence)", seq))
			}
			continue
		}
		seen[seq] = rec.Checkpoint
		if seq > maxAnchored {
			maxAnchored = seq
		}
		cp, ok := cpBySeq[seq]
		if !ok {
			mismatch(seq, fmt.Sprintf("the witness recorded checkpoint %d but the checkpoints file does not contain it (the log and checkpoints were rolled back past a witnessed head)", seq))
			continue
		}
		if cp.Hash() != rec.Checkpoint {
			mismatch(seq, fmt.Sprintf("checkpoint %d disagrees with the external witness (the checkpoints file was rewritten after anchoring)", seq))
			continue
		}
		if rec.ChainHead != "" && rec.ChainHead != cp.ChainHead {
			mismatch(seq, fmt.Sprintf("checkpoint %d chain head disagrees with the external witness", seq))
			continue
		}
		res.Matched++
	}
	if err := sc.Err(); err != nil {
		return res, err
	}

	for seq := range cpBySeq {
		if seq > maxAnchored {
			res.UnanchoredTail++
		}
	}

	switch {
	case len(res.MismatchSeqs) > 0:
		res.Status = AnchorStatusMismatch
	case res.Matched == len(cpBySeq) && len(cpBySeq) > 0:
		res.Status = AnchorStatusAnchored
		res.Reason = ""
	default:
		res.Status = AnchorStatusPartial
		if res.Reason == "" {
			res.Reason = fmt.Sprintf("%d of %d checkpoint(s) are not yet witnessed", len(cpBySeq)-res.Matched, len(cpBySeq))
			if res.Matched == 0 && res.OtherSignerRecords > 0 {
				// Nothing here is witnessed, but the witness is not empty: it
				// holds records attributed to other signer key(s). If this
				// gateway previously anchored under a different key, that is
				// rewrite-under-a-new-signer evidence, not mere witness lag.
				res.Reason += fmt.Sprintf("; the witness holds %d record(s) attributed to other signer key(s) — if this gateway previously anchored under a different key, the log and checkpoints may have been rewritten under a new signer (compare the witness records' signer with the previously pinned key)", res.OtherSignerRecords)
			}
		}
	}
	return res, nil
}
