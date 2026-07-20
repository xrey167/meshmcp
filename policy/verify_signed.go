package policy

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// SignedVerifyResult reports the outcome of verifying an audit log against its
// signed checkpoints.
type SignedVerifyResult struct {
	Records        int    `json:"records"`
	Checkpoints    int    `json:"checkpoints"`
	CoveredRecords int    `json:"covered_records"` // records committed to by a verified checkpoint
	OK             bool   `json:"ok"`              // the checkpoint chain is structurally and cryptographically valid
	Sealed         bool   `json:"sealed"`          // the last checkpoint covers the final record (no unsealed tail)
	Trusted        bool   `json:"trusted"`         // every checkpoint was signed by the pinned expected key
	Status         string `json:"status"`          // "invalid" | "untrusted_key" | "unsealed" | "sealed"
	Reason         string `json:"reason,omitempty"`
	SignerPub      string `json:"signer_pubkey,omitempty"`
}

// Verification status values, distinguishing the four outcomes a signed audit
// verification can have. Only StatusSealed is safe to describe as a complete,
// trusted, gateway-signed tamper-evident decision log.
const (
	StatusInvalid      = "invalid"       // the chain does not verify
	StatusUntrustedKey = "untrusted_key" // cryptographically valid but no expected key was pinned
	StatusUnsealed     = "unsealed"      // valid & trusted chain, but records after the last checkpoint are unsealed
	StatusSealed       = "sealed"        // valid, trusted, and every record is covered by a checkpoint
)

// VerifySigned checks an audit log against its signed checkpoints and reports
// one of four honest outcomes via Status: invalid, untrusted_key (valid but no
// expected key pinned), unsealed (valid and trusted but a tail of records is
// not yet covered by a checkpoint), or sealed (valid, trusted, and every record
// covered). It recomputes each record's hash from its own content (so any edit
// shows up), rejects duplicate/non-monotonic record sequence numbers and mixed
// signers, then for every checkpoint checks: the Ed25519 signature (pinned to
// expectPub when given), the link to the previous checkpoint, a Count that
// matches the covered span, the Merkle root recomputed over the covered
// records' hashes against the SIGNED root, and the chain head.
//
// This establishes a gateway-signed, tamper-evident decision log: a caller that
// controls the file cannot edit a covered record without the signing key. It
// does NOT prove every real-world action was observed, and — until an external
// witness anchors a checkpoint — cannot by itself defend against an insider who
// holds the key and rolls both the log and the checkpoints back together. Only
// Status == "sealed" (with expectPub pinned) is safe to describe as complete
// and trusted.
func VerifySigned(auditR, checkpointR io.Reader, expectPub string) (SignedVerifyResult, error) {
	var res SignedVerifyResult

	// 1) Read records, recomputing each one's hash from its content. The log is
	// a single-writer append-only chain, so sequence numbers must be strictly
	// increasing with no duplicates; a duplicate or out-of-order seq is a
	// malformed or tampered log and must be rejected, not silently collapsed.
	hashBySeq := map[int][]byte{}
	sc := bufio.NewScanner(auditR)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	lastSeq := 0
	maxSeq := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec AuditRecord
		if json.Unmarshal(line, &rec) != nil {
			// A line that does not parse as a record is not skippable in a
			// tamper-evident log: it could hide an edited record.
			res.Status = StatusInvalid
			res.Reason = "audit log contains a line that is not a valid record"
			return res, nil
		}
		if rec.Seq <= lastSeq {
			res.Status = StatusInvalid
			res.Reason = fmt.Sprintf("record sequence number %d is duplicate or non-monotonic (previous was %d)", rec.Seq, lastSeq)
			return res, nil
		}
		lastSeq = rec.Seq
		maxSeq = rec.Seq
		res.Records++
		hHex, _, err := chainHash(rec)
		if err != nil {
			return res, err
		}
		raw, _ := hex.DecodeString(hHex)
		hashBySeq[rec.Seq] = raw
	}
	if err := sc.Err(); err != nil {
		return res, err
	}

	// 2) Walk checkpoints in order.
	csc := bufio.NewScanner(checkpointR)
	csc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	prevCP := ""
	prevTo := 0
	for csc.Scan() {
		line := bytes.TrimSpace(csc.Bytes())
		if len(line) == 0 {
			continue
		}
		var cp Checkpoint
		if err := json.Unmarshal(line, &cp); err != nil {
			res.Status = StatusInvalid
			res.Reason = "checkpoint is not valid JSON"
			return res, nil
		}
		res.Checkpoints++
		if res.SignerPub == "" {
			res.SignerPub = cp.PubKey
		} else if cp.PubKey != res.SignerPub {
			// Every checkpoint in one log must be signed by the same key. When a
			// key is pinned VerifyCheckpoint already enforces it; this catches
			// the unpinned case, where an attacker could append checkpoints
			// signed with their own key over a rolled-back log.
			res.Status = StatusInvalid
			res.Reason = fmt.Sprintf("checkpoint %d is signed by a different key than earlier checkpoints (mixed signers)", cp.Seq)
			return res, nil
		}

		if err := VerifyCheckpoint(cp, expectPub); err != nil {
			res.Reason = err.Error()
			res.Status = StatusInvalid
			return res, nil
		}
		if cp.PrevCP != prevCP {
			res.Status = StatusInvalid
			res.Reason = fmt.Sprintf("checkpoint %d does not link to the previous checkpoint (chain of checkpoints broken — one may have been dropped)", cp.Seq)
			return res, nil
		}
		if cp.FromSeq != prevTo+1 {
			res.Status = StatusInvalid
			res.Reason = fmt.Sprintf("checkpoint %d starts at seq %d but the previous ended at %d (a gap in coverage)", cp.Seq, cp.FromSeq, prevTo)
			return res, nil
		}
		if cp.ToSeq < cp.FromSeq {
			res.Status = StatusInvalid
			res.Reason = fmt.Sprintf("checkpoint %d has an inverted range [%d,%d]", cp.Seq, cp.FromSeq, cp.ToSeq)
			return res, nil
		}
		// The signed Count must equal the covered span; otherwise a forged Count
		// could inflate CoveredRecords and fake a sealed result.
		if span := cp.ToSeq - cp.FromSeq + 1; cp.Count != span {
			res.Status = StatusInvalid
			res.Reason = fmt.Sprintf("checkpoint %d count %d does not match its covered span %d", cp.Seq, cp.Count, span)
			return res, nil
		}

		// Recompute the Merkle root over the covered records' hashes.
		var leaves [][]byte
		for s := cp.FromSeq; s <= cp.ToSeq; s++ {
			h, ok := hashBySeq[s]
			if !ok {
				res.Status = StatusInvalid
				res.Reason = fmt.Sprintf("checkpoint %d covers record seq %d, which is missing from the log", cp.Seq, s)
				return res, nil
			}
			leaves = append(leaves, h)
		}
		root := MerkleRoot(leaves)
		if hex.EncodeToString(root[:]) != cp.MerkleRoot {
			res.Status = StatusInvalid
			res.Reason = fmt.Sprintf("checkpoint %d Merkle root mismatch: the records it covers were edited (signed root %s, recomputed %s)", cp.Seq, short(cp.MerkleRoot), short(hex.EncodeToString(root[:])))
			return res, nil
		}
		if head, ok := hashBySeq[cp.ToSeq]; ok && hex.EncodeToString(head) != cp.ChainHead {
			res.Status = StatusInvalid
			res.Reason = fmt.Sprintf("checkpoint %d chain head mismatch at seq %d", cp.Seq, cp.ToSeq)
			return res, nil
		}

		res.CoveredRecords += cp.Count
		prevCP = cp.Hash()
		prevTo = cp.ToSeq
	}
	if err := csc.Err(); err != nil {
		return res, err
	}
	if res.Checkpoints == 0 {
		res.Status = StatusInvalid
		res.Reason = "no checkpoints found"
		return res, nil
	}

	// The checkpoint chain is structurally and cryptographically valid.
	res.OK = true

	// Sealed: the last checkpoint covers the final record, and coverage is a
	// gapless span from the first record. (Contiguity from seq 1 is already
	// enforced above: the first FromSeq must be 1 and each subsequent FromSeq
	// must be prevTo+1, so CoveredRecords == prevTo.)
	res.Sealed = res.Records > 0 && prevTo == maxSeq && res.CoveredRecords == res.Records

	// Trusted: a result is only trustworthy if the verifier pinned the expected
	// signing key. Without a pin the chain is internally valid but the signer is
	// unverified — an attacker who rewrites the log and re-signs with their own
	// key would still "verify". VerifyCheckpoint enforced the pin on every
	// checkpoint, so reaching here with expectPub set means all matched it.
	res.Trusted = expectPub != ""

	switch {
	case !res.Trusted:
		res.Status = StatusUntrustedKey
		res.Reason = "chain is valid but no expected public key was pinned; signer is unverified"
	case !res.Sealed:
		res.Status = StatusUnsealed
		res.Reason = fmt.Sprintf("valid and trusted, but %d record(s) after the last checkpoint are unsealed", res.Records-res.CoveredRecords)
	default:
		res.Status = StatusSealed
	}
	return res, nil
}
