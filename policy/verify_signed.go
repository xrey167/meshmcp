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
	OK             bool   `json:"ok"`
	Reason         string `json:"reason,omitempty"`
	SignerPub      string `json:"signer_pubkey,omitempty"`
}

// VerifySigned proves an audit log is complete and unedited using its signed
// checkpoints — the externally verifiable guarantee. It recomputes each
// record's hash from the record's own content (so any edit shows up), then for
// every checkpoint checks: the Ed25519 signature (optionally pinned to
// expectPub), the link to the previous checkpoint, that the Merkle root
// recomputed over the covered records' hashes matches the SIGNED root, and
// that the chain head matches. Because the root is signed, even an insider who
// rewrites the entire file and re-hashes the plain chain cannot make it verify
// without the private key.
func VerifySigned(auditR, checkpointR io.Reader, expectPub string) (SignedVerifyResult, error) {
	var res SignedVerifyResult

	// 1) Read records, recomputing each one's hash from its content.
	hashBySeq := map[int][]byte{}
	sc := bufio.NewScanner(auditR)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec AuditRecord
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
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
			res.Reason = "checkpoint is not valid JSON"
			return res, nil
		}
		res.Checkpoints++
		if res.SignerPub == "" {
			res.SignerPub = cp.PubKey
		}

		if err := VerifyCheckpoint(cp, expectPub); err != nil {
			res.Reason = err.Error()
			return res, nil
		}
		if cp.PrevCP != prevCP {
			res.Reason = fmt.Sprintf("checkpoint %d does not link to the previous checkpoint (chain of checkpoints broken — one may have been dropped)", cp.Seq)
			return res, nil
		}
		if cp.FromSeq != prevTo+1 {
			res.Reason = fmt.Sprintf("checkpoint %d starts at seq %d but the previous ended at %d (a gap in coverage)", cp.Seq, cp.FromSeq, prevTo)
			return res, nil
		}

		// Recompute the Merkle root over the covered records' hashes.
		var leaves [][]byte
		for s := cp.FromSeq; s <= cp.ToSeq; s++ {
			h, ok := hashBySeq[s]
			if !ok {
				res.Reason = fmt.Sprintf("checkpoint %d covers record seq %d, which is missing from the log", cp.Seq, s)
				return res, nil
			}
			leaves = append(leaves, h)
		}
		root := MerkleRoot(leaves)
		if hex.EncodeToString(root[:]) != cp.MerkleRoot {
			res.Reason = fmt.Sprintf("checkpoint %d Merkle root mismatch: the records it covers were edited (signed root %s, recomputed %s)", cp.Seq, short(cp.MerkleRoot), short(hex.EncodeToString(root[:])))
			return res, nil
		}
		if head, ok := hashBySeq[cp.ToSeq]; ok && hex.EncodeToString(head) != cp.ChainHead {
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
		res.Reason = "no checkpoints found"
		return res, nil
	}
	res.OK = true
	return res, nil
}
