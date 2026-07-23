// Witness receiver for external audit anchoring: peer gateways POST their
// signed audit checkpoints to /v1/anchor, and this control plane — an
// independent host — records each verified checkpoint in its own append-only,
// self-linked anchor file. Once a checkpoint head is witnessed here, an
// insider on the peer who rolls the audit log and its checkpoints back
// together (even holding the signing key) is caught by
// `meshmcp audit verify --anchors` against this witness's file.
//
// Trust model: the witness verifies (1) the caller via the governed control
// plane (transport-derived identity + default-deny RBAC — the anchor.submit
// role), and (2) the checkpoint's Ed25519 signature against a PINNED allowlist
// of signer public keys. The pin plus append-only dedup by (signer, ordinal,
// hash) is the replay/rollback defense; PrevCP inside the checkpoint hash
// prevents fork-splicing. The witness never removes or replaces a record, so a
// later conflicting checkpoint for an already-witnessed ordinal is rejected
// (409) — that conflict IS the fork evidence.
package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/xrey167/meshmcp/policy"
)

// maxAnchorBody caps a witness POST body. A checkpoint is ~600 bytes; 64 KiB
// is generous headroom without letting a peer exhaust memory.
const maxAnchorBody = 64 * 1024

// AnchorWitness accepts verified checkpoints from pinned peer signers and
// appends them to an append-only, self-linked anchor file.
type AnchorWitness struct {
	mu      sync.Mutex
	out     *os.File
	file    *policy.FileAnchor
	allowed map[string]bool           // pinned signer pubkeys (hex Ed25519)
	seen    map[string]map[int]string // signer -> checkpoint ordinal -> witnessed hash
}

// Close releases the witness anchor file.
func (wt *AnchorWitness) Close() error {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	return wt.out.Close()
}

// NewAnchorWitness opens (or creates) the witness anchor file at path, seeds
// the per-signer dedup state and self-linkage from its existing records, and
// pins allowSigners as the only accepted checkpoint signers. An empty
// allowSigners is a configuration error: a witness that accepts any signer
// witnesses nothing of value (fail closed, matching the control plane's
// default-deny posture).
func NewAnchorWitness(path string, allowSigners []string) (*AnchorWitness, error) {
	if len(allowSigners) == 0 {
		return nil, fmt.Errorf("anchor witness: no allowed signers pinned (an unpinned witness would witness anything; refusing)")
	}
	allowed := map[string]bool{}
	for _, s := range allowSigners {
		if s == "" {
			return nil, fmt.Errorf("anchor witness: empty signer key in allowlist")
		}
		allowed[s] = true
	}

	seen := map[string]map[int]string{}
	lastHash := ""
	if f, err := os.Open(path); err == nil {
		recs, lh, rerr := policy.ReadAnchorRecords(f)
		f.Close()
		if rerr != nil {
			return nil, fmt.Errorf("anchor witness %s: %w", path, rerr)
		}
		lastHash = lh
		for _, r := range recs {
			if r.Signer == "" {
				continue
			}
			if seen[r.Signer] == nil {
				seen[r.Signer] = map[int]string{}
			}
			seen[r.Signer][r.Seq] = r.Checkpoint
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("anchor witness %s: %w", path, err)
	}

	out, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("anchor witness %s: %w", path, err)
	}
	return &AnchorWitness{
		out:     out,
		file:    policy.NewFileAnchor(out, lastHash),
		allowed: allowed,
		seen:    seen,
	}, nil
}

// Accept verifies and records one checkpoint, returning the HTTP status that
// describes the outcome:
//
//	200 — witnessed (or already witnessed with the identical hash: idempotent)
//	403 — the signer key is not pinned
//	400 — malformed or the signature does not verify
//	409 — this ordinal was already witnessed with a DIFFERENT hash (fork or
//	      rollback evidence; the original record stands)
//	500 — the witness file could not be appended
func (wt *AnchorWitness) Accept(cp policy.Checkpoint) (int, error) {
	if !wt.allowed[cp.PubKey] {
		return http.StatusForbidden, fmt.Errorf("checkpoint signer is not a pinned witness client")
	}
	if cp.Seq <= 0 {
		return http.StatusBadRequest, fmt.Errorf("checkpoint_seq must be positive")
	}
	if err := policy.VerifyCheckpoint(cp, cp.PubKey); err != nil {
		return http.StatusBadRequest, err
	}

	wt.mu.Lock()
	defer wt.mu.Unlock()
	h := cp.Hash()
	if prev, dup := wt.seen[cp.PubKey][cp.Seq]; dup {
		if prev == h {
			return http.StatusOK, nil // idempotent re-anchor / replay
		}
		return http.StatusConflict, fmt.Errorf("checkpoint %d conflicts with the already-witnessed checkpoint for this signer (fork or rollback evidence; the witnessed record stands)", cp.Seq)
	}
	if err := wt.file.Witness(cp, cp.PubKey); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("witness append failed: %v", err)
	}
	if wt.seen[cp.PubKey] == nil {
		wt.seen[cp.PubKey] = map[int]string{}
	}
	wt.seen[cp.PubKey][cp.Seq] = h
	return http.StatusOK, nil
}

// handleAnchor is the witness route: POST /v1/anchor with a full checkpoint
// JSON body. Authorization first (governed channel: transport identity +
// anchor.submit role), then signature verification against the pinned signer
// allowlist, then append-only dedup.
func (s *Server) handleAnchor(w http.ResponseWriter, r *http.Request) {
	if s.Witness == nil {
		http.Error(w, "anchor witness not configured", http.StatusNotImplemented)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.authorize(w, r, RoleAnchorSubmit, "anchor.submit", ""); !ok {
		return
	}
	var cp policy.Checkpoint
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAnchorBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cp); err != nil {
		http.Error(w, "invalid checkpoint: "+err.Error(), http.StatusBadRequest)
		return
	}
	code, err := s.Witness.Accept(cp)
	if err != nil {
		http.Error(w, err.Error(), code)
		return
	}
	writeJSON(w, code, map[string]any{"status": "witnessed", "checkpoint_seq": cp.Seq})
}
