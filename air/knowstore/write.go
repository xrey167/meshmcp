package knowstore

import (
	"fmt"

	"github.com/xrey167/meshmcp/air/know"
)

// AssertRequest is a single fact to write, plus the corpus that governs the
// write and the optional provenance the stable receipt binds. Corpus is both
// the authorization dimension (an exact-literal grant is required to write it)
// and the record's subgraph label: Corpus, Source, and ValidFrom are persisted
// on the store record itself, so the KnowReceipt returned by Assert is
// recomputable from what a later read returns — assert and retrieve provenance
// reference the same stable hash.
type AssertRequest struct {
	Corpus    string // corpus/subgraph the write targets — governs authorization AND scopes the record
	S         string
	P         string
	O         string
	Source    string // optional: doc/URI the fact was extracted from (persisted + hashed)
	ValidFrom string // optional: bi-temporal valid-from (persisted + hashed)
}

// Assert governs, writes, and audits a new triple as the single writer. The
// whole gate → store → audit sequence runs under the facade mutex, so 32
// concurrent Asserts serialize into 32 well-formed, chained appends — never an
// interleaved or corrupted chain.
//
// Deny-by-default: a write needs an EXACT-literal grant for req.Corpus (a broad
// read glob confers no write power). A denied write never touches the store —
// the triple is not written — and appends a know.assert deny record. A
// successful write returns a KnowReceipt whose stable KnowHash is what the audit
// record carries as provenance (never the chain hash).
func (f *Facade) Assert(caller Caller, req AssertRequest) (know.KnowReceipt, error) {
	op := know.KnowOp{Corpus: req.Corpus, Write: true}

	f.mu.Lock()
	defer f.mu.Unlock()

	if !know.Allowed(caller.Claims, op) {
		_ = f.appendAudit(know.Assert(know.Event{
			Peer:     caller.Peer,
			PeerKey:  caller.PeerKey,
			Corpus:   req.Corpus,
			Decision: "deny",
			Reason:   "capability does not grant exact-literal write to corpus",
		}))
		return know.KnowReceipt{}, fmt.Errorf("%w: write to corpus %q", ErrDenied, req.Corpus)
	}

	if _, err := f.store.AssertProv(req.S, req.P, req.O, caller.Peer, req.Corpus, req.Source, req.ValidFrom); err != nil {
		return know.KnowReceipt{}, fmt.Errorf("knowstore: assert: %w", err)
	}

	receipt := know.NewReceipt(know.KnowTriple{
		S:         req.S,
		P:         req.P,
		O:         req.O,
		Peer:      caller.Peer,
		Source:    req.Source,
		ValidFrom: req.ValidFrom,
	})

	if err := f.appendAudit(know.Assert(know.Event{
		Peer:       caller.Peer,
		PeerKey:    caller.PeerKey,
		Corpus:     req.Corpus,
		Decision:   "allow",
		Provenance: []string{receipt.KnowHash},
	})); err != nil {
		return receipt, fmt.Errorf("knowstore: audit assert: %w", err)
	}
	return receipt, nil
}

// Delete tombstones a triple by id, governed as a write (know.supersede — a
// delete is a bi-temporal invalidation, not an erasure; nothing leaves history).
// Deny-by-default with the same exact-literal write grant as Assert; a denied
// delete never touches the store and audits a deny record.
func (f *Facade) Delete(caller Caller, corpus, id string) error {
	op := know.KnowOp{Corpus: corpus, Write: true}

	f.mu.Lock()
	defer f.mu.Unlock()

	if !know.Allowed(caller.Claims, op) {
		_ = f.appendAudit(know.Supersede(know.Event{
			Peer:     caller.Peer,
			PeerKey:  caller.PeerKey,
			Corpus:   corpus,
			Decision: "deny",
			Reason:   "capability does not grant exact-literal write to corpus",
		}))
		return fmt.Errorf("%w: delete in corpus %q", ErrDenied, corpus)
	}

	if _, err := f.store.Delete(id, caller.Peer); err != nil {
		return fmt.Errorf("knowstore: delete: %w", err)
	}

	if err := f.appendAudit(know.Supersede(know.Event{
		Peer:     caller.Peer,
		PeerKey:  caller.PeerKey,
		Corpus:   corpus,
		Decision: "allow",
		Reason:   "tombstoned " + id,
	})); err != nil {
		return fmt.Errorf("knowstore: audit supersede: %w", err)
	}
	return nil
}

// Supersede replaces the active fact oldID with a new one, bi-temporally:
// assert-new + tombstone-old under ONE facade-mutex hold, so no reader can
// interleave between the two and no concurrent writer can split them. History
// is preserved — the old fact stays replayable at any as-of before the
// supersession (invalidate, never erase).
//
// Governance is deny-by-default three ways:
//   - the caller needs the same EXACT-literal write grant as Assert;
//   - oldID must name an ACTIVE fact VISIBLE in req.Corpus — a write grant on
//     corpus A can never tombstone corpus B's fact, and a probe for a foreign
//     or nonexistent id gets one indistinguishable refusal (no existence leak);
//   - a denied supersede leaves the store untouched and audits a deny.
//
// Crash semantics (documented, deliberate): the new fact is asserted BEFORE the
// old is tombstoned, so a crash between the two leaves BOTH active — a visible
// duplicate and no data loss — rather than a silently missing fact. One
// know.supersede allow record carries both refs: the new fact's stable
// KnowHash and "tombstoned:<oldID>".
func (f *Facade) Supersede(caller Caller, oldID string, req AssertRequest) (know.KnowReceipt, error) {
	op := know.KnowOp{Corpus: req.Corpus, Write: true}

	f.mu.Lock()
	defer f.mu.Unlock()

	if !know.Allowed(caller.Claims, op) {
		_ = f.appendAudit(know.Supersede(know.Event{
			Peer:     caller.Peer,
			PeerKey:  caller.PeerKey,
			Corpus:   req.Corpus,
			Decision: "deny",
			Reason:   "capability does not grant exact-literal write to corpus",
		}))
		return know.KnowReceipt{}, fmt.Errorf("%w: supersede in corpus %q", ErrDenied, req.Corpus)
	}

	// The old fact must be active and visible in this corpus. Missing and
	// foreign-corpus ids fail identically so a writer cannot probe for facts
	// outside its subgraph.
	if !f.activeVisibleLocked(oldID, req.Corpus) {
		_ = f.appendAudit(know.Supersede(know.Event{
			Peer:     caller.Peer,
			PeerKey:  caller.PeerKey,
			Corpus:   req.Corpus,
			Decision: "deny",
			Reason:   "no active fact " + oldID + " visible in corpus",
		}))
		return know.KnowReceipt{}, fmt.Errorf("%w: no active fact %q visible in corpus %q", ErrDenied, oldID, req.Corpus)
	}

	if _, err := f.store.AssertProv(req.S, req.P, req.O, caller.Peer, req.Corpus, req.Source, req.ValidFrom); err != nil {
		return know.KnowReceipt{}, fmt.Errorf("knowstore: supersede assert: %w", err)
	}
	if _, err := f.store.Delete(oldID, caller.Peer); err != nil {
		// New fact stands, old not yet tombstoned: both active (visible
		// duplicate, no loss). Surface the fault so the caller can retry the
		// tombstone.
		return know.KnowReceipt{}, fmt.Errorf("knowstore: supersede tombstone %s: %w", oldID, err)
	}

	receipt := know.NewReceipt(know.KnowTriple{
		S:         req.S,
		P:         req.P,
		O:         req.O,
		Peer:      caller.Peer,
		Source:    req.Source,
		ValidFrom: req.ValidFrom,
	})
	if err := f.appendAudit(know.Supersede(know.Event{
		Peer:       caller.Peer,
		PeerKey:    caller.PeerKey,
		Corpus:     req.Corpus,
		Decision:   "allow",
		Provenance: []string{receipt.KnowHash, "tombstoned:" + oldID},
	})); err != nil {
		return receipt, fmt.Errorf("knowstore: audit supersede: %w", err)
	}
	return receipt, nil
}

// activeVisibleLocked reports whether an ACTIVE record with the given id exists
// AND is visible in corpus. Caller holds f.mu.
func (f *Facade) activeVisibleLocked(id, corpus string) bool {
	for _, r := range f.store.Active(0) {
		if r.ID == id {
			return visible(r, corpus)
		}
	}
	return false
}
