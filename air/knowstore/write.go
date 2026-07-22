package knowstore

import (
	"fmt"

	"github.com/xrey167/meshmcp/air/know"
)

// AssertRequest is a single fact to write, plus the corpus that governs the
// write and the optional provenance the stable receipt binds. Corpus is the
// authorization dimension (an exact-literal grant is required to write it);
// Source and ValidFrom are hashed into the KnowReceipt but not the base store
// record, which stays S/P/O/Peer only (extended record fields are a later
// air-kg phase).
type AssertRequest struct {
	Corpus    string // corpus/subgraph the write targets — governs authorization
	S         string
	P         string
	O         string
	Source    string // optional: doc/URI the fact was extracted from (into the receipt)
	ValidFrom string // optional: bi-temporal valid-from (into the receipt)
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

	if _, err := f.store.Assert(req.S, req.P, req.O, caller.Peer); err != nil {
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
