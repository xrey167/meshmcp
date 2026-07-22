package knowstore

import (
	"fmt"

	"github.com/xrey167/meshmcp/air/know"
	"github.com/xrey167/meshmcp/kg"
)

// Query governs, runs, and audits a pattern read (empty fields are wildcards;
// asOf replays the graph at a past sequence). Deny-by-default: a read needs any
// granted glob to cover corpus over a non-empty grant. A denied read never
// touches the store and audits a know.retrieve deny record; a successful read
// audits a know.retrieve record whose provenance is the stable KnowHash of every
// returned triple — the verifiable-answer receipt.
func (f *Facade) Query(caller Caller, corpus, s, p, o string, asOf int) ([]kg.Record, error) {
	op := know.KnowOp{Corpus: corpus, Write: false}

	f.mu.Lock()
	defer f.mu.Unlock()

	if !know.Allowed(caller.Claims, op) {
		_ = f.appendAudit(know.Retrieve(know.Event{
			Peer:     caller.Peer,
			PeerKey:  caller.PeerKey,
			Corpus:   corpus,
			Decision: "deny",
			Reason:   "capability does not grant read of corpus",
		}))
		return nil, fmt.Errorf("%w: read corpus %q", ErrDenied, corpus)
	}

	recs := f.store.Query(s, p, o, asOf)
	if err := f.appendAudit(know.Retrieve(know.Event{
		Peer:       caller.Peer,
		PeerKey:    caller.PeerKey,
		Corpus:     corpus,
		Decision:   "allow",
		Provenance: knowHashes(recs),
	})); err != nil {
		return recs, fmt.Errorf("knowstore: audit retrieve: %w", err)
	}
	return recs, nil
}

// Neighbors governs, runs, and audits an entity-centric read: active triples in
// which node is the subject or object (the k-hop seed for GraphRAG). Same
// deny-by-default read gate and know.retrieve provenance receipt as Query.
func (f *Facade) Neighbors(caller Caller, corpus, node string, asOf int) ([]kg.Record, error) {
	op := know.KnowOp{Corpus: corpus, Write: false}

	f.mu.Lock()
	defer f.mu.Unlock()

	if !know.Allowed(caller.Claims, op) {
		_ = f.appendAudit(know.Retrieve(know.Event{
			Peer:     caller.Peer,
			PeerKey:  caller.PeerKey,
			Corpus:   corpus,
			Decision: "deny",
			Reason:   "capability does not grant read of corpus",
		}))
		return nil, fmt.Errorf("%w: read corpus %q", ErrDenied, corpus)
	}

	recs := f.store.Neighbors(node, asOf)
	if err := f.appendAudit(know.Retrieve(know.Event{
		Peer:       caller.Peer,
		PeerKey:    caller.PeerKey,
		Corpus:     corpus,
		Decision:   "allow",
		Provenance: knowHashes(recs),
	})); err != nil {
		return recs, fmt.Errorf("knowstore: audit retrieve: %w", err)
	}
	return recs, nil
}
