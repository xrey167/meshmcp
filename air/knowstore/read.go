package knowstore

import (
	"fmt"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/air/know"
	"github.com/xrey167/meshmcp/kg"
)

// denyRead audits and wraps the deny for a refused read of corpus. Caller holds
// f.mu.
func (f *Facade) denyRead(caller Caller, corpus string) error {
	_ = f.appendAudit(know.Retrieve(know.Event{
		Peer:     caller.Peer,
		PeerKey:  caller.PeerKey,
		Corpus:   corpus,
		Decision: "deny",
		Reason:   "capability does not grant read of corpus",
	}))
	return fmt.Errorf("%w: read corpus %q", ErrDenied, corpus)
}

// Query governs, runs, and audits a pattern read (empty fields are wildcards;
// asOf replays the graph at a past sequence). Deny-by-default twice over: the
// CALL needs a granted glob covering corpus over a non-empty grant, and the
// RESULT is filtered to records whose own corpus label is visible under that
// corpus (record-level subgraph scoping — two corpora sharing one store are
// mutually invisible). A denied read never touches the store and audits a
// know.retrieve deny record; a successful read audits a know.retrieve record
// whose provenance is the stable KnowHash of every RETURNED triple — the
// verifiable-answer receipt covers exactly what left the process.
func (f *Facade) Query(caller Caller, corpus, s, p, o string, asOf int) ([]kg.Record, error) {
	op := know.KnowOp{Corpus: corpus, Write: false}

	f.mu.Lock()
	defer f.mu.Unlock()

	if !know.Allowed(caller.Claims, op) {
		return nil, f.denyRead(caller, corpus)
	}

	recs := filterVisible(f.store.Query(s, p, o, asOf), corpus)
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
// deny-by-default read gate, record-level corpus filter, and know.retrieve
// provenance receipt as Query.
func (f *Facade) Neighbors(caller Caller, corpus, node string, asOf int) ([]kg.Record, error) {
	op := know.KnowOp{Corpus: corpus, Write: false}

	f.mu.Lock()
	defer f.mu.Unlock()

	if !know.Allowed(caller.Claims, op) {
		return nil, f.denyRead(caller, corpus)
	}

	recs := filterVisible(f.store.Neighbors(node, asOf), corpus)
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

// Canonical governs, resolves, and audits an alias/sameAs canonicalization: the
// name is followed through the corpus-visible alias index (built lazily and
// cached against the store head, so lookups are not O(active-set)). Same
// deny-by-default read gate as Query; an unknown name resolves to itself.
func (f *Facade) Canonical(caller Caller, corpus, name string) (string, error) {
	op := know.KnowOp{Corpus: corpus, Write: false}

	f.mu.Lock()
	defer f.mu.Unlock()

	if !know.Allowed(caller.Claims, op) {
		return "", f.denyRead(caller, corpus)
	}

	resolved := air.Canonical(f.aliasIndexLocked(corpus), name)
	if err := f.appendAudit(know.Retrieve(know.Event{
		Peer:     caller.Peer,
		PeerKey:  caller.PeerKey,
		Corpus:   corpus,
		Decision: "allow",
		Reason:   "canonicalize " + name,
	})); err != nil {
		return resolved, fmt.Errorf("knowstore: audit retrieve: %w", err)
	}
	return resolved, nil
}

// Delta governs, assembles, and audits the sync delta for corpus above the
// since watermark — the sender side of `air kg sync`. The filter is applied ON
// THE SENDER: an out-of-corpus record is absent from the wire payload, not
// hidden client-side. Two record kinds ride a delta:
//
//   - assert records visible in corpus (record-level scope, as in Query);
//   - delete records whose TARGET fact belongs to corpus — a tombstone carries
//     no corpus label of its own, so it is resolved through the fact it
//     tombstones; this is what lets a deletion survive a sync round-trip
//     without ever leaking a foreign corpus's tombstone traffic.
//
// Deny-by-default read gate as Query; the know.retrieve receipt carries the
// KnowHash of every shipped assert record.
func (f *Facade) Delta(caller Caller, corpus string, since int) ([]kg.Record, error) {
	op := know.KnowOp{Corpus: corpus, Write: false}

	f.mu.Lock()
	defer f.mu.Unlock()

	if !know.Allowed(caller.Claims, op) {
		return nil, f.denyRead(caller, corpus)
	}

	all := f.store.DeltaSince(0)
	corpusOf := make(map[string]string, len(all))
	for _, r := range all {
		if r.Op == "assert" {
			c := r.Corpus
			if c == "" {
				c = r.Peer // legacy default subgraph = asserting peer
			}
			corpusOf[r.ID] = c
		}
	}

	var out []kg.Record
	var asserts []kg.Record
	for _, r := range all {
		if r.Seq <= since {
			continue
		}
		switch r.Op {
		case "assert":
			if visible(r, corpus) {
				out = append(out, r)
				asserts = append(asserts, r)
			}
		case "delete":
			if corpusOf[r.ID] == corpus {
				out = append(out, r)
			}
		}
	}

	if err := f.appendAudit(know.Retrieve(know.Event{
		Peer:       caller.Peer,
		PeerKey:    caller.PeerKey,
		Corpus:     corpus,
		Decision:   "allow",
		Reason:     fmt.Sprintf("delta since %d", since),
		Provenance: knowHashes(asserts),
	})); err != nil {
		return out, fmt.Errorf("knowstore: audit retrieve: %w", err)
	}
	return out, nil
}
