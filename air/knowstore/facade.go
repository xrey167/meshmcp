// Package knowstore is the single-writer knowledge-store facade — spine
// primitive S1 of the Air Knowledge System. It owns exactly ONE kg.Store and is
// the SOLE writer to it, which is the whole point: today N session subprocesses
// each fork and append to one kg.jsonl, racing on the hash chain and corrupting
// it. Keeping one Store behind one serialized writer makes that race
// structurally impossible to reproduce in-process.
//
// Every governed op is gated, provenance-stamped, and audited before it can
// touch the store:
//
//   - Governance (S3). Every write AND read passes air/know.Allowed(claims, op)
//     FIRST — deny-by-default; a write needs an exact-literal corpus grant, a
//     read needs any covering glob over a non-empty grant. Unauthorized ops are
//     rejected before the store is touched, and audit a deny record.
//   - Provenance (S2). A successful Assert returns an air/know.KnowReceipt whose
//     stable KnowHash addresses the fact independent of chain position; the
//     facade records provenance by KnowHash, never by the chain hash (which CRDT
//     re-append changes on every replica).
//   - Audit (S4). Every governed op appends an air/know audit record
//     (know.assert / know.supersede / know.retrieve) to the real hash chain via
//     a policy.AuditSink, so ingest and recall land on one verifiable ledger.
//
// It is a library: no mesh/net. It imports only kg, air (pure logic), air/know,
// and policy, and takes the caller's capability claims + peer identity as
// parameters — the caller (e.g. the air-kg verb) supplies them from the
// verified request.
package knowstore

import (
	"errors"
	"sync"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/air/know"
	"github.com/xrey167/meshmcp/kg"
	"github.com/xrey167/meshmcp/policy"
)

// ErrDenied is returned (wrapped) when a caller's capability does not authorize
// an op. It is a sentinel so callers and tests can errors.Is against it, and it
// carries no store detail — a denied op never learns anything about the store.
var ErrDenied = errors.New("knowstore: operation denied by capability scope")

// Caller is the verified identity behind a request: the capability claims the
// transport proved and the asserting WireGuard peer identity to stamp as
// provenance. The facade never derives authorization from anything else — no
// tool arguments, no per-session env snapshot — so scoping cannot be bypassed
// by a stale or forged ambient value.
type Caller struct {
	Claims  policy.CapabilityClaims // signed, verified capability of the caller
	Peer    string                  // asserting WireGuard identity (stamped on triples + audit)
	PeerKey string                  // that identity's public key (optional, for audit)
}

// Facade is the single-writer knowledge store. Its mutex is the serialization
// point: every governed op acquires it for the whole gate → store → audit
// critical section, so concurrent callers can never interleave appends to the
// store or its audit chain, nor corrupt the hash chain. This is a deliberate
// correctness-over-throughput choice — S1's job is to make the N-writer race
// structurally impossible, not to maximize read parallelism.
//
// A Facade must be created with New and must not be copied (it holds a mutex).
type Facade struct {
	mu    sync.Mutex
	store *kg.Store
	audit policy.AuditSink

	// alias caches the per-corpus alias/sameAs index (air.BuildAliasIndex) with
	// a store-head watermark, so Canonical is not O(active-set) per lookup: the
	// fold runs only when the store has advanced since the cache was built.
	// Guarded by mu like every other facade state.
	alias map[string]aliasCache
}

// aliasCache is one corpus's folded alias index plus the store head it was
// built at; a moved head invalidates it lazily.
type aliasCache struct {
	idx     map[string]string
	builtAt int
}

// New builds a facade that owns store as its single writer and appends every
// governed op to audit. audit may be nil (audit becomes a no-op), but a real
// policy.AuditLog is expected in production so ops land on the shared,
// verifiable chain. store must be non-nil and must not be shared with any other
// writer — that sole-ownership is what the single-writer guarantee rests on.
func New(store *kg.Store, audit policy.AuditSink) *Facade {
	return &Facade{store: store, audit: audit}
}

// Verify proves the store's hash chain is intact (no fact edited, reordered, or
// truncated). It is an ungoverned integrity check: the store serializes it
// against writes internally, so it observes a consistent snapshot.
func (f *Facade) Verify() error { return f.store.Verify() }

// Head returns the store's current sequence number (the time-travel cursor).
func (f *Facade) Head() int { return f.store.Head() }

// appendAudit writes rec to the audit chain, treating a nil sink as a no-op.
// Audit is a control: callers propagate the returned error rather than dropping
// it silently.
func (f *Facade) appendAudit(rec policy.AuditRecord) error {
	if f.audit == nil {
		return nil
	}
	return f.audit.Append(rec)
}

// knowHashes returns the stable KnowHash of each record — the verifiable-answer
// receipt for a recall. It addresses each fact by content — the full S2 tuple
// (S,P,O,Peer,Source,ValidFrom), now persisted on the record — never by chain
// position, so a retrieve receipt equals the assert receipt of the same fact
// and stays valid across replicas.
func knowHashes(recs []kg.Record) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		t := know.KnowTriple{S: r.S, P: r.P, O: r.O, Peer: r.Peer, Source: r.Source, ValidFrom: r.ValidFrom}
		out = append(out, t.KnowHash())
	}
	return out
}

// visible reports whether one record belongs to the named corpus — the
// record-level subgraph scope (spec: "a triple with no visible subgraph never
// leaves the process"). A record labeled with a corpus is visible only under
// that exact corpus; a LEGACY corpus-less record is private to its asserting
// peer's default subgraph (corpus == the record's own Peer id), so old data
// never becomes visible to a foreign corpus by default. Deny-by-default: a
// blank query corpus matches nothing.
func visible(r kg.Record, corpus string) bool {
	if corpus == "" {
		return false
	}
	if r.Corpus != "" {
		return r.Corpus == corpus
	}
	return r.Peer == corpus
}

// filterVisible keeps only the records visible in corpus. It runs BEFORE audit
// provenance is computed, so a retrieve receipt covers exactly what leaves the
// process — an invisible record contributes neither content nor hash.
func filterVisible(recs []kg.Record, corpus string) []kg.Record {
	out := make([]kg.Record, 0, len(recs))
	for _, r := range recs {
		if visible(r, corpus) {
			out = append(out, r)
		}
	}
	return out
}

// aliasIndexLocked returns the corpus's alias index, rebuilding it from the
// caller-visible active set only when the store head has moved since the last
// build. Caller holds f.mu.
func (f *Facade) aliasIndexLocked(corpus string) map[string]string {
	head := f.store.Head()
	if c, ok := f.alias[corpus]; ok && c.builtAt == head {
		return c.idx
	}
	recs := filterVisible(f.store.Active(0), corpus)
	triples := make([]air.KGTriple, 0, len(recs))
	for _, r := range recs {
		triples = append(triples, air.KGTriple{S: r.S, P: r.P, O: r.O, Peer: r.Peer})
	}
	idx := air.BuildAliasIndex(triples)
	if f.alias == nil {
		f.alias = map[string]aliasCache{}
	}
	f.alias[corpus] = aliasCache{idx: idx, builtAt: head}
	return idx
}
