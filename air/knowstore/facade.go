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
// It is a library: no mesh/net. It imports only kg, air/know, and policy, and
// takes the caller's capability claims + peer identity as parameters — the
// caller (e.g. a future air-kg verb) supplies them from the verified request.
package knowstore

import (
	"errors"
	"sync"

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
// receipt for a recall. It addresses each fact by content (S/P/O/Peer), never
// by chain position, so the provenance stays valid across replicas.
func knowHashes(recs []kg.Record) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		t := know.KnowTriple{S: r.S, P: r.P, O: r.O, Peer: r.Peer}
		out = append(out, t.KnowHash())
	}
	return out
}
