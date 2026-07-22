package know

import "github.com/xrey167/meshmcp/policy"

// Backend is the audit Backend name every knowledge-op record carries, so the
// whole Air Knowledge System's activity is filterable as one source on the
// shared ledger.
const Backend = "air-know"

// Verb is a canonical knowledge-op method name. Ingest (assert/supersede/
// extract), recall (retrieve), and agent-graph control-flow (node-enter/
// checkpoint/cosign) all draw from this ONE vocabulary, so every governed step
// lands on a single verifiable chain with a consistent method — rather than two
// conflated ledgers. A Verb is written into policy.AuditRecord.Method.
type Verb string

// The canonical knowledge-op verbs (S4).
const (
	VerbAssert     Verb = "know.assert"      // write a new fact
	VerbSupersede  Verb = "know.supersede"   // invalidate-and-replace a fact (bi-temporal)
	VerbRetrieve   Verb = "know.retrieve"    // recall facts/chunks (RAG/KG read)
	VerbExtract    Verb = "know.extract"     // derive triples from a document/interaction
	VerbNodeEnter  Verb = "graph.node-enter" // an agent-graph node begins executing
	VerbCheckpoint Verb = "graph.checkpoint" // persist agent-graph / session state
	VerbCosign     Verb = "graph.cosign"     // human co-sign of a parked sensitive egress
)

// Event carries the attributes a knowledge-op audit record shares. A constructor
// turns one into a policy.AuditRecord whose Method is the canonical verb. The
// tamper-evidence chain fields (Seq, PrevHash, Hash) are NOT set here — they are
// filled by policy.AuditLog when the record is appended, so a record from any
// constructor slots straight into the existing hash chain and passes
// policy.VerifyChain.
type Event struct {
	Peer     string // asserting / acting WireGuard identity
	PeerKey  string // that identity's public key (optional)
	Corpus   string // corpus / subgraph / node the op touched; lands in Tool
	Decision string // "allow" | "deny" | "cosign"; empty defaults to "allow"
	Reason   string
	// Provenance carries stable content refs — KnowHash values (see KnowTriple.
	// KnowHash), never chain hashes — that produced or were produced by the op:
	// the retrieved triples behind a recall, or the asserted triple behind a
	// write. This is the signed provenance receipt for a verifiable answer.
	Provenance []string
	Cost       int // cost/quota units this call consumed (budget accounting)
}

// record is the shared shape for every verb constructor. It is pure: it returns
// a new record and mutates nothing.
func record(v Verb, e Event) policy.AuditRecord {
	decision := e.Decision
	if decision == "" {
		decision = "allow"
	}
	return policy.AuditRecord{
		Backend:    Backend,
		Peer:       e.Peer,
		PeerKey:    e.PeerKey,
		Method:     string(v),
		Tool:       e.Corpus,
		Decision:   decision,
		Reason:     e.Reason,
		Provenance: e.Provenance,
		Cost:       e.Cost,
	}
}

// Assert builds a know.assert record (a new fact written).
func Assert(e Event) policy.AuditRecord { return record(VerbAssert, e) }

// Supersede builds a know.supersede record (a fact invalidated and replaced).
func Supersede(e Event) policy.AuditRecord { return record(VerbSupersede, e) }

// Retrieve builds a know.retrieve record (facts/chunks recalled). Its
// Provenance should carry the KnowHashes of the returned triples — the
// verifiable-answer receipt.
func Retrieve(e Event) policy.AuditRecord { return record(VerbRetrieve, e) }

// Extract builds a know.extract record (triples derived from a document or
// interaction).
func Extract(e Event) policy.AuditRecord { return record(VerbExtract, e) }

// NodeEnter builds a graph.node-enter record (an agent-graph node begins).
func NodeEnter(e Event) policy.AuditRecord { return record(VerbNodeEnter, e) }

// Checkpoint builds a graph.checkpoint record (agent-graph/session state persisted).
func Checkpoint(e Event) policy.AuditRecord { return record(VerbCheckpoint, e) }

// Cosign builds a graph.cosign record (human co-sign of a parked sensitive egress).
func Cosign(e Event) policy.AuditRecord { return record(VerbCosign, e) }
