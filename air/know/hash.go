// Package know is the pure-logic core of the Air Knowledge System's shared
// spine (Phase 0). It has zero mesh/network dependencies — only the standard
// library and github.com/xrey167/meshmcp/policy — so all three knowledge
// pillars (KG, RAG, Agent Graph) can compose on one set of unit-tested
// primitives:
//
//   - S2 (hash.go)  the stable content-hash receipt: a content address for a
//     knowledge triple that is independent of audit-chain position.
//   - S3 (scope.go) the per-call corpus/subgraph scoping helper: deny-by-default
//     authorization built on policy.CapabilityClaims.
//   - S4 (audit.go) the knowledge-ops audit vocabulary: canonical verbs and
//     constructors that build correctly-shaped policy.AuditRecords, so ingest,
//     recall, and loop control-flow land on one verifiable chain.
package know

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// knowHashDomain is a domain-separation tag folded (length-prefixed, like every
// other field) into the KnowHash preimage. It ensures a KnowHash preimage can
// never be confused with the preimage of some other sha256 use elsewhere in the
// mesh, even if an attacker controls every triple field.
const knowHashDomain = "meshmcp/air/know/knowhash/v1"

// knowHashPrefix marks a value as a stable knowledge content hash, mirroring the
// repo's "e_"/"cap_" identifier conventions.
const knowHashPrefix = "kh_"

// KnowTriple is the content that a stable knowledge receipt addresses:
// the subject/predicate/object of the fact, the WireGuard identity that
// asserted it (Peer), the document/URI it was extracted from (Source), and the
// valid-time it took effect (ValidFrom). These are exactly the fields hashed by
// KnowHash — S2's H(S,P,O,Peer,Source,ValidFrom).
//
// It deliberately excludes anything chain-positional (Seq, PrevHash, the chain
// Hash): CRDT re-append gives a triple a fresh chain hash on every replica, so
// provenance must reference this stable content address instead.
type KnowTriple struct {
	S         string `json:"s"`
	P         string `json:"p"`
	O         string `json:"o"`
	Peer      string `json:"peer"`
	Source    string `json:"source,omitempty"`
	ValidFrom string `json:"valid_from,omitempty"`
}

// KnowHash returns the stable content address of the triple:
// "kh_" + hex(sha256(canonical(S,P,O,Peer,Source,ValidFrom))).
//
// The hash is deterministic (same fields → same hash, on every replica and
// across re-encoding) and collision-resistant ACROSS field boundaries: the
// canonical preimage length-prefixes every field, so bytes can never migrate
// from one field into an adjacent one to forge a collision. A naive
// S+"|"+P+"|"+O join is unsafe whenever any field can contain the delimiter —
// this encoding is unambiguous regardless of field contents.
//
// Because the preimage is a pure function of the six content fields and nothing
// chain-positional, the hash is independent of where (or how many times) the
// triple sits in any audit chain — the whole point of S2.
func (t KnowTriple) KnowHash() string {
	sum := sha256.Sum256(t.canonical())
	return knowHashPrefix + hex.EncodeToString(sum[:])
}

// canonical builds the unambiguous, length-prefixed preimage. The field order
// is fixed and part of the on-the-wire contract: reordering fields would change
// the hash, so it must never be changed without a version bump in the domain
// tag. Each field is written as an 8-byte big-endian length followed by its raw
// bytes, guaranteeing that distinct field tuples always yield distinct byte
// streams.
func (t KnowTriple) canonical() []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte(knowHashDomain))
	writeField(&buf, []byte(t.S))
	writeField(&buf, []byte(t.P))
	writeField(&buf, []byte(t.O))
	writeField(&buf, []byte(t.Peer))
	writeField(&buf, []byte(t.Source))
	writeField(&buf, []byte(t.ValidFrom))
	return buf.Bytes()
}

// writeField appends a length-prefixed field to buf. The 8-byte big-endian
// length prefix is what makes the framing injection-proof: because the reader
// (conceptually) knows exactly how many bytes each field spans, no combination
// of field contents can be reinterpreted as a different field split.
func writeField(buf *bytes.Buffer, b []byte) {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}

// KnowReceipt binds a triple to its stable content hash — the non-repudiation
// primitive the whole mesh references instead of the chain Hash. A provenance
// record (see audit.go) carries KnowHash values, not chain hashes, so a receipt
// stays valid across replicas even as each replica re-chains the triple.
type KnowReceipt struct {
	KnowHash string     `json:"know_hash"`
	Triple   KnowTriple `json:"triple"`
}

// NewReceipt computes the stable hash of t and returns a receipt binding the two.
func NewReceipt(t KnowTriple) KnowReceipt {
	return KnowReceipt{KnowHash: t.KnowHash(), Triple: t}
}

// Verify recomputes the hash from the receipt's triple content and reports
// whether it matches the stored KnowHash. Because the recomputation depends
// only on content, a receipt verifies identically on any replica regardless of
// chain position — exactly the cross-replica stability S2 exists to provide.
func (r KnowReceipt) Verify() bool {
	return r.KnowHash != "" && r.KnowHash == r.Triple.KnowHash()
}
