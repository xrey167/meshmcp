package know

import "github.com/xrey167/meshmcp/policy"

// KnowOp is the knowledge operation being authorized: which corpus/subgraph it
// touches and whether it writes. The backend constructs one PER CALL from the
// live request and the caller's presented capability — never from a static,
// per-session env snapshot (e.g. MESHMCP_CORPORA), which is exactly the
// bypass window the shared-spine design closes.
type KnowOp struct {
	// Corpus is the corpus / KG subgraph label being accessed. Required: a blank
	// target is never authorized (see Allowed).
	Corpus string
	// Write is true for mutating ops (know.assert / know.supersede / know.extract)
	// and false for reads (know.retrieve). Writes are authorized strictly more
	// narrowly than reads — see Allowed.
	Write bool
}

// Allowed reports whether claims authorize op, DENY-BY-DEFAULT. It is the single
// per-call scoping gate the KG and RAG backends call after policy.Verify, using
// the caller's own capability claims.
//
// Semantics (deliberately stricter than CapabilityClaims.AllowsCorpus alone):
//
//   - An unnamed corpus (op.Corpus == "") is always denied. Knowledge ops must
//     target a concrete corpus/subgraph; a blank target must never fall through
//     to allow-all.
//   - An EMPTY grant (claims.Corpora == nil) is denied. AllowsCorpus treats an
//     empty list as allow-all — that is the LOCAL-capability convention — but
//     for knowledge ops we mirror federation.Boundary.CheckCorpus instead: no
//     grant shares nothing. This override is load-bearing; without it the
//     deny-by-default guarantee is marketing.
//   - A READ is allowed when any granted glob covers the corpus
//     (claims.AllowsCorpus, once we know the grant is non-empty).
//   - A WRITE is allowed only by an EXACT, literal corpus grant equal to the
//     target. A broad read grant (a "*" or a glob) must not silently confer
//     write/poisoning power over a shared subgraph, so a caller can be given
//     wide read visibility yet may only assert into corpora it was named into
//     explicitly. This directly bounds the "confidence laundering" /
//     shared-subgraph poisoning threat.
//
// Allowed never trusts client-supplied fields other than the op's own
// corpus/write intent, which the backend derives from the request it is about
// to execute; authorization rests entirely on the signed, verified claims.
func Allowed(claims policy.CapabilityClaims, op KnowOp) bool {
	if op.Corpus == "" {
		return false
	}
	if len(claims.Corpora) == 0 {
		return false
	}
	if !op.Write {
		return claims.AllowsCorpus(op.Corpus)
	}
	return grantsExactWrite(claims.Corpora, op.Corpus)
}

// grantsExactWrite reports whether corpus is covered by an exact literal grant
// (no glob, no "*"). This is what makes a write strictly narrower than a read.
func grantsExactWrite(grants []string, corpus string) bool {
	for _, g := range grants {
		if g == corpus {
			return true
		}
	}
	return false
}
