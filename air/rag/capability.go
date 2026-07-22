package rag

import "errors"

// Capability is a named feature the retrieval backend may or may not be able to
// serve. v1 ships governed hybrid RETRIEVAL only; every generation feature is
// gated behind CapLLM and is NOT wired to any model.
type Capability string

const (
	// CapHybridSearch — dense + BM25 + RRF retrieval. Always available in v1.
	CapHybridSearch Capability = "hybrid-search"
	// CapLLM — requires a governed LLM backend for answer generation, LLM
	// reranking, query rewrite, HyDE, or contextual blurbs. There is NO LLM in
	// the mesh, so v1 refuses these with ErrRequiresLLM rather than pretending.
	CapLLM Capability = "requires-llm-backend"
)

// ErrRequiresLLM is returned by any entry point that would need an LLM. The mesh
// has no inference path, so v1 deliberately does not call one: answer
// generation, cross-encoder / LLM reranking, and KG-augmented answer synthesis
// are all deferred behind this gate (see the air-rag pillar spec, Phase 4).
var ErrRequiresLLM = errors.New("rag: requires an LLM backend, which is not available in v1 (governed hybrid retrieval only; generation is deferred)")

// RedactionNote documents the corrected redaction claim (adversarial-judge
// required change). The mesh's DLP is policy.PatternDLPHook: it detects sensitive
// spans by OPERATOR-CONFIGURED REGEX RULES, not by auto-masking arbitrary
// "sensitive-looking" text. air-rag v1 does not silently mask corpus content;
// any redaction a caller layers on is DISPLAY-ONLY over spans matched by those
// explicit DLP rules. Retrieval never claims to auto-detect unknown secrets.
const RedactionNote = "redaction is display-only over spans matched by operator-configured policy.PatternDLPHook regex rules; air-rag does not auto-mask unknown sensitive content"
