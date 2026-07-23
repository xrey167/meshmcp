# Air Knowledge System — Implementation Status

> Companion to the accepted architecture in `AIR-KNOWLEDGE-SYSTEM.md` (which is
> the spec and stays as written). This file is the honest spec-vs-built ledger:
> what exists, where it lives, what is deliberately deferred, and the known
> deviations. Updated 2026-07-23 (branch task/10-aks).

## Phase 0 — shared spine: COMPLETE

| Spine | Status | Where |
|---|---|---|
| S1 single-writer facade | done | `air/knowstore/facade.go` — mutex-serialized `Facade` sole-owns one `kg.Store`; gate→store→audit under one lock; served as the one writer process by `air kg serve` (`cmd/meshmcp/airkgserve.go`) |
| S2 stable KnowHash receipt | done | `air/know/hash.go` — domain-tagged, length-prefixed `H(S,P,O,Peer,Source,ValidFrom)`; `KnowReceipt.Verify` |
| S3 `know.Allowed` scoping | done (stricter than spec) | `air/know/scope.go` — deny-by-default, empty grant denies, writes need an exact-literal grant; called per-call inside the KG facade and the RAG backend |
| S4 audit vocabulary | done | `air/know/audit.go` — all 7 verbs; every one now emitted somewhere real (`graph.cosign` since AG-1) |
| S5 checkpoint + intent | done | `air/checkpoint/` — atomic temp+fsync+rename, `CreatorKey` binding on Load/Save/intent ops, pre-execution `Intent` closing the double-fire window |
| S6 envelope + trust-weighting | done | `air/know/envelope.go` — nonce-fenced `WrapUntrusted`, anti-breakout neutralization, Peer-derived `TrustMap.Weigh`; applied to RAG chunk egress (`airrag.go`) and GraphRAG triple egress (`graphrag.go`) |
| S7 caller-side gateway | done and wired | `air/egress/gateway.go` — per-call decide with accumulated taint, budget reserve/refund, cosign surfaced; driven per-hop by the graph runner (`cmd/meshmcp/airgraph.go`) |

Closed spine defect: the assert/retrieve **receipt mismatch** (assert hashed
Source/ValidFrom, reads recomputed from S/P/O/Peer only) is fixed — `kg.Record`
now persists `Corpus`/`Source`/`ValidFrom`, and `knowHashes` recomputes the full
S2 tuple, so a retrieve receipt equals the assert receipt of the same fact
(`air/knowstore/scope_test.go: TestReceiptRoundTrip_AssertHashEqualsRetrieveProvenance`).

Spec's two-process-append concurrency test exists in its honest form:
`kg/concurrency_test.go` proves two independent writer handles on one `kg.jsonl`
produce corruption that `Verify` DETECTS — which is why the single serve-process
writer is load-bearing.

**Operator warning — legacy second-writer footgun.** The old `cmd/kg` binary
(`cmd/kg/main.go`) still calls `st.Assert` directly against a store file. Never
point it at a `kg.jsonl` a running `air kg serve` owns: two writers on one file
corrupt the chain (detected, not prevented). Use `air kg serve` as the only
writer; records the legacy binary wrote without a corpus stay private to their
asserting peer's default subgraph.

## Phase 1 — air-kg: core COMPLETE, extract/EDC deferred

Done:
- Client verbs `assert | supersede | query | neighbors | subgraph | sync | verify | serve` (`cmd/meshmcp/airkg.go`).
- **Record-level subgraph scoping**: `kg.Record.Corpus` (additive, chain-compatible; old logs still verify — `kg/prov_test.go`); every facade read filters by record corpus BEFORE computing the provenance receipt, so "a triple with no visible subgraph never leaves the process" holds, including through the bounded k-hop traversal (`cmd/meshmcp/airkg_test.go: TestAirKGSubgraph_TraversalCannotCrossCorpusBoundary`). Legacy corpus-less records default to the asserting peer's own subgraph.
- **Supersede** (`Facade.Supersede`, `POST /v1/kg/supersede`): assert-new + tombstone-old under one facade-mutex hold, exact-write-grant gated, old fact must be active AND visible in the corpus (indistinguishable refusal for missing vs foreign — no existence probe), one `know.supersede` record carrying both refs. Deviation from the spec's `ValidTo` field: an append-only log cannot stamp the already-written old record; supersession is assert-new + tombstone (the spec's own storage model), with history preserved via `as_of`.
- **Alias/sameAs index** (`air/kgresolve.go` + `Facade.Canonical`): resolution modeled as triples, folded into a per-corpus index cached against the store head — not O(active-set) per lookup — governed and corpus-scoped (a foreign corpus's `sameAs` cannot steer resolution).
- **Delta sync** (`kg.DeltaSince`/`kg.ApplyDelta`, `Facade.Delta`, `GET /v1/kg/delta`, `air kg sync`): sender-side corpus filtering (out-of-scope records never hit the wire); tombstones resolved through their target fact's corpus so deletions survive a sync round-trip (`kg/delta_test.go`, `cmd/meshmcp/airkg_test.go: TestAirKGSyncRoundTrip_TombstoneSurvives`); each replica re-appends through its own chain (local `Verify` stays green; cross-replica identity is the stable KnowHash); cross-org pulls additionally gated by `federation.Boundary.CheckCorpus` via `--org-grant` (deny-by-default; an org claim can only narrow).
  - Sync is PULL-ONLY v1 into a locally-owned store: `--into` must not name a file a running serve owns (single-writer invariant). Serve-side apply and push are deferred.

Deferred (Phase 1): `kg extract` (EDC pipeline — the heuristic extractor and
`BuildExtractPrompt` remain unbuilt; the LLM extractor is Phase 4 regardless);
canonical `e_<hash>` entity IDs (aliases resolve names; nothing rewrites S/O).

## Phase 2 — air-rag: non-LLM v1 COMPLETE

Done:
- Hybrid retrieval (small-to-big `ChunkDocument` with ParentID + parents map, Okapi BM25, `FuseRRF`) served with per-call `know.Allowed` scoping, envelope-wrapped egress, row + total-byte caps (`airrag.go`), know.retrieve/extract audit with chunk-hash provenance.
- **KG entity linking** (`air/rag/entity.go` `LinkEntities`): surface forms from query + chunks, cosine vs the KG node vocabulary, deny-below-threshold (default 0.95), links only to supplied nodes (never fabricates). `graphrag.go` now links real entities and expands only linked nodes — the doc-ID proxy (`extractEntities`) is deleted; retrieved triples enter the merged context only inside the S6 envelope. Honesty note: under the local lexical embedder only (near-)exact token-set surfaces link; synonyms stay below threshold. A semantic embedder slots in behind `embed.Embedder` unchanged.
- **Eval harness** (`air/rag/eval.go` + `air rag eval`): deterministic ContextPrecision/Recall vs a gold JSONL set, mean-threshold CI gate (non-zero exit below `--min-precision`/`--min-recall`), fail-closed on any denied/failed search (never a silent 0.0).

Deferred (Phase 4, gated by `rag.CapLLM` / `ErrRequiresLLM`): answer generation,
LLM rerank, contextual blurbs, HyDE, query rewrite, LLM-judged faithfulness.

## Phase 3 — air-agent-graph: core COMPLETE

Done:
- Pure bounded cyclic engine (`air/graph`): conditional/back edges, immutable reducer, monotonic taint labels, max-iter (fail-closed default 25), cost mirror, convergence predicate.
- Governed runner (`cmd/meshmcp/airgraph.go`): every hop decided fresh through the local egress gateway (proved by `TestRunGraph_PolicyConsultedEveryHop`); deny terminates, budget halts, S5 checkpointing with CreatorKey-bound resume and pre-execution intent.
- **Cosign release wiring**: a park persists the exact-call binding key and emits a `graph.cosign` (cosign) record; release happens ONLY by atomically consuming a signed, single-use, argument-bound `policy.ApprovalToken` (`--approvals` + `--approval-key`, pinned signer required — fail-closed against approval-burning). Run-bound (session = run id) approvals are tried first, then the standard approver's session-less form. A release executes exactly once — through `egress.Gateway.Release`, which recovers the matched rule's emit-labels + cost from the engine (`policy.Engine.RuleEffects`) and binds them exactly as an allowed call's decision would (budget pre-check before executing, spend + taint folded into the gateway and the state mirror) — and emits a `graph.cosign` allow record plus the governed-call allow record with its cost; an approval for different arguments does not match (the iteration-N vs N+1 attack); resume refuses a drifted pending binding outright.
- **Wall-clock bound**: `--timeout` (default 10m; zero/negative coerced — never unbounded) enforced at every hop in the runner (the pure engine stays time-free by design); expiry checkpoints a resumable `timeout` stop and audits a wall-clock deny. All four spec bounds now hold: max-iter, cost, wall-clock, convergence.
- **Taint lattice across restarts**: resume re-seeds the fresh gateway from the checkpoint's persisted labels (`egress.Gateway.Taint`), so pre-crash taint still blocks post-resume egress.

Closed defect (was: released-call taint/cost drop): the engine's cosign verdict
carries no `Cost`/`AddLabels` (nothing is charged while a call is held), so the
runner's original release path executed the tool directly and folded those
empties — a rule that was both `require_cosign` and `taint_source` released
WITHOUT tainting the run, defeating every downstream taint guard for exactly
the human-approved high-risk call, and released calls spent nothing against the
budget. Fixed: release now executes through `egress.Gateway.Release`, which
recovers the matched rule's effects via `policy.Engine.RuleEffects` and binds
them exactly as an allowed call — cost budget-checked BEFORE executing (a
breach halts the run as `budget`, unexecuted; a stale rule id refuses
fail-closed), spend and emit-labels folded into the gateway and the state
mirror. Anchored by `TestResume_ReleasedCosignCallStillTaints` (released
taint_source still blocks taint-guarded egress),
`TestResume_ReleasedCosignCallSpendsRuleCost`,
`TestResume_ReleasedCosignCallBudgetHalted`, and the egress-level
`TestReleaseFoldsRuleEffects` / `TestReleaseFailClosed` / `TestReleaseBudgetHalt`.

Deferred (Phase 3 tail): distinct-critic-identity dispatch, supervisor
`AuthorizeDelegated` bound, `air graph steer`/`list` verbs, run fork/branch.

## Phase 4 — LLM-gated generation: DEFERRED (unchanged)

No model is wired anywhere. Every LLM-adjacent surface refuses via
`rag.ErrRequiresLLM`; nothing in Phases 0–3 depends on inference.

## Governance invariants (held by construction, test-anchored)

- **Identity-stamped**: every store record and audit record carries the acting Peer/PeerKey.
- **Subgraph-scoped**: record-level corpus visibility on every read, sender-side on sync, per-call claims in RAG, org-narrowing on cross-boundary deltas.
- **Deny-by-default**: empty grant shares nothing; blank corpus never authorizes; below-threshold links resolve nothing; unapproved cosign stays parked; zero bounds coerce to safe defaults; eval and resume fail closed.
