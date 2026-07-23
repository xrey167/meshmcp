# OAuth Standards Integration — Status

Companion to `docs/spec/OAUTH-STANDARDS-dod.md` (the checklist this document
tracks item-for-item), `docs/spec/OAUTH-STANDARDS.md` (design), and
`docs/spec/OAUTH-STANDARDS-tests.md` (test plan).

**How this was produced.** Every item below was independently checked against
the repo on disk as of this writing (`git status` shows an uncommitted working
tree on branch `dependabot/github_actions/actions/checkout-7.0.1`) — not
transcribed from the five implementation-agent JSON summaries handed off for
this review. Where a summary claimed something the repo doesn't show, that
claim is called out explicitly. Legend: ✅ done (verified in repo, passing) ·
🟡 partial (exists but incomplete, or deviation/open issue) · ❌ missing/not
attempted · 🚫 blocked (not a defect — deliberately not attempted, per the
task).

## Global caveats (apply to every feature below, not repeated per row)

1. **The DoD's repo-wide gate is not satisfied in this environment.**
   `CGO_ENABLED=1 go build ./...` and `go vet ./...` are clean (verified).
   `go test ./... -race` cannot run at all: no C compiler is installed
   (`cgo: C compiler "gcc" not found`), and `-race` requires cgo. The full
   suite was verified instead with `CGO_ENABLED=0 go test ./...` (no
   `-race`) — every test passes, but this is **not** the literal gate the DoD
   requires, and no feature below is fully signed off until CI re-runs the
   real gate (`-race`) on a host with a C toolchain. This is an environment
   limitation, not a code defect, but it means "tests pass" in this document
   never means "the DoD's gate is green."
2. **`govulncheck` was not run anywhere** (not installed in this environment).
   Relevant because this work introduces the repo's first new direct
   third-party dependency (`golang.org/x/crypto/bcrypt`, Feature C1) — the
   design doc treats a vuln/license check as a prerequisite for that, not a
   nice-to-have.
3. **Feature-wide documentation bookkeeping (`docs/CAPABILITY-MATRIX.md`,
   `docs/ROADMAP-HARDENING.md`) is broadly missing, and this is one shared
   root cause, not five independent oversights.** Five agents edited these
   same two shared files concurrently across separate sessions; only the
   Feature C0 agent's edits (the last to land) survived. As of now,
   `docs/CAPABILITY-MATRIX.md` contains exactly **one** new row (C0's DPoP
   verifier, "Experimental") and `docs/ROADMAP-HARDENING.md` contains
   exactly **one** new flagship entry (F35, also C0). Feature A's row, F34
   (Feature B), F31's extension (Features C1/C2), and S61 are all absent from
   the files on disk regardless of what each agent's summary claims to have
   written. This is called out once here; each feature's own doc line below
   just says "missing — see global caveat 3."
4. **The Feature C gating precondition was never satisfied, yet C0–C2 were
   built anyway.** The DoD states, as a precondition for *any* C0 code:
   the exposure-model question in `docs/spec/OAUTH-STANDARDS.md` must be
   "explicitly resolved and recorded ... before any C0 code is written."
   As of this writing, `docs/spec/OAUTH-STANDARDS.md` still reads "requires
   explicit operator/product sign-off" — the placeholder language the DoD
   says must be replaced with an actual decision. It was not. This means C0,
   C1, and C2 (all built, tested, and green as standalone modules) proceeded
   without their own required gate being closed — separate from, and prior
   to, the C3 block the task already told you about. A project owner should
   treat this as a process gap to close (record the decision) even though it
   did not block the code from being written or tested.

---

## Feature A — SPIFFE identity labels

**Overall: 🟡 Partial — and materially less complete than the implementing
agent's summary claims.** The core primitive (`SpiffeID`/`ValidTrustDomain`)
is real, tested, and correct. But the feature's actual purpose — labels
*surfaced in audit records and federation crossings* — is not wired to
anything: `Config.TrustDomain` does not exist, `federation/boundary.go` has
zero SPIFFE/TrustDomain content, and grepping the whole repo for a call to
`SpiffeID(` outside its own definition and tests returns nothing. **No
SPIFFE label is emitted anywhere in this codebase today.** The agent's JSON
reported `federation/boundary.go`/`federation/boundary_test.go` as edited
with 5 new passing tests and `config.go`/`config_test.go` as edited with a
`TestConfigTrustDomainValidation` test — none of this exists on disk; it was
most likely lost to the concurrent-agent git churn later agents' own
`openIssues` describe, and never reapplied.

**Code**
- ❌ `config.go`: `Config.TrustDomain string` — **absent.** Grepped the
  `Config` struct in full; no such field. `Backend.Remote` (Feature B) is
  present, so this isn't a stale read — the field genuinely isn't there.
- ✅ `policy/spiffe.go` (new file, not `policy/audit.go` as the DoD's
  "or" allows): `type SpiffeLabel string`; `SpiffeID(trustDomain,
  peerKeyBase64 string) SpiffeLabel` — plain return, no error; decodes
  `base64.StdEncoding`, re-encodes `base64.RawURLEncoding`; malformed
  key/empty trust domain → `SpiffeLabel("")`. Matches spec.
- ✅ `AuditRecord` gains `PeerSpiffeID SpiffeLabel
  \`json:"peer_spiffe_id,omitempty"\`` appended after `Hash` — verified in
  `policy/audit.go`, correct position, correct tag. (Note: the code comment
  on this field states plainly it was added by the *Feature C0* agent "to
  unblock the policy package's test compilation," not by Feature A's own
  session — corroborating that Feature A's original edit to this file was
  lost and a different agent re-added only the minimum needed.)
- ❌ `federation/boundary.go`: `Mapping.TrustDomain`, org→trust-domain map in
  `NewBoundary`, collision check, `Boundary.SpiffeID(org, peerKey)` — **all
  absent.** Read the full file; it has no trust-domain or SPIFFE content at
  all, only the pre-existing `Grant`/`Mapping`/`OrgFor`/`Principal` plus the
  separately-landed Feature C2 `OrgForIssuer`.
- ❌ Which-trust-domain-applies call-site rule — **not applicable / not met**,
  since neither call site exists to enforce the rule at.
- ✅ No existing exported signature changed (trivially true — additive-only
  everywhere it landed).

**Docs / schema**
- 🟡 `docs/spec/AUDIT-RECORD.md` — updated with the `peer_spiffe_id` row, but
  **missing the required mixed-fleet compatibility note** (grepped for
  "mixed-fleet"/"old verifier"/"upgraded together" — no match anywhere in the
  file).
- ✅ `docs/spec/audit-record.schema.json` — `peer_spiffe_id` added
  (`"type":"string"`, pattern-constrained); `TestAuditRecordSchema_AllowsPeerSpiffeID`
  passes.
- ❌ `docs/CAPABILITY-MATRIX.md` Planned→Beta row — missing (global caveat 3).

**Invariants preserved**
- 🟡 "Record with `PeerSpiffeID` unset verifies identically" — plausible by
  construction (`omitempty`, zero value) but the specific regression test the
  DoD calls for (`TestAuditRecord_HashChainUnaffectedByNewField`,
  `TestAuditRecord_PeerSpiffeIDOmittedWhenEmpty`,
  `TestAuditRecord_HashChainWithSpiffeIDPresent`,
  `TestAuditRecord_MixedFleetHashMismatchIsExpected`) **does not exist
  anywhere in the repo** — grepped by exact name, zero hits, despite being
  listed in the agent's `testsAdded`. Not verified, only asserted.
- ✅ Enforcement decisions don't read `PeerSpiffeID`/`SpiffeID()` — true, but
  vacuously: grepped every `.go` file for a call to `SpiffeID(`; the only
  hits are the definition and its own tests. There is no enforcement (or any
  other) call site to have gotten this wrong at.

**Sign-off:** not met. Trust-domain collision check is not exercised (the
collision-detection code doesn't exist). Schema round-trip is verified;
hash-chain regression suite is unaffected but not through a dedicated new
test as specified.

---

## Feature B — Outbound OAuth 2.1 client + DPoP (signer/client side)

**Overall: 🟡 Partial — code and tests are solid and verified; doc
bookkeeping and one explicitly-optional integration test are the gaps.**

**Code**
- ✅ `config.go`: `Backend.Remote *RemoteBackendConfig` present; three-way
  exactly-one-of check at `loadConfig` (verified: `hasStdio, hasHTTP,
  hasRemote` all checked, rejects zero-of and two-or-more-of). Test
  `TestServeRemote_ThreeWayBackendExclusivity` passes.
- ✅ `remotebackend.go`: `serveRemote` factory present; uses
  `protocol/authorization` discovery helpers per grep (`Doer` interface,
  `httpEnforcer` reuse on the inbound side, `secrets.Store`/`SetSecretResolver`
  wiring all present in the file).
- ✅ `policy/dpopsign.go`: ECDSA P-256 `DPoPSigner`;
  `GenerateDPoPSigner`/`SaveDPoPSigner`/`LoadDPoPSigner` present; on-disk
  `KeyType` field pinned to `"dpop-es256"` (`dpopKeyType` const), and
  `LoadDPoPSigner` explicitly errors if the discriminator doesn't match —
  domain separation from `policy/sign.go` is real, not just claimed.
  `SaveDPoPSigner` uses tmp-file + `os.Rename` (atomic), confirmed at line 95.
- ✅ RFC 9449 §4.2 claims (`htu`, `htm`, `iat`, `jti`, `nonce`, `ath`) — all
  covered by passing tests (`TestDPoPProof_RequiredClaims`,
  `TestDPoPProof_AthClaimOnResourceRequest`, etc.).
- ✅ `use_dpop_nonce`/`invalid_dpop_proof` handling — both distinct test cases
  pass (`TestServeRemote_RefreshesOnExpiryAndNonce`,
  `TestServeRemote_HandlesInvalidDPoPProofErrorCode`).
- ✅ Secrets via existing `secrets.Store`/`Broker` — confirmed, no second
  store type introduced.
- ✅ Refresh-token rotation atomic (`TestRotateSecretInFile_Atomic` passes).
- ✅ Missing/unloadable DPoP key file fatal at startup
  (`TestDPoPSigner_MissingKeyFileIsFatalAtStartup`,
  `TestBuildRemoteClient_MissingDPoPKeyFileIsFatal` both pass).
- ✅ `httpEnforcer` reused on the inbound side (grep confirms the same F16
  enforcer type is threaded through `remoteHandler`).
- ✅ Outbound `Doer`-shaped `http.Client`, no retry loop — confirmed in code.

**Docs / schema**
- ❌ Operator-facing `Remote` backend config doc — the agent's own summary
  notes `docs/for-operators/meshmcp-gateway/backends.mdx` doesn't exist in
  this repo and no equivalent was created; field docs exist only as GoDoc
  comments on `RemoteBackendConfig`. Acceptable per the DoD's own hedge
  ("wherever such a doc exists... if such a doc exists") but the operator
  still has no doc page today.
- ❌ `docs/CAPABILITY-MATRIX.md` new row ("Remote OAuth-protected MCP
  backend") — missing (global caveat 3; confirmed by direct grep, only the
  C0 row exists).
- ❌ `docs/ROADMAP-HARDENING.md` F34 — missing (global caveat 3; grepped, no
  F34 anywhere in the file).
- N/A — no new JOSE library adopted (hand-rolled, per design doc), so the
  license/govulncheck item doesn't strictly apply, though `govulncheck`
  overall still wasn't run (global caveat 2).

**Invariants preserved**
- ✅ Denied tool never reaches outbound request —
  `TestServeRemote_DeniedToolNeverReachesOutboundRequest` passes.
- ✅ Secrets never in audit/trace/error —
  `TestServeRemote_SecretsNeverInAuditOrError` passes.
- ✅ DPoP proof never reused (`TestDPoPProof_JTIUniquePerRequest`,
  `TestServeRemote_RejectsReplayedProof` pass).

**Sign-off:** fake-AS suite green, denied-tool and secrets-redaction tests
pass, refresh/key-file atomicity tests pass. 🟡 **Not fully met**: the one
real end-to-end drive against `cmd/mcpecho` fronted by a live local
OAuth+DPoP server (`TestRemoteBackend_EndToEnd`) does not exist anywhere in
the repo (grepped by name, zero hits) — it is explicitly allowed to be
skipped per the test-plan doc's own "may be `t.Skip`" language, and the
implementing agent flagged this as a deliberate deferral rather than an
oversight, but the sign-off line in the DoD explicitly lists this test as
required, so it is marked not-met here rather than silently waived.

---

## Feature C0 — DPoP verification primitive

**Overall: ✅ Done, modulo the global `-race` caveat.** This is the most
complete slice. Every named check in the DoD and every named test in the
test plan exists and passes.

**Code** — all ✅, verified by reading `policy/dpopsign.go` (verifier lives
alongside the Feature B signer, per design) and running the test file:
- ✅ Algorithm pinned to `ES256`, `alg` header only checked against the pin.
- ✅ `typ`, `htu` (documented normalization), `htm`, non-empty `jti`.
- ✅ `iat` freshness window with a pinned default (300s max age / skew,
  matching the DoD's recommendation).
- ✅ `jkt` (RFC 7638) vs. `cnf.jkt` binding.
- ✅ `ath` check on resource requests.
- ✅ Replay store bounded to the freshness window; `TestVerify_JTIRetentionBounded`
  passes.
- ✅ Nonce lifecycle: issuance, single-use, TTL — `TestVerify_NonceRequiredAndSingleUse`,
  `TestVerify_NonceExpiry` pass.
- ✅ Spec-shaped `invalid_dpop_proof`/`use_dpop_nonce` errors —
  `TestVerify_ErrorResponseShapeIsSpecCompliant` passes.
- ✅ Replay-store durability decision recorded (in-memory, documented,
  restart-window residual risk explicit) — `TestVerify_RestartReplayWindow`
  passes and asserts exactly this behavior. The documented durable-backing
  option now exists: `pgstore` implements `DPoPReplayStore`, and the edge
  accepts it via `oauth.dpop_replay_store` (fail-closed, cross-instance).
- ✅ Structural domain separation from `policy/sign.go`'s Ed25519 path — no
  shared verify function/type (confirmed by reading the file: distinct types,
  distinct key-file discriminator).

**Docs**
- ✅ `docs/ROADMAP-HARDENING.md` F35 — present, references
  `policy/dpopsign.go` and the DoD block.
- ✅ `docs/CAPABILITY-MATRIX.md` new row for the verifier, distinct from
  Feature B's row — present ("Experimental").

**Invariants preserved** — all ✅: `TestVerify_AlgConfusionRejected`,
`TestVerify_WrongJKTRejected`, `TestVerify_ReplayedJTIRejected` all pass and
match the DoD's exact scenarios.

**Sign-off:** every named check has its own passing test.
`TestDPoP_ClientServerInterop` (B's client ↔ C0's verifier, no fake AS) passes.
Alg-confusion and key-confusion tests pass. 🟡 Caveat: none of this ran under
`-race` (global caveat 1) — treat as "green modulo the repo-wide gate," not
fully signed off until that's re-run on a host with a C toolchain.
🟡 Also built ahead of its own gating precondition (global caveat 4).

---

## Feature C1 — DCR registration + management store

**Overall: 🟡 Partial — code, tests, and the hard security invariants are
all solid and verified; the cross-cutting fuzz target and shared docs are
the real gaps.**

**Code** — verified by reading `federation/dcr.go` and running its tests:
- ✅ `POST /oauth2/register`, `GET/PUT/DELETE /oauth2/register/{client_id}` —
  present as standalone handlers (unwired, per C3 staging discipline).
- ✅ Initial-access-token gate with `client:register` scope —
  `TestDCR_RegisterRequiresValidInitialAccessToken` passes.
- ✅ File store mirrors `FileApprovalStore` (`0700`/`0600`, atomic rename) —
  `TestDCR_RegisterFilePermsAndAtomicWrite` passes.
- ✅ bcrypt-hashed `registration_access_token`, cost 12 pinned
  (`bcryptCost = 12`), SHA-256 pre-hash before bcrypt —
  `TestDCR_BcryptCostFactorPinned`, `TestDCR_LongTokenPreHashedBeforeBcrypt`
  both pass.
- ✅ `registration_source ∈ {"internal","dcr"}`; DELETE refuses `"internal"` —
  `TestDCR_DeleteRefusesInternalClient` passes. Deviation (documented,
  reasonable): PUT does *not* apply the internal-refusal rule, only DELETE —
  a literal reading of the design doc, which scopes the rule to "the delete
  path" specifically; flagged here as a judgment call worth a second look,
  not a defect.
- ✅ Fail-closed on read failure —
  `TestDCR_DeleteRefusesOnUnreadableRecord` passes; distinct positive case
  `TestDCR_DeleteAllowsDCRClient` proves the refusal is source-gated, not a
  blanket delete-disable.
- ✅ Rate-limiting/quota — `http.MaxBytesReader`, `ReadHeaderTimeout`/
  `ReadTimeout`, per-token client quota (`defaultMaxClientsPerToken`), and a
  management-path rate limiter (`rateLimiter`/`manageLimiter`) all present in
  code and exercised by `TestDCR_RegistrationQuotaEnforced`,
  `TestDCR_MaxBytesReaderEnforced`, `TestDCR_SlowlorisTimeoutEnforced`,
  `TestDCR_ManagementRateLimitEnforced`.
- ✅ Fail-closed audit — `TestDCR_AuditWriteFailureDeniesRegistration` passes.

**Docs**
- N/A `docs/spec/DCR-FACADE.md` — the DoD explicitly allows skipping this
  "decide at implementation time based on actual surface size"; the surface
  here (two routes) is small enough that skipping is a defensible call, not
  a gap.
- ❌ `docs/THREAT-MODEL.md` new "external non-mesh OAuth registrant/client"
  adversary — missing (grepped for "non-mesh"/"registrant"/"DCR" in
  `docs/THREAT-MODEL.md`: zero hits).

**Invariants preserved**
- ✅ Internal client unreachable by delete, including on read failure — both
  tested and passing.
- ✅ Registration cannot exhaust disk — bounded by the enforced quota, tested.

**Sign-off:** CRUD lifecycle, internal-deletion red-team (incl. read-failure
variant), rate-limit/quota, and fail-closed-audit tests all pass. 🟡 Two
gaps against the cross-cutting test-plan requirements: the fuzz target for
the DCR JSON parser (explicitly "expected before C1/C2 are marked done" per
`docs/spec/OAUTH-STANDARDS-tests.md`) does not exist (grepped, no `func
Fuzz` in `federation/`), and `govulncheck` was not run against the new
direct `bcrypt` dependency (global caveat 2). Also built ahead of the
Feature C gating precondition (global caveat 4).

---

## Feature C2 — RFC 8693 exchange + RAR mapping

**Overall: 🟡 Partial — code and tests fully match the DoD's hardest
requirements; the gap is entirely shared-doc bookkeeping (global caveat 3).**

**Code** — verified by reading `federation/exchange.go` and running its
tests:
- ✅ DPoP required before subject-token parsing —
  `TestExchange_RejectsRequestWithoutDPoP`,
  `TestExchange_RejectsPlainBearerAtTokenEndpoint` pass.
- ✅ All four subject-token checks (signature/pinned JWKS, issuer, audience,
  exp/nbf) — `TestExchange_SubjectTokenAudienceConfusionRejected` (the
  Critical-severity finding from the design doc's review) passes, as do the
  issuer and expiry variants.
- ✅ Org resolution via validated issuer, new `Mapping` match form
  (`issuer:` prefix, `OrgForIssuer` in `federation/boundary.go`), does **not**
  inherit `"*"` wildcard — `TestExchange_IssuerCollisionDoesNotCrossOrgBoundary`
  passes; confirmed in code that `OrgForIssuer` has no wildcard fallback.
- ✅ `authorization_details` → `CapabilityClaims` via `Signer.IssueCapability`
  — confirmed by grep (`IssueCapability` called; `IssueDelegation`/
  `AuthorizeDelegated` explicitly asserted absent by
  `TestExchange_DoesNotInvokeDelegationPath`, which greps the exchange path's
  own source for those forbidden identifiers at test time).
- ✅ Closed, enumerated RAR `type` set with `DisallowUnknownFields()` strict
  decoding — confirmed in code; `TestExchange_UnknownFieldInKnownTypeRejected`
  and `TestExchange_UnknownTypeRejected` both pass (the DoD's stronger
  "unknown field within known type" guarantee, not just "unknown type").
- ✅ Multi-entry union-then-intersect semantics —
  `TestExchange_MultiEntryUnionThenIntersect`,
  `TestExchange_ScopeIntersectsOrgGrant` pass.
- ✅ Lifetime cap — `federationGrantMaxLifetime = 1 * time.Hour`, explicitly
  documented in code as shorter than `policy/capability.go`'s general 24h
  ceiling, with the required stated justification (smaller blast radius for
  an external, non-DPoP-rebound-per-request grant) —
  `TestExchange_MintedCapabilityLifetimeCapped` passes.
- ✅ No parallel minting path — `Signer.IssueCapability` called directly,
  `TestExchange_CallsExistingIssueCapabilityNotADuplicate` passes.

**Docs**
- N/A OAUTH-STANDARDS.md C2 section as source of truth — unchanged, fine.
- ❌ `docs/ROADMAP-HARDENING.md` F31 extended to reference C2 — missing
  (global caveat 3; confirmed F31's text is unchanged, still only mentions
  OIDC/SSO mapping, no DCR/8693/RAR reference).

**Invariants preserved**
- ✅ Audience-confusion rejected (the single most important test in this
  document, per the test plan) — passes.
- ✅ Subject collision doesn't cross org boundary — passes.
- ✅ Scope never exceeds org grant — passes.
- ✅ `policy/delegation_test.go` untouched and still green — ran it directly
  as part of the full `policy` package test run; all existing delegation
  tests pass unchanged. `federation/boundary_test.go`'s pre-existing cases
  (`TestOrgIdentityMapping`, `TestCrossOrgCorpusGrant`,
  `TestBoundaryAuthorizesByGrant`) also pass unchanged.

**Sign-off:** full exchange lifecycle, audience-confusion/issuer-collision
red-team, RAR strict-rejection, and both regression suites all green. 🟡 Same
two caveats as C1: no fuzz target for the RAR mapper (cross-cutting
requirement), built ahead of the Feature C gating precondition (global
caveat 4), and not run under `-race` (global caveat 1).

---

## Feature C3 — Wire into a live listener

**Overall: ✅ Shipped — 2026-07-23.** The exposure-model decision was recorded
(extended Option A; see the decision block in `docs/spec/OAUTH-STANDARDS.md`),
which unblocked C3. The wiring did NOT go into `federate.go` (the partner-org
boundary): the recorded decision extended the scope to **hosted MCP clients**
(claude.ai custom connectors), which the issuer-pinned federation-exchange
model does not fit. It ships instead as a dedicated, off-by-default public
ingress — the **`meshmcp edge`** subcommand and the `edge/` package — that
terminates OAuth 2.1 + PKCE with operator-in-the-loop consent, DCR (open-
approval or IAT-gated), and a single tool-scoped Streamable-HTTP `/mcp` path
(POST + GET/SSE + sessions). Each hosted client is mapped to an
`oauth:<client_id>` identity that passes the same default-deny policy, an
Ed25519 capability double-gate, and the fail-closed audit log. A full-handshake
conformance harness (`edge/conformance_test.go`) exercises the whole flow
against a live TLS server for both registration modes, green under `-race`.
`federate.go`, `serve.go`, the policy engine, and `federation/` are unchanged —
the earlier standalone DCR/exchange handlers there remain the partner-org path
for a future, separate wiring.

- ❌ `federate.go`'s `buildBoundaryServer` — not touched (confirmed no
  façade wiring; existing `OrgFor` path is exactly as it was).
- ❌ Distinct listener for the façade — N/A, nothing built.
- 🚫 All invariants/sign-off items — not attempted, correctly blocked.

**What this means concretely:** C0–C2 exist today as reachable-only-via-tests
standalone modules with zero effect on any live mesh-peer federation path —
exactly the intended state pending the product decision.

---

## Summary

| Feature | Implemented | Tested | Build+Vet Clean | Open Issues Count |
|---|---|---|---|---|
| A — SPIFFE labels | 🟡 Partial (primitive only; not wired to config or federation; no label ever emitted) | 🟡 Partial (11 tests pass; 4+ DoD-required regression tests don't exist) | ✅ Yes | 6 |
| B — Outbound DPoP/OAuth client | 🟡 Partial (all code items verified) | ✅ Yes (all named unit/integration tests pass; optional E2E test absent) | ✅ Yes | 3 |
| C0 — DPoP verifier | ✅ Done (modulo `-race`) | ✅ Yes (all 14 named tests + interop test pass) | ✅ Yes | 2 |
| C1 — DCR store | 🟡 Partial (code solid; docs + fuzz target missing) | ✅ Yes (all 13 named tests pass) | ✅ Yes | 3 |
| C2 — RFC 8693 exchange + RAR | 🟡 Partial (code solid; doc bookkeeping missing) | ✅ Yes (all 13 named tests + 2 regression suites pass) | ✅ Yes | 3 |
| C3 — Wire into a live listener (`meshmcp edge`) | ✅ Shipped (2026-07-23; hosted-client edge, not federate.go) | ✅ Yes (edge/*_test.go + full-handshake conformance) | ✅ Yes | 0 |

**"Build+Vet Clean" columns** reflect the actual, just-run
`CGO_ENABLED=1 go build ./... && CGO_ENABLED=1 go vet ./...` across the whole
module — both are clean as of this writing, contradicting several
implementation agents' reports of pre-existing module-wide build breaks
(`Backend.Remote` undefined, import-path mismatches); those issues have
evidently been resolved by a later agent's session and are no longer present.
**"Tested" does not mean the DoD's literal `-race` gate passed** — see global
caveat 1; it means the named tests exist and pass under
`CGO_ENABLED=0 go test ./...` in this environment.

**Bottom line for a project owner:** Features C0–C2 are the strong result of
this round — real, tested, security-invariant-verified code, gated correctly
behind C3's non-wiring. Feature B is essentially done at the code level with
only documentation debt outstanding. **Feature A is the one that needs
another pass, not just bookkeeping**: its headline capability (SPIFFE labels
on audit records and federation crossings) does not exist in any operative
sense today — only the pure-function primitive and an unused struct field
do. Two process items apply across the board: the Feature C exposure-model
sign-off was never recorded even though C0–C2 were built (global caveat 4),
and nothing in this round has been verified under the repo's own `-race`
gate (global caveat 1) — both should be closed before any of this is called
"done" in the fullest sense the DoD intends.
