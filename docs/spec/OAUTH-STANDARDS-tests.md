# OAuth Standards Integration — Test Plan

Companion to `docs/spec/OAUTH-STANDARDS.md` (design) and
`docs/spec/OAUTH-STANDARDS-dod.md` (done criteria). Follows the repo's
existing per-package test convention (table-driven, `-race`, one file per
source file — e.g. `policy/delegation_test.go`,
`policy/approval_token_test.go`, `federation/boundary_test.go`) and its
stated test culture from `docs/ROADMAP-HARDENING.md`: a per-feature invariant
test, an end-to-end drive, and a red-team regression per closed finding.

> **Revision note.** This revision adds an entirely new test section (Feature
> C0, the DPoP verifier) that the first draft had no owned tests for — the
> first draft's DPoP-related tests all verified correctness from a *fake AS's*
> point of view, which covers Feature B's client behavior but never actually
> exercises meshmcp verifying a proof itself. It also adds: subject-token
> audience/issuer-confusion tests (the Critical finding), RAR
> strict-unknown-field-rejection tests, fail-closed-on-read-failure and
> fail-closed-audit tests, rate-limit/DoS tests, and a restart-replay test.
> White-box "assert this literal function was called" cases from the first
> draft are reworded to behavioral assertions.

All new test files must pass under `CGO_ENABLED=1 go test ./... -race`
alongside the existing suite — no new test may be `-race`-unsafe or skip the
race detector.

---

## Feature A — SPIFFE identity labels

**New file: `policy/spiffe_test.go`**

| Test | Asserts |
|---|---|
| `TestSpiffeID_RoundTripsRealNetBirdKey` | A real NetBird-shaped standard-padded-base64 key (including one containing `+` and `/`) produces a SPIFFE ID whose path segment matches `^[a-zA-Z0-9._-]+$`; decoding the segment back (`base64.RawURLEncoding`) yields the original key bytes. |
| `TestSpiffeID_EmptyTrustDomain` | Empty `trustDomain` returns `SpiffeLabel("")`, never a malformed `spiffe://` string. |
| `TestSpiffeID_MalformedKey` | An unparseable key string returns `SpiffeLabel("")` — the signature is `(SpiffeLabel)`, no error (per the design doc's explicit signature decision), so this test asserts the empty-return behavior, not an error value. |
| `TestSpiffeID_Deterministic` | Same inputs → byte-identical output across calls (no time/random dependency). |
| `TestSpiffeID_StandardPaddedInputOnly` | Confirms the decode side accepts standard padded base64 (matching `client.IdentityForIP`'s actual output form) and does not also silently accept unpadded/URL-safe input variants that would decode to a different byte value for a visually similar string. |

**Extend `policy/audit_test.go` (or wherever `AuditRecord` hash-chain tests
live today):**

| Test | Asserts |
|---|---|
| `TestAuditRecord_PeerSpiffeIDOmittedWhenEmpty` | Marshaling a record with `PeerSpiffeID == ""` produces JSON with the field absent, not `""` — confirms `omitempty` actually elides it. |
| `TestAuditRecord_HashChainUnaffectedByNewField` | A chain of records built **before** this feature (fixture bytes, or records built with `PeerSpiffeID` always empty) verifies identically to the pre-feature test output — i.e. this is a true additive-only, `-race`-covered regression test. |
| `TestAuditRecord_HashChainWithSpiffeIDPresent` | A chain where every record **has** `PeerSpiffeID` set still verifies — proves the new field doesn't accidentally break canonical serialization/ordering assumptions the hash-chain relies on (`docs/spec/AUDIT-RECORD.md` §3). |
| `TestAuditRecord_MixedFleetHashMismatchIsExpected` | A record written with `PeerSpiffeID` set, then re-serialized by code that doesn't know the field (simulating an old verifier binary), produces a **different** hash than the original — documents and locks in the accepted mixed-fleet incompatibility rather than leaving it as an undiscovered surprise. |

**Extend `federation/boundary_test.go`:**

| Test | Asserts |
|---|---|
| `TestBoundary_SpiffeID_KnownOrg` | `Boundary.SpiffeID(org, peerKey)` returns the expected URI when `Mapping.TrustDomain` is set for that org and a stable peer key is available. |
| `TestBoundary_SpiffeID_UnknownOrgOrNoTrustDomain` | Returns `""` for an org with no configured trust domain — never panics, never falls back to a default domain silently. |
| `TestBoundary_SpiffeID_FQDNMappedPeerHasNoStableKey` | An org mapped by FQDN glob (no individual pubkey) yields `SpiffeID(org, "") == ""` rather than a malformed URI. |
| `TestBoundary_TrustDomainCollisionDetected` | Two `Mapping`s with the same non-empty `TrustDomain` for different orgs are flagged at `NewBoundary` construction (reject or warn per config) rather than silently accepted. |
| `TestBoundary_ExistingMappingFieldsUnaffected` | Existing `OrgFor`/`Principal` test cases from before this change still pass byte-for-byte — proves `Match`/`Org`/`Principal` semantics are untouched. |

**Schema check:** a small test (or reuse an existing schema-validation
harness if one exists for `audit-record.schema.json`) that marshals a sample
`AuditRecord` with `PeerSpiffeID` set and validates it against the updated
schema — catches the `additionalProperties: false` trap directly.

---

## Feature B — Outbound OAuth 2.1 client + DPoP (signer/client side)

**Scope reminder:** every test in this section verifies meshmcp's behavior
*as a DPoP client* — the correctness check for "did meshmcp send a valid
proof" is performed by the fake AS's own independent verification logic in
the test, which is appropriate here. It must not be read as testing
meshmcp's own verifier — that has no owned tests until Feature C0 below.

**New file: `policy/dpopsign_test.go`** (mirrors `policy/sign_test.go` if one
exists, else `policy/capability_test.go`'s structure)

| Test | Asserts |
|---|---|
| `TestDPoPSigner_GenerateSaveLoadRoundTrip` | Generate → save to temp path → load → produced proofs are verifiable with the loaded key; file perms are `0600`. |
| `TestDPoPSigner_KeyFileHasDistinctTypeDiscriminator` | The on-disk key file includes `"key_type":"dpop-es256"` and `policy/sign.go`'s `LoadSigner` cannot successfully load it as an Ed25519 signer (fails clearly, not silently) — proves the domain-separation requirement. |
| `TestDPoPProof_RequiredClaims` | A generated proof JWT decodes to a header with `typ: "dpop+jwt"`, `alg: "ES256"`, and an embedded `jwk`; claims include `htu`, `htm`, `iat`, `jti`. |
| `TestDPoPProof_HTUMatchesActualRequestURL` | Proof built for URL A is rejected (by the fake AS's own check) when replayed against URL B. |
| `TestDPoPProof_JTIUniquePerRequest` | Two proofs generated for the same request in quick succession have different `jti`. |
| `TestDPoPProof_AthClaimOnResourceRequest` | When presenting a DPoP-bound access token to a resource server, the proof's `ath` claim equals the base64url SHA-256 of the access token (RFC 9449 §4.3). |
| `TestDPoPSigner_MissingKeyFileIsFatalAtStartup` | A backend configured with `dpop_private_key` pointing at a nonexistent/corrupt file fails backend startup outright — never silently generates a fresh key in its place. |
| `TestDPoPSigner_RotationIsAtomic` | Simulated key rotation (regenerate + save) uses tmp-file + rename; an interrupted rotation (test kills the write mid-way, or asserts via the API surface used) never leaves the original key file partially overwritten. |

**New file: `remotebackend_test.go`** (root package, matching
`httpserve_test.go`/`httppolicy_test.go` naming if those exist)

Use `httptest.NewServer` to stand up a fake Protected Resource + Authorization
Server:

| Test | Asserts |
|---|---|
| `TestServeRemote_DiscoversViaWWWAuthenticate` | A 401 with `WWW-Authenticate: Bearer resource_metadata=...` drives `serveRemote` to fetch PRM then AS metadata via the existing `protocol/authorization` helpers — no hardcoded URL. |
| `TestServeRemote_TokenRequestIncludesValidDPoPProof` | The fake AS's `/token` handler independently reconstructs and verifies the DPoP proof (its own `jkt` thumbprint check against the presented `jwk`) — proves correctness from the server's point of view. |
| `TestServeRemote_RefreshesOnExpiryAndNonce` | Fake AS returns a `DPoP-Nonce` header on first token attempt; `serveRemote` retries with that nonce in the next proof; an expired access token triggers a refresh-token exchange without a full re-discovery. |
| `TestServeRemote_RejectsReplayedProof` | Fake AS tracks `jti`s and 400s a replay; test asserts `serveRemote` does not silently retry with the *same* proof (it must mint a new one or surface the error). |
| `TestServeRemote_HandlesInvalidDPoPProofErrorCode` | Fake AS returns `400 invalid_dpop_proof`; `serveRemote` surfaces the error and does **not** retry with the identical proof (distinct from the `use_dpop_nonce` retry case above — this asserts the two error codes are handled differently). |
| `TestServeRemote_DeniedToolNeverReachesOutboundRequest` | With policy denying a tool, assert the fake remote server receives **zero** HTTP requests for that call (not just that the response is a denial) — the invariant is enforcement-before-dial, not response-filtering-after. |
| `TestServeRemote_SecretsNeverInAuditOrError` | Force an error path (e.g. fake AS 500s) and assert the client_secret/refresh_token/DPoP-private-key material never appears in the resulting audit record, trace, or returned error string. |
| `TestServeRemote_ThreeWayBackendExclusivity` | `config.go`'s `loadConfig`: a `Backend` with zero of `{Stdio,HTTP,Remote}` set, and one with two-or-more set, both fail to load with a clear error — table-driven over all invalid combinations. |

**Integration (may be `t.Skip` outside a tagged integration run, matching
repo convention for anything needing real processes):**

| Test | Asserts |
|---|---|
| `TestRemoteBackend_EndToEnd` | `cmd/mcpecho` fronted by a minimal local test OAuth+DPoP server; a real `tools/call` through `serveRemote` succeeds and produces exactly one audit record, attributed to the correct backend name, indistinguishable in shape from a stdio/http backend's record except for backend kind. |

---

## Feature C0 — DPoP verification primitive (new section)

**New file: `policy/dpopverify_test.go`**

This is the section the first draft was missing entirely. Every check in
`docs/spec/OAUTH-STANDARDS-dod.md`'s C0 block gets its own test — verification
correctness must be proven by meshmcp's own verifier, not inferred from a
test fake.

| Test | Asserts |
|---|---|
| `TestVerify_ValidProofAccepted` | A correctly constructed proof (matching request, fresh `iat`, correct `jkt`/`ath`, unused `jti`) verifies successfully — the baseline positive case every negative case below is a variant of. |
| `TestVerify_AlgConfusionRejected` | A proof whose JWT header claims `alg: none` or `alg: HS256` (or any value other than the pinned `ES256`) is rejected regardless of whether the signature bytes happen to validate under some interpretation — the pin, not the header, decides the algorithm. |
| `TestVerify_WrongJKTRejected` | A structurally valid, correctly-signed proof whose `jwk` thumbprint does **not** match the access token's bound `cnf.jkt` is rejected — asserted as a *distinct* test case from "invalid signature," since this is the actual sender-constraint check, not a signature check. |
| `TestVerify_HTUMismatchRejected` | A valid proof built for a different URL (or method) than the actual request is rejected; a sub-case asserts the documented normalization rule (e.g. query string excluded) behaves as specified, not accidentally stricter or looser. |
| `TestVerify_StaleIatRejected` | A proof with `iat` older than the pinned max-age (e.g. >300s) is rejected; a proof with `iat` slightly in the future beyond the skew allowance is also rejected. |
| `TestVerify_FreshIatWithinSkewAccepted` | A proof with `iat` within the pinned skew window (including a few seconds in the future, within tolerance) is accepted — proves the window isn't accidentally zero-tolerance. |
| `TestVerify_ReplayedJTIRejected` | The same `jti` presented twice within the freshness window: first accepted, second rejected. |
| `TestVerify_JTIRetentionBounded` | The replay store's memory usage does not grow unboundedly under a long-running stream of unique `jti`s — entries older than the freshness window are evicted (assert via store size, not wall-clock timing). |
| `TestVerify_RestartReplayWindow` | Simulates a verifier restart (fresh in-memory store) and confirms a proof captured before restart, still within its freshness window, **can** replay after restart — this is the accepted, documented residual risk (`docs/spec/OAUTH-STANDARDS.md`), asserted explicitly so it's a known, tracked behavior rather than a silent gap; a second assertion confirms a proof **outside** its freshness window is rejected post-restart regardless. |
| `TestVerify_AthMismatchRejected` | A proof whose `ath` claim does not match SHA-256(actual presented access token) is rejected on a resource request. |
| `TestVerify_NonceRequiredAndSingleUse` | First request without a nonce gets `WWW-Authenticate: DPoP error="use_dpop_nonce"`; a retry with the issued nonce succeeds; a second request reusing the same (already-consumed) nonce is rejected. |
| `TestVerify_NonceExpiry` | A nonce presented after its TTL has elapsed is rejected, prompting a fresh `use_dpop_nonce` challenge rather than being silently accepted. |
| `TestVerify_ErrorResponseShapeIsSpecCompliant` | Rejections surface `invalid_dpop_proof` (or `use_dpop_nonce` where applicable) in the wire format a compliant client expects — cross-checked against Feature B's own client-side handling of these codes. |

**Interop test (new, bridges B and C0 directly):**

| Test | Asserts |
|---|---|
| `TestDPoP_ClientServerInterop` | Feature B's `serveRemote`/DPoP signer, talking directly to Feature C0's verifier (no fake AS in between), completes a full discovery→token→resource-call cycle successfully — proves the two components are actually compatible, not just independently self-consistent against their own test fakes. |

---

## Feature C1 — DCR registration + management store

**New file: `federation/dcr_test.go`** (or `policy/clientregistry_test.go` if
the store is implemented in `policy/` — match wherever the store code
actually lands)

| Test | Asserts |
|---|---|
| `TestDCR_RegisterRequiresValidInitialAccessToken` | `POST /oauth2/register` without a token, or with one lacking `client:register` scope, is rejected before touching the store. |
| `TestDCR_RegisterPersistsHashedTokenOnly` | After registration, the on-disk file for that `client_id` contains a bcrypt hash, never the raw `registration_access_token` — read the file directly in the test and assert the raw token string is not a substring of the file contents. |
| `TestDCR_BcryptCostFactorPinned` | The stored hash's cost factor matches the documented configured value (e.g. 12) — a regression guard against someone later "tuning" it without updating the doc. |
| `TestDCR_LongTokenPreHashedBeforeBcrypt` | A `registration_access_token` longer than 72 bytes still produces a verifiably distinct hash from a different long token sharing the same first 72 bytes — proves the SHA-256 pre-hash step actually runs (guards against silent bcrypt truncation). |
| `TestDCR_RegisterFilePermsAndAtomicWrite` | New client file is `0600` in a `0700` dir; a crash-simulated partial write (kill mid-write in test harness, or assert via the rename-based API surface) never leaves a half-written file visible under the real `client_id` path. |
| `TestDCR_ManageRequiresMatchingToken` | `GET/PUT/DELETE /oauth2/register/{client_id}` with a wrong or malformed `registration_access_token` is rejected — asserted **behaviorally** (wrong/malformed tokens are consistently rejected; timing variance across many trials stays within a documented tolerance), not by asserting a specific Go function was called. |
| `TestDCR_DeleteRefusesInternalClient` | A record seeded with `registration_source="internal"` cannot be deleted via the DCR path under any presented token, including one crafted to match if the hash comparison were (incorrectly) skipped — i.e. this test must fail loudly if someone later "simplifies" the check. |
| `TestDCR_DeleteRefusesOnUnreadableRecord` | A record file that is corrupted/unparseable, or missing `registration_source` entirely, causes DELETE (and PUT) to be **refused**, not defaulted to "not internal" — this is the P0-3-class fail-closed test the first draft was missing. |
| `TestDCR_DeleteAllowsDCRClient` | A record with `registration_source="dcr"` and a correct token **can** be deleted — proves the refusal above is source-gated, not a blanket delete-disable bug. |
| `TestDCR_RegistrationQuotaEnforced` | Registering more than the configured per-initial-access-token cap of live `client_id`s is rejected once the cap is hit — new test, closes the disk-exhaustion gap. |
| `TestDCR_MaxBytesReaderEnforced` | An oversized request body to `/register` is rejected before full-body processing (mirrors the existing S26 test pattern for `/v1/approve`/`/v1/deny`). |
| `TestDCR_SlowlorisTimeoutEnforced` | A deliberately slow-trickling request against `/register` is cut off by `ReadHeaderTimeout`/`ReadTimeout` (mirrors S27). |
| `TestDCR_AuditWriteFailureDeniesRegistration` | Simulated audit-sink failure during a registration causes the registration itself to fail (F22 fail-closed semantics) — no client record is created without a corresponding landed audit entry. |

---

## Feature C2 — RFC 8693 exchange + RAR mapping

**New file: `federation/exchange_test.go`**

| Test | Asserts |
|---|---|
| `TestExchange_RejectsRequestWithoutDPoP` | A token-exchange request with no `DPoP` header (or an invalid proof, verified via C0) is rejected before the subject token is even parsed — fail closed, ordering matters. |
| `TestExchange_RejectsPlainBearerAtTokenEndpoint` | A request shaped like a normal token request but missing the DPoP proof is rejected — the literal "no plain bearer at issuance/exchange" invariant, tested directly. |
| `TestExchange_SubjectTokenAudienceConfusionRejected` | A structurally valid, correctly-signed subject token whose `aud` does **not** include meshmcp's exchange identity is rejected — this is the Critical-severity finding from review; a passing test here is the single most important new test in this document. |
| `TestExchange_SubjectTokenWrongIssuerRejected` | A subject token from an unpinned or mismatched issuer for the claimed org is rejected. |
| `TestExchange_SubjectTokenExpiredOrNotYetValidRejected` | `exp` in the past or `nbf` in the future on the subject token itself causes rejection, independent of the exchange-token's own expiry logic. |
| `TestExchange_IssuerCollisionDoesNotCrossOrgBoundary` | Two orgs configured with subject principals that happen to share a string value: a token correctly attributed (by validated issuer) to org A never resolves to org B's grant, and the new token-based `Mapping` match form does not fall through to the existing `"*"` wildcard. |
| `TestExchange_AuthorizationDetailsMapToCapabilityClaims` | A valid `authorization_details` array (tools + corpora + backend) maps onto `CapabilityClaims` fields exactly via `Signer.IssueCapability` — not `DelegationToken`. |
| `TestExchange_UnknownFieldInKnownTypeRejected` | An `authorization_details` entry of an accepted `type` but carrying one additional, unrecognized field causes the **whole request** to be rejected (400) — this is the strengthened RAR guarantee; a passing test distinguishes "reject unknown type" (weaker, insufficient) from "reject unknown field within a known type" (required). |
| `TestExchange_UnknownTypeRejected` | An `authorization_details` entry of a `type` outside the closed enumerated set is rejected outright. |
| `TestExchange_MultiEntryUnionThenIntersect` | Multiple `authorization_details` entries combine as a union of requested grants, and that union is then intersected against the org's configured `Grant` — both steps asserted separately (a test where the union alone would exceed the org grant, proving the intersection step actually clips it). |
| `TestExchange_ScopeIntersectsOrgGrant` | Partner requests broader `authorization_details` than its org's configured `Grant.Tools`/`Grant.Corpora`; the minted internal token is scoped to the intersection, never the wider requested set. |
| `TestExchange_MintedCapabilityLifetimeCapped` | The exchange path's minted `CapabilityClaims` never exceeds whichever ceiling the implementation records (exported `MaxDelegationLifetime`, existing `maxCapLifetime`, or a new federation-specific cap) — a direct test of the DoD item that was previously unenforced/untested. |
| `TestExchange_CallsExistingIssueCapabilityNotADuplicate` | (White-box, retained deliberately — this is a defensible anti-drift guard, not brittle over-specification) the exchange path's minted token is byte-for-byte producible by `policy.Signer.IssueCapability` given the same claims — guards against a future duplicate token-minting implementation drifting from the original. |
| `TestExchange_DoesNotInvokeDelegationPath` | Confirms the exchange path never calls `IssueDelegation`/`AuthorizeDelegated` — guards against the first draft's incorrect token-shape choice silently reappearing. |

**Regression — must still pass unchanged after Feature C2 lands:**

| Existing suite | Expectation |
|---|---|
| `policy/delegation_test.go` | Every existing case (forged origin, wrong backend/audience/router, changed args, expiry + lifetime cap, replay, nested hops, compromised-router-widening, bidirectional intersection) still passes verbatim — this feature does not touch delegation at all, so this is a pure no-op regression check. |
| `federation/boundary_test.go` | Every existing `OrgFor`/mapping case still passes verbatim; the new issuer-keyed `Mapping` match form is additive only and does not alter pubkey/FQDN resolution. |

---

## Feature C3 — Wire into `federate.go`

**New file: `federate_facade_test.go`** or extension of `federate_test.go`

| Test | Asserts |
|---|---|
| `TestFacade_DisabledLeavesFederateUnchanged` | With the façade config flag off, `federate.go`'s behavior is byte-for-byte identical to the pre-C3 baseline (run the existing `federate_test.go` suite against the wired binary with the flag off). |
| `TestFacade_EndToEndThroughBuildBoundaryServer` | The full C0→C1→C2 lifecycle (register, DPoP-gated token issuance, exchange, mint) driven through the actual `buildBoundaryServer` wiring, not the standalone module — the first time these components are exercised together in the real request path. |
| `TestFacade_ExistingMeshPeerPathUnaffected` | An ordinary mesh-peer federation call (via `OrgFor`'s existing pubkey/FQDN resolution) behaves identically whether or not the façade is enabled. |

**End-to-end lifecycle test (`federation/facade_e2e_test.go` or similar,
spanning C0–C3):**

1. DCR-register a test client → get `client_id` + `registration_access_token`.
2. Request a token with an `authorization_details` grant request + valid
   DPoP proof (verified by C0).
3. Exchange a **valid, correctly-audienced** external subject token for an
   internal `CapabilityClaims`.
4. Confirm a **wrongly-audienced** subject token is rejected in the same
   flow (the Critical-finding regression, run end-to-end not just unit-level).
5. Attempt to delete the DCR-registered client with its own token →
   succeeds.
6. Attempt to delete a seeded `internal` client with a forged/any token, and
   separately with a corrupted record → both fail.
7. Confirm `AuthorizeDelegated` and `policy/delegation_test.go`'s existing
   cases are entirely unexercised by this flow (this feature is
   capability-based, not delegation-based) — a negative assertion that no
   delegation code path fired.

---

## Cross-cutting

- **Fuzz target (recommended, matching `policy/filter.go`'s existing fuzz
  coverage style):** fuzz the DCR registration JSON parser and the
  `authorization_details` mapper — both parse attacker-influenced JSON from a
  party that, by definition, isn't a trusted mesh peer. Given C0/C1/C2 are
  the plan's highest-risk, externally-reachable parsers, this is upgraded
  from "optional" to "expected before C1/C2 are marked done."
- **`govulncheck`** (already tracked as S33 in `docs/ROADMAP-HARDENING.md`,
  itself still backlog) must be run against any new third-party JWT/JOSE or
  bcrypt dependency this work introduces, before it's added to `go.mod`; a
  license check (permissive only, per the design doc) accompanies it.
- **DoS / exposure-model tests are first-class, not cross-cutting
  afterthoughts,** for C1/C2 specifically, given both are reachable by
  parties with no mesh membership at all — see the rate-limit/quota tests
  under C1 above; do not treat these as optional hardening to add later.
- **Red-team regression naming:** per the repo's stated convention ("a
  session-takeover repro before F23, a malformed-window fail-open before
  S16"), each test above that encodes a specific attack (replayed DPoP proof,
  alg/key confusion, audience confusion, internal-client deletion, plain-bearer
  acceptance, scope-widening via `authorization_details`, unknown-field
  smuggling in a known RAR type) should be named so it reads as the attack it
  prevents, not just the function it calls — the table above already follows
  this; keep it consistent as the suite grows.
