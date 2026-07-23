# OAuth/DPoP/DCR/SPIFFE Integration — Final Report

Source specs: `docs/spec/OAUTH-STANDARDS.md`, `docs/spec/OAUTH-STANDARDS-dod.md`, `docs/spec/OAUTH-STANDARDS-tests.md`.
This report consolidates: the five implementation agents' own summaries, an independent status-verification pass (`docs/spec/OAUTH-STANDARDS-status.md`), a per-function verification pass against every named test in the tests doc, and two adversarial review passes (code review + security review) whose findings have already been reproduced against the live code, not just read.

## 1. Executive Summary

Across five parallel implementation slices, this run built: a SPIFFE identity-labeling primitive (Feature A — only the primitive; the wiring into `Config`/`federation.Boundary` that would actually make it emit labels never landed), an outbound OAuth 2.1 client with DPoP proof signing for a new `remote` backend kind (Feature B), a DPoP proof *verifier* with replay/nonce handling (Feature C0), an RFC 7591/7592 dynamic client registration and management store (Feature C1), and an RFC 8693 token-exchange facade with RFC 9396 (RAR) `authorization_details` mapping (Feature C2). All of B, C0, C1, and C2 are real, tested, and independently re-verified function-by-function against the tests doc, with the code review and security review below identifying concrete defects to fix before any of it is wired live. **Feature C3 — actually wiring any of this into `federate.go`'s live listener — was correctly not attempted.** It was gated on an explicit "exposure-model" product/operator decision (what may be reachable from outside the mesh, and under what authentication) that the design doc requires before C3 begins; that decision was never recorded in `docs/spec/OAUTH-STANDARDS.md` (it still reads as requiring sign-off), which also means Features C0–C2 were technically built ahead of their own stated gating precondition — they just weren't wired to anything reachable, which is why none of the findings below are live-exploitable today. Two further caveats apply globally: `go test ./... -race` could not run anywhere in this session (no C compiler in the sandbox), so nothing here has been raced; and this working tree experienced heavy concurrent-agent churn (shared docs like `CAPABILITY-MATRIX.md`/`ROADMAP-HARDENING.md`/`THREAT-MODEL.md` show last-writer-wins damage — only Feature C0's doc edits fully survived).

## 2. Feature Status

| Feature | What it is | Build | Vet | Tests (named in tests doc) | Status |
|---|---|---|---|---|---|
| **A** — SPIFFE identity labels | Derived `spiffe://<trust-domain>/peer/<key>` labels on audit records + federation crossings | clean | clean | 5 of 14 named tests exist and pass (`policy/spiffe_test.go`); the schema-check bullet is covered (`TestAuditRecordSchema_AllowsPeerSpiffeID`, passes). **9 of 14 named tests do not exist** — 4 audit hash-chain tests, 5 `Boundary.SpiffeID`/collision tests — because the underlying code they'd test (`Config.TrustDomain`, `Mapping.TrustDomain`, `Boundary.SpiffeID`, `NewBoundary` collision detection) was never added to `config.go`/`federation/boundary.go`. | **Partial — primitive only, unwired.** No SPIFFE label is emitted anywhere in the running system today. |
| **B** — Outbound OAuth 2.1 client + DPoP signer (`remote` backend) | Client-side DPoP proof construction, lazy discovery via `WWW-Authenticate`, client_credentials/refresh_token grants | clean | clean | 16 of 17 named tests exist and pass. Missing: `TestRemoteBackend_EndToEnd` (explicitly optional/skippable integration test per the tests doc; not implemented in any form, not even skipped). | **Done**, one optional test deferred. |
| **C0** — DPoP verification primitive | Server-side proof verification: alg pinning, htu/htm/iat freshness, jkt key-confirmation, ath, replay store, nonce lifecycle | clean | clean | All 14 named tests (13 unit + 1 client/server interop) exist and pass. | **Done.** Strongest-verified feature in this run. |
| **C1** — RFC 7591 DCR + RFC 7592 client management | Registration endpoint, bcrypt-hashed registration_access_token store, quota/rate-limit, fail-closed delete/manage | clean | clean | All 13 named tests exist and pass (plus 2 bonus tests beyond the named list). Missing: the cross-cutting fuzz target for the registration JSON parser, which the spec explicitly upgrades from optional to *required* before C1 is marked done. | **Functionally done, one required artifact missing** (fuzz target); see Section 4 for two concurrency defects found in this feature. |
| **C2** — RFC 8693 token exchange + RFC 9396 (RAR) `authorization_details` | Federation OAuth facade: DPoP-gated token exchange, subject-token validation, union-then-intersect scope mapping | clean | clean | All 14 named tests + both named regression suites (`policy/delegation_test.go` 10 cases, `federation/boundary_test.go` 3 cases) exist and pass. Missing: the same required fuzz target, and no dedicated DoS/body-size test analogous to C1's. | **Functionally done, one required artifact missing** (fuzz target); see Section 3 for a real authorization-logic defect found in this feature. |
| **C3** — Wire into `federate.go` | Making A–C2 reachable from a live listener | — | — | — | **Not attempted — correctly blocked.** Gating "exposure-model" decision was never recorded in the design doc. |

`-race` caveat applies to every row above: no C compiler was available anywhere in this session, so `CGO_ENABLED=1 go test ./... -race` could not run. All "pass" verdicts above are from plain (non-race) `go test -v` runs, re-executed independently during verification, not merely trusted from agent self-reports.

## 3. Code-Review Findings (surviving, most severe first)

### CRITICAL — `federation/dcr.go:567` — DELETE/PUT race resurrects a deleted client
**Category:** concurrency
A concurrent DELETE and PUT against the same `client_id` in `DCRStore.handleManage` can both pass token verification while the record still exists, then race on disk: if DELETE's `removeAtomic` completes first and PUT's `writeAtomic` completes after, the client record is silently recreated — **still carrying its old `registration_access_token` hash** — even though the caller who issued the DELETE received a clean `204 No Content`. Empirically reproduced (4–5 of 8 runs resurrected the client via a subsequent GET returning `200`). No lock of any kind guards `load`-then-write for a given `client_id`; the only mutex in the file (`rateLimiter.mu`) is unrelated. No existing test exercises concurrent management requests. Not live-exploitable today only because this handler isn't wired to any listener yet (Feature C3 deferred) — but the defect is real, in code that will be exposed the moment C3 lands.

### HIGH — `federation/exchange.go:217` — corpora intersection silently degrades to allow-all
**Category:** authz-logic
When an org's configured `Grant.Corpora` is empty, or a federation partner simply omits `datatypes` from its `authorization_details`, `intersectGranted`'s empty-result early-out (`if len(granted)==0 || len(requested)==0 { return nil }`) collapses both "org granted nothing" and "partner asked for nothing" to `nil`. Unlike the `tools` side (which has an explicit `len(tools)==0` reject at line 218), there is no equivalent reject for corpora — so the mint proceeds with `Corpora: nil`, and per `policy/capability.go`'s `AllowsCorpus`, a nil/empty `Corpora` list means **no restriction at all**, i.e. access to every corpus. Reproduced directly: a `Grant{Org:"acme", Tools:["search"]}` with zero `Corpora` entries, hit with a request that omits `datatypes`, mints a real, verifiable capability whose `AllowsCorpus("anything-at-all")` returns `true`. This directly contradicts the design doc's stated intersection semantics and is inconsistent with `federation/boundary.go`'s own `CheckCorpus`, which documents the opposite convention ("empty grant means no corpus is shared") for the identical config field. Not caught by any existing `TestExchange_*` test. Same "unwired until C3" caveat on live exploitability applies, but the logic bug is real and reachable in code today.

### HIGH — `federation/dcr.go:462` — registration quota is a TOCTOU that concurrent requests bypass
**Category:** concurrency-toctou
`handleRegister`'s per-initial-access-token quota (`liveCountForIssuer` → check → `writeAtomic`) has no lock serializing registrations for the same issuer token. K concurrent registrations under one token all observe the pre-write count and all pass the `n >= maxClients` check before any of them persists. Reproduced deterministically: 8 concurrent requests against a `MaxClients:2` store landed 8 live client records in every one of 8 repeated runs (0/8 correctly capped). Because the bcrypt hashing step (~100–300ms at cost 12) sits between the read and the write, this triggers under ordinary concurrent load, not just adversarial timing. This is the *only* disk/inode bound on the registration path (the management path has a rate limiter; registration does not), and because the race is on filesystem state read independently per goroutine rather than a shared Go variable, `-race` would not catch it even if it could run here.

### MEDIUM — `federation/dcr.go:462` — same underlying defect, independently re-derived at lower severity
**Category:** concurrency-toctou
A second, independently-run reviewer pass reproduced the identical quota-bypass mechanism above and rated it Medium rather than High (both reports agree on cause and reproducibility; they differ only in severity judgment, likely reflecting the "not yet wired to a live listener" mitigation). Retained here rather than merged, since it corroborates the finding via a second independent reproduction (also empirically confirmed, also 100% reproducible across repeated runs).

## 4. Security-Review Findings (surviving, most severe first)

**One finding is HIGH severity — flagged explicitly, not buried:**

### HIGH — `meshmcp/remotebackend.go:262` — untrusted AS error field leaks secrets into local logs
**Category:** secret-exposure
`tokenErrorFromBody`'s doc comment claims it surfaces "ONLY the standard OAuth error code — never the raw response body," but the implementation interpolates the token endpoint's free-form JSON `"error"` field verbatim into the returned/logged error string with no validation that it's actually one of the fixed RFC 6749 §5.2 codes. A malicious, compromised, or MITM'd remote authorization server can return e.g. `{"error":"invalid_client: client_secret s3cr3t-value rejected"}`, and that string propagates unmodified through `fetchToken → ensureToken → resourceCall → remoteHandler`'s `log.Printf`, writing the plaintext client secret (or a reflected refresh token) into the gateway's own local process logs. Empirically reproduced end-to-end with a real `httptest` AS and a real `remoteHandler`: the captured log line contained the injected secret verbatim, while the HTTP response returned to the calling mesh peer was unaffected (`502 remote backend unavailable`, no secret) — so this is a **local-log leak**, not a wire leak, but a real one. The existing test `TestServeRemote_SecretsNeverInAuditOrError` does not catch this because it only exercises a plain-text 500 response that never populates the `error` field.

### LOW — `federation/dcr.go:462` — same registration-quota TOCTOU as Section 3, re-confirmed from a security lens
**Category:** race-condition
This reviewer independently rated the identical defect as Low severity (included here at its own reported severity, not upgraded) — reproduced the same mechanism as the code-review findings above: an initial access token configured with `MaxClients: 1`, hit by 20 concurrent registration requests, landed 19–20 live client records across repeated runs. Cross-referenced against Section 3's Medium/High-rated instances of the identical bug: **three independent reviewer passes reproduced this exact defect**, disagreeing only on severity (Low/Medium/High). That disagreement should be read as a strong signal the underlying bug is real and worth fixing (see checklist below) regardless of where any single pass placed it on the severity scale — treat it at the higher end (High, per Section 3) for prioritization purposes.

## 5. Before This Ships — Checklist

> **Update 2026-07-23 (edge Phase 1 verification).** All Must-Fix and both
> C1/C2 "should-fix" items below are now **closed in-tree** (commit `c862c18`,
> re-verified this session), the exposure-model decision is **recorded**
> (commit recording extended Option A in `OAUTH-STANDARDS.md`), and the full
> module test suite was run **under `-race` with `CGO_ENABLED=1` on a host
> with gcc** — green after fixing two unrelated pre-existing stale
> `cmd/meshmcp` air-live assertions. The one item that could **not** be closed
> in this environment is `govulncheck`: the agent proxy denies
> `vuln.go.dev` (403), so the vulnerability database cannot be fetched here —
> it must be run in CI. Feature A's SPIFFE wiring remains open (out of scope
> for the edge work).

**Must fix (Critical/High, in order of severity):**
- [x] **CRITICAL** — Per-`client_id` locking added to `federation/dcr.go`'s `handleManage` (`s.keyed.lock("client:"+clientID)`, `dcr.go:590`; `keyedLocks`, `dcr.go:117-147`). Regression test `TestDCR_ConcurrentDeletePutNoResurrect` (`dcr_concurrency_test.go:67`). Verified green under `-race`.
- [x] **HIGH** — Corpora intersection now denies-by-default via `clampCorpora` + deny-all sentinel (`exchange.go:217`, `:528-542`). Regression test `TestExchange_EmptyCorporaDeniesByDefault` (`exchange_corpora_test.go:18`).
- [x] **HIGH** — `tokenErrorFromBody` whitelists the closed RFC 6749 §5.2 code set before surfacing (`rfc6749TokenErrorCodes`, `remotebackend.go:265`, gate at `:281`).
- [x] **HIGH** — Registration quota serialized by a per-issuer lock (`s.keyed.lock("issuer:"+issuerHashHex)`, `dcr.go:512`). Regression test `TestDCR_ConcurrentRegisterRespectsQuota` (`dcr_concurrency_test.go:40`).

**Blocking decision (not a code fix):**
- [x] Exposure-model decision **recorded** in `docs/spec/OAUTH-STANDARDS.md` — extended Option A: a second, off-by-default TLS ingress (`meshmcp edge`) that may carry exactly one tool-scoped MCP path for hosted MCP clients (claude.ai), with deviations D-A..D-D and compensating controls enumerated. THREAT-MODEL adversaries 12–13 and CAPABILITY-MATRIX rows added.

**Should fix before considering C1/C2 fully done (per the spec's own upgraded requirement):**
- [x] Fuzz targets present: `FuzzDCRRegisterMetadata` and `FuzzAuthorizationDetails` (`federation/fuzz_test.go:14`, `:31`).
- [x] C2 DoS/body-size test present: `TestExchange_OversizedBodyRejected` (`federation/fuzz_test.go:45`; `exchangeMaxBodyBytes`, `exchange.go:31`).

**Should fix before Feature A is considered real:**
- [ ] Feature A's federation-side wiring (`Config.TrustDomain`, `Mapping.TrustDomain`, `Boundary.SpiffeID`, `NewBoundary` collision detection) does not exist. Currently the SPIFFE primitive is unused dead code from the running system's perspective — no label is ever emitted. This needs a dedicated follow-up slice; treat prior claims of Feature A completion as inaccurate. **(Still open; out of scope for the edge/hosted-client work.)**

**Process / environment, before signing off on any of the above as fully verified:**
- [x] Full test suite re-run under `-race` with `CGO_ENABLED=1` on a host with gcc (2026-07-23). Green across the module after fixing two unrelated pre-existing stale air-live assertions in `cmd/meshmcp`.
- [ ] `govulncheck ./...` — **could not run in this environment**: the agent proxy denies `vuln.go.dev` (403), so the vuln DB cannot be fetched. Run it in CI (promote the existing advisory `govulncheck` step, `.github/workflows/ci.yml`, to required once the baseline is clean).
- [x] CAPABILITY-MATRIX / THREAT-MODEL bookkeeping consolidated for the edge decision in a single pass (this session).
