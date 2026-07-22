# OAuth Standards Integration — Definition of Done

Companion to `docs/spec/OAUTH-STANDARDS.md` (design) and
`docs/spec/OAUTH-STANDARDS-tests.md` (test plan). Each feature is done only
when every item below holds — not "code compiles," but "the invariant the
feature exists to provide is proven, not asserted."

> **Revision note.** This revision follows two independent review passes on
> the first draft. The single biggest change: Feature C is now four
> sub-features (C0 DPoP verifier, C1 DCR store, C2 exchange+RAR, C3 wiring),
> each with its own sign-off, because the first revision assumed a DPoP
> "verification side" that no section actually specified. This revision also
> scopes the "never a bearer token" rule against its own DCR bootstrap
> (previously self-contradictory), adds fail-closed rules mirroring the
> existing P0-3/F22 precedent, adds rate-limiting requirements, and replaces
> white-box "asserts this exact function was called" test requirements with
> behavioral ones.

Repo-wide gate for all features (per `docs/ROADMAP-HARDENING.md`
"Verification"):
`CGO_ENABLED=1 go build ./... && CGO_ENABLED=1 go vet ./... && CGO_ENABLED=1 go test ./... -race`
must stay green after each feature lands, not just at the end.

**Gating precondition for C0–C3 (new):** the exposure-model question in
`docs/spec/OAUTH-STANDARDS.md` ("The exposure-model question") must be
explicitly resolved and recorded (either the recommended second-listener
design, or "rejected, out of scope") **before any C0 code is written.** This
is a sign-off item, not a code item — record it in
`docs/spec/OAUTH-STANDARDS.md` itself (replacing the "requires explicit
operator/product sign-off" language with the actual decision) before
proceeding.

---

## Feature A — SPIFFE identity labels

**Code**
- [ ] `config.go`: `Config.TrustDomain string` added; absent/empty is valid
      (labeling is skipped, never fatal — this is a label, not a control).
      Validated at load (SPIFFE trust-domain DNS-label shape) when non-empty.
- [ ] `policy/audit.go` (or a small new file): `type SpiffeLabel string`
      defined; `SpiffeID(trustDomain string, peerKeyBase64 string) SpiffeLabel`
      implemented — **plain return, no error** (decided explicitly, see
      design doc's "Signature decision"); decodes standard-padded base64
      (`base64.StdEncoding`) and re-encodes with `base64.RawURLEncoding`
      before composing the URI; malformed key or empty trust domain returns
      `SpiffeLabel("")`.
- [ ] `AuditRecord` gains
      `PeerSpiffeID SpiffeLabel \`json:"peer_spiffe_id,omitempty"\`` appended
      **after all existing fields (after `Hash`)** — field order unchanged
      for every pre-existing name.
- [ ] `federation/boundary.go`: `Mapping.TrustDomain` (`omitempty`) added;
      `Boundary` builds an org→trust-domain map in `NewBoundary` alongside the
      existing `principal` map; **collision check** at construction — two
      orgs configured with the same non-empty `TrustDomain` is flagged
      (reject or warn, operator-configurable) rather than silently accepted.
      `Boundary.SpiffeID(org, peerKey string) SpiffeLabel` added next to
      `Principal()`; returns `""` when no stable peer key is available (e.g.
      FQDN-glob-mapped peers).
- [ ] **Which-trust-domain-applies rule is enforced by call site, not
      convention**: local-gateway audit records only ever call `SpiffeID`
      with `Config.TrustDomain`; federation-crossing audit records only ever
      call `Boundary.SpiffeID` with the org's `Mapping.TrustDomain`. No
      code path passes `Config.TrustDomain` into a federation record or
      vice versa.
- [ ] No existing exported signature in `policy/audit.go` or
      `federation/boundary.go` changed (only additive fields/methods).

**Docs / schema (this directory's stated contract, `docs/spec/AGENTS.md`)**
- [ ] `docs/spec/AUDIT-RECORD.md` updated with the new field, **including the
      mixed-fleet compatibility note**: an old verifier binary re-serializing
      a new-format record (with `peer_spiffe_id` set) without knowing the
      field will hash-mismatch; verifier and writer binaries must be upgraded
      together across this field addition.
- [ ] `docs/spec/audit-record.schema.json` updated (`peer_spiffe_id`,
      optional, string) — schema has `additionalProperties: false`, so
      omitting this makes every future record with the field
      schema-invalid.
- [ ] `docs/CAPABILITY-MATRIX.md`: row added or updated marking SPIFFE
      labeling **Planned → Beta** once landed with tests.

**Invariants preserved**
- [ ] A record with `PeerSpiffeID` unset (no `TrustDomain` configured)
      verifies identically to today under the existing hash-chain
      verifier — proves the field is truly `omitempty` end to end, not just
      in the struct tag.
- [ ] Enforcement decisions (`policy.Engine`, `acl.go`) do not read
      `PeerSpiffeID`/`SpiffeID()` anywhere — grep-checked **and** structurally
      guarded by the distinct `SpiffeLabel` type (a decision function
      accepting it where a `Caller`/pubkey string is expected is now a
      compile error, not just a grep-miss).

**Sign-off:** unit tests below pass, hash-chain regression suite unaffected,
schema round-trips a record with and without the field, trust-domain
collision check exercised.

---

## Feature B — Outbound OAuth 2.1 client + DPoP (signer/client side only)

**Scope reminder:** Feature B owns DPoP proof **construction**
(client/signer side) only. It does not implement or claim to implement
verification — that is Feature C0, scoped separately below. Do not mark
Feature B done based on "the fake AS in the test verified it" standing in for
an owned verifier; that is correct coverage for B's own client behavior and
insufficient for anything C depends on.

**Code**
- [ ] `config.go`: `Backend.Remote *RemoteBackendConfig` added; the
      exactly-one-of check at `loadConfig` (~line 246-248) extended to
      three-way (stdio / http / remote) and rejects zero-of and two-or-more-of
      configurations at load, not at first call.
- [ ] `remotebackend.go`: `serveRemote` factory implemented; performs PRM/AS
      discovery via the existing `protocol/authorization` helpers (no
      duplicate discovery logic introduced elsewhere).
- [ ] `policy/dpopsign.go`: ECDSA P-256 `DPoPSigner` with
      `GenerateDPoPSigner`/`SaveDPoPSigner`/`LoadDPoPSigner` mirroring
      `policy/sign.go`'s on-disk convention (0600, atomic write) —
      **but using a distinct on-disk key-file type carrying an explicit
      `"key_type":"dpop-es256"` discriminator**, never the same `keyFile`
      shape as `policy/sign.go`'s Ed25519 signer.
- [ ] DPoP proof construction covers RFC 9449 §4.2 required claims: `htu`,
      `htm`, `iat`, `jti`, and — when the AS returns one — `nonce`; the
      `ath` claim is included on resource requests (§4.3).
- [ ] `serveRemote` recognizes and correctly handles both
      `WWW-Authenticate: DPoP error="use_dpop_nonce"` (retry with the
      supplied nonce) and `400 invalid_dpop_proof` (surface and stop — never
      blindly retry with the identical proof).
- [ ] Token/refresh-token/DPoP-private-key storage goes through the existing
      `secrets.Store`/`secrets.Broker` (`secrets/broker.go`) — no new
      credential store type introduced.
- [ ] Refresh-token rotation on-disk write is atomic (tmp file + rename),
      matching `cmd/vault/main.go`'s `rotate()`.
- [ ] DPoP private key lifecycle is explicit: missing/unloadable key file at
      startup for a backend configured to use one is **fatal** (matches S13's
      "missing signing key is fatal" precedent) — never silently regenerated.
- [ ] `httpEnforcer` (F16, `httppolicy.go`) still governs the **inbound**
      (mesh-facing) side of a `remote` backend exactly as it does an `http`
      backend — same policy/audit/capability code path, verified by a shared
      test helper if one already exists for F16.
- [ ] Outbound `http.Client` follows house style: fixed `Timeout`, injected
      via a `Doer`-shaped interface (mirroring `control/netbird.go:15`) so
      tests can substitute a fake transport; no retry loop added (matches
      every existing outbound caller in the repo).

**Docs / schema**
- [ ] `docs/spec/AGENTS.md`-style note or new doc: `Remote` backend config
      shape documented (fields, required secrets keys) — operators need this
      to configure it; put it wherever `docs/spec/` or `docs/` documents the
      `HTTP`/`Stdio` backend kinds today (extend that same doc rather than
      creating an orphan page, if such a doc exists — check
      `docs/for-operators/meshmcp-gateway/backends.mdx` in the docs site
      tree first).
- [ ] `docs/CAPABILITY-MATRIX.md`: new row, "Remote OAuth-protected MCP
      backend (DPoP client)" — **Planned** until tests land, then
      **Experimental/Labs** at minimum (do not mark Stable/Beta without the
      red-team regression below).
- [ ] `docs/ROADMAP-HARDENING.md`: add **F34** with a one-line description and
      file pointers, matching the existing flagship-entry format.
- [ ] New dependency (if a JOSE library is adopted rather than hand-rolled
      signing): license confirmed permissive (MIT/BSD/Apache-2.0), added to
      `go.mod`, and passed through `govulncheck` before merge.

**Invariants preserved**
- [ ] A `remote` backend cannot bypass the tool/method policy engine — a
      denied tool call never reaches the outbound HTTP request
      (test asserts the fake AS/backend receives zero calls for a denied
      tool).
- [ ] Secrets (client_secret, refresh token, DPoP private key) never appear
      in the audit log, trace, or an error message — reuse the existing
      response-side redaction path (per `docs/THREAT-MODEL.md` adversary #5)
      or prove a new equivalent exists for this backend kind.
- [ ] A DPoP proof is never reused across two distinct HTTP requests (unique
      `jti` per request, checked against the AS's own replay behavior in the
      test fake).

**Sign-off:** fake-AS test suite green (discovery, token issuance, DPoP proof
shape, refresh, nonce/error-code handling as a *client*), one real end-to-end
drive against `cmd/mcpecho` fronted by a minimal local OAuth+DPoP test
server, denied-tool red-team test passes, secrets-redaction test passes,
refresh-token and DPoP-key-file atomicity tests both pass (previously an
orphan item with no test — now required).

---

## Feature C0 — DPoP verification primitive (new sub-feature)

**Code**
- [ ] `policy/dpopsign.go`: a verifier type/function distinct from the
      Feature-B signer type, implementing each of the following as a
      separately named, independently testable step (not one opaque
      `Verify(proof) bool`):
  - [ ] Algorithm pinned to `ES256` by verifier configuration; the proof's
        own `alg` header is checked against the pin, never used to select
        behavior.
  - [ ] `typ`, `htu` (exact match, normalization rule documented and
        implemented consistently), `htm`, non-empty `jti`.
  - [ ] `iat` freshness window enforced with a **pinned concrete default**
        (±60s skew, ≤300s max age, or the implementer's justified
        alternative — but a default must exist and be documented, not left
        open).
  - [ ] `jkt` (RFC 7638 JWK thumbprint) of the proof's embedded `jwk` equals
        the `cnf.jkt` bound to the presented access token.
  - [ ] `ath` claim on resource requests equals base64url(SHA-256(access
        token)).
  - [ ] Replay store records every verified `jti`; retention bounded to the
        freshness window (§`iat` check) + skew, so memory is bounded; a
        repeated `jti` within that window is rejected.
- [ ] Server-issued `DPoP-Nonce` lifecycle: nonce issued via
      `WWW-Authenticate: DPoP error="use_dpop_nonce"` on a nonce-less/stale
      request; nonce is **single-use** (consumed on first valid presentation,
      tracked in the same bounded store as `jti`); nonce TTL pinned
      (recommended 300s).
- [ ] Verifier emits `invalid_dpop_proof` / `use_dpop_nonce` error responses
      per the RFC 9449 wire contract, consumable by Feature B's own client
      handling (cross-checked in an integration test where B's client talks
      to C0's verifier directly).
- [ ] Replay-store durability decision recorded: in-memory (accepted bounded
      residual risk across restart, documented) by default, with a
      documented option to back it with durable storage if an operator's
      threat model requires surviving a replay across a restart.
- [ ] **Domain separation from `policy/sign.go`'s Ed25519 verify path is
      structural**: no shared verify function or type between the DPoP
      (ES256) and capability/delegation (Ed25519) signature checks.

**Docs**
- [ ] `docs/ROADMAP-HARDENING.md`: add **F35** (DPoP verification primitive)
      referencing this DoD block and `policy/dpopsign.go`.
- [ ] `docs/CAPABILITY-MATRIX.md`: new row for the verifier itself, distinct
      from the Feature B client-side row.

**Invariants preserved**
- [ ] A proof with `alg` set to anything other than the pinned `ES256`
      (including `none`) is rejected regardless of what the rest of the
      proof contains.
- [ ] A proof whose `jkt` does not match the presented access token's `cnf`
      is rejected even if every other claim is valid — this is the
      sender-constraint itself; a test must exercise "valid proof, wrong
      key" as a distinct case from "invalid proof."
- [ ] A replayed `jti` within the freshness window is rejected on the second
      presentation, even if the two presentations are for the same
      otherwise-valid request.

**Sign-off:** every check above has its own passing test (see test plan);
an integration test where Feature B's client and Feature C0's verifier
interoperate directly (no fake AS in between) passes; the alg-confusion and
key-confusion tests specifically pass (these are the two checks a senior
reviewer flags first on any DPoP implementation).

---

## Feature C1 — DCR registration + management store

**Code**
- [ ] New DCR endpoints (`POST /oauth2/register`, `GET/PUT/DELETE
      /oauth2/register/{client_id}`) implemented as a boundary-scoped HTTP
      surface, separate from `control/control.go`'s role-gated enrollment
      (different threat model — do not merge the two), and bound to the
      distinct listener/TLS surface required by the exposure-model
      resolution in the design doc.
- [ ] Initial-access-token gate enforces a `client:register` scope before
      `POST /register` is accepted. **This bearer credential is a
      documented, scoped exception** (see design doc "Bearer-token
      exception") — not a violation to be silently tolerated.
- [ ] Client-registration store mirrors `policy/approval_token.go`'s
      `FileApprovalStore`: `0700` dir, one `0600` JSON file per `client_id`,
      atomic `os.Rename` on every state transition.
- [ ] `registration_access_token` stored **bcrypt-hashed** with an explicit,
      documented **cost factor (recommended 12)**, and the presented token is
      **SHA-256 pre-hashed before bcrypt** to avoid silent 72-byte truncation;
      verified via bcrypt's own compare function (behavioral requirement:
      "rejects a wrong/malformed token, in roughly constant time" — the test
      must assert behavior, not literally assert which Go function was
      called).
- [ ] Every stored client record has `registration_source` ∈
      `{"internal","dcr"}`; the DELETE path refuses (403 or 404 — pick one
      and document it) any record with `registration_source == "internal"`,
      **even given a technically-valid registration_access_token** for that
      record (confirm internal clients genuinely have no valid deletion
      token at all, rather than merely "usually" refused).
- [ ] **Fail-closed on read failure (new, closes the P0-3-class gap review
      found):** any read error, unparseable record, or missing/unrecognized
      `registration_source` on a mutating request (PUT/DELETE) results in
      refusal — never defaults to treating an unreadable record as
      `"dcr"`/deletable.
- [ ] **Rate-limiting/quota (new, required):** `http.MaxBytesReader` and
      `ReadHeaderTimeout`/`ReadTimeout` on every C1 endpoint (mirroring
      S26/S27); a per-initial-access-token cap on live registered
      `client_id` count; a request-rate limit on the bcrypt-bearing
      management path.
- [ ] **Fail-closed audit (new):** registration, management, and deletion are
      each an auditable state transition; an audit-write failure for that
      transition denies the operation (F22 semantics), never proceeds
      silently.

**Docs**
- [ ] Dedicated `docs/spec/DCR-FACADE.md` (mirroring
      `docs/spec/ROUTER-DELEGATION.md`'s Problem/Design/Status/Not-yet-wired
      structure) if the endpoint surface is complex enough to need its own
      request/response schema — otherwise this DoD block plus the design
      doc's C1 section suffices; decide at implementation time based on
      actual surface size.
- [ ] `docs/THREAT-MODEL.md`: the new "external non-mesh OAuth
      registrant/client" adversary (from the design doc's exposure-model
      section) documented with its own defended/limit bullets, not folded
      into an existing adversary's bullets.

**Invariants preserved**
- [ ] An admin-provisioned (`registration_source=internal`) client is
      unreachable by the DCR delete path under every code path that reaches
      it, including a request whose record read fails or is corrupted.
- [ ] Registration cannot be used to exhaust disk into an audit fail-closed
      cascade (bounded by the quota above; tested explicitly).

**Sign-off:** full CRUD lifecycle test green; internal-client-deletion
red-team test (including the read-failure variant) passes; rate-limit/quota
test passes; fail-closed audit test passes.

---

## Feature C2 — RFC 8693 exchange + RAR mapping

**Code**
- [ ] Token issuance/exchange at this boundary requires a DPoP proof
      (verified by C0) on every request; a request without one, or with an
      invalid one, is rejected **before the subject token is parsed at all**
      — ordering is a hard requirement, not an optimization.
- [ ] Subject-token validation, all four checks required (closes the
      Critical-severity gap review found):
  - [ ] Signature verified against a per-org **pinned** JWKS/issuer key.
  - [ ] Issuer matches the org's configured, pinned issuer.
  - [ ] Audience contains meshmcp's exchange endpoint identity.
  - [ ] `exp`/`nbf` validated independent of any exchange-token expiry
        applied afterward.
- [ ] Org resolution uses the validated **issuer**, via a new token-based
      `Mapping` match form in `federation/boundary.go` — this new match form
      does **not** inherit the existing `"*"` wildcard behavior in `OrgFor`;
      an unmapped issuer resolves to no org.
- [ ] `authorization_details` (RFC 9396) mapped onto **`CapabilityClaims`**
      fields (tools/corpora/backend/audience) via `Signer.IssueCapability` —
      **not** `DelegationToken`/`IssueDelegation` (corrects the first
      revision's wrong token-shape choice).
- [ ] RAR mapping is a **closed, enumerated set of accepted `type` values**,
      each decoded with strict unknown-field-rejecting parsing (an
      accepted-type entry with an unrecognized extra field rejects the whole
      request, not just that field).
- [ ] Multi-entry `authorization_details` semantics implemented as specified:
      union of requested grants across entries, then intersected against the
      org's configured `Grant.Tools`/`Grant.Corpora`.
- [ ] Minted `CapabilityClaims` lifetime capped per the decision recorded in
      the design doc (either `policy.MaxDelegationLifetime` exported, or
      `policy/capability.go`'s existing `maxCapLifetime`, or a new
      federation-specific, shorter ceiling — implementer states which and
      why, per the design doc's explicit flag).
- [ ] No parallel token-minting code path introduced — the exchange
      literally calls the existing `Signer.IssueCapability`.

**Docs**
- [ ] `docs/spec/OAUTH-STANDARDS.md` C2 section stays the source of truth for
      the mapping table; if it grows complex, extract into
      `docs/spec/DCR-FACADE.md` alongside C1.
- [ ] `docs/ROADMAP-HARDENING.md`: F31 extended to reference C2 specifically
      (subject-token validation, RAR closed-set mapping) alongside C1.

**Invariants preserved**
- [ ] A subject token valid for a different audience (a different SaaS
      integration at the same partner) is rejected — audience-confusion
      test is mandatory, not optional.
- [ ] A subject token whose subject string collides with a different org's
      principal does not resolve to that other org's grant (resolution is
      issuer-keyed, not subject-string-keyed).
- [ ] A partner cannot obtain a grant broader than its org's configured
      `Grant.Tools`/`Grant.Corpora` regardless of what its
      `authorization_details` requests.
- [ ] `AuthorizeDelegated`'s existing caller∩router intersection semantics
      (tested in `policy/delegation_test.go`) are **untouched** — this
      feature does not call `AuthorizeDelegated` at all, having moved to
      `CapabilityClaims`; the existing delegation test suite passes
      unchanged as a pure regression check, not because this feature
      exercises it.

**Sign-off:** full exchange lifecycle test (register via C1 → DPoP-gated
token request via C0 → validated exchange → minted `CapabilityClaims`) green;
audience-confusion and issuer-collision red-team tests pass; RAR
strict-rejection test passes; existing `policy/delegation_test.go` and
`federation/boundary_test.go` suites unaffected (run unchanged, still green).

---

## Feature C3 — Wire into `federate.go`

**Precondition:** C0, C1, and C2 are each independently implemented, tested,
and green in isolation **and** the exposure-model sign-off from the design
doc is recorded, before this sub-feature begins.

**Code**
- [ ] `federate.go`'s `buildBoundaryServer` gains the façade as an additional,
      config-gated entry point — existing mesh-peer `OrgFor` resolution path
      is untouched.
- [ ] The façade's listener remains distinct from the mesh interface per the
      exposure-model resolution — this sub-feature does not fold it into the
      mesh-only listener as a shortcut.

**Invariants preserved**
- [ ] Every existing `federation/boundary_test.go` case still passes
      verbatim after wiring.
- [ ] Disabling the façade (config flag off) leaves `federate.go`'s behavior
      byte-for-byte identical to pre-C3.

**Sign-off:** end-to-end test through the actual `federate.go` wiring (not
just the standalone C0-C2 module); full regression suite green; capability
matrix updated to reflect the now-wired status (still Experimental/Labs
until a red-team pass on the *wired* path specifically, matching the existing
convention that wiring is where confused-deputy risk actually materializes).
