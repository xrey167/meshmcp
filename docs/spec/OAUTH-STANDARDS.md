# OAuth / DPoP / DCR / SPIFFE Standards Integration (Phase 10)

> **Revision note.** This is the second revision. The first revision was
> reviewed by two independent passes (a plan-quality critique and an
> adversarial security review); both converged on the same core gap: Feature
> C claimed to reuse "Feature B's DPoP verification side," which Feature B
> never actually specified — Feature B only builds a DPoP *signer* (the
> client side). Verifying a DPoP proof is where nearly every real security
> property lives (algorithm pinning, key-confirmation binding, replay
> tracking), and it had no owned design section, DoD item, or test. This
> revision fixes that, splits Feature C into independently-shippable
> sub-phases, scopes the "never a bearer token" rule against its own DCR
> bootstrap (which is unavoidably bearer-authenticated), and adds the
> exposure-model question that Feature C cannot proceed without answering.

## Context

meshmcp's core identity model is deliberately not OAuth: callers are identified
by the WireGuard/NetBird public key the transport proves (`acl.go`), never by a
caller-supplied header or bearer token (see `docs/THREAT-MODEL.md`,
"Positioning and trust boundaries"). A review was requested of whether a set of
IETF security standards — Dynamic Client Registration (RFC 7591/7592), DPoP
(RFC 9449), the OAuth 2.1 token-issuance grant suite, SPIFFE/WIMSE identity
URIs, On-Behalf-Of delegation (RFC 8693), and Rich Authorization Requests
(RFC 9396) — are useful for meshmcp, and if so, where.

The finding: none of them belong on the mesh-internal enforcement path, where
WireGuard + the existing signed-token primitives (`policy.CapabilityClaims`,
`policy.DelegationToken`, `policy.ApprovalToken`) already provide an equal or
stronger guarantee. They *do* have concrete value at the edges where meshmcp
already needs to interoperate with parties that are not, and may never be, a
WireGuard mesh peer: a third-party remote MCP server meshmcp calls out to, and
a partner organization at the federation boundary. This document scopes four
features at those edges, in build order.

**Central design rule, precisely scoped (see "Bearer-token exceptions"
below — the first revision stated this as an unqualified absolute, which
its own DCR bootstrap contradicted):** every token meshmcp **issues for tool
access, or accepts as authorization for a tool call**, is either DPoP-bound
(RFC 9449) or an existing Ed25519-signed meshmcp token
(`CapabilityClaims`/`DelegationToken`). This is what keeps the additions
consistent with "identity is cryptographic, never claimed" — a raw bearer
token is a claimed identity; a sender-constrained one requires proof of
possession on every use, the same shape of guarantee the WireGuard key already
gives. A small, explicitly enumerated set of *bootstrap* credentials (initial
access token, DCR management token) are bearer by necessity and are called out
as scoped exceptions with compensating controls, not swept under the rule.

**Explicit non-goal:** meshmcp does not become a general-purpose OAuth 2.1
Authorization Server serving arbitrary bearer-token clients over the mesh's own
tool-call path. That would duplicate and weaken the capability/delegation model
for no benefit and contradicts the product's positioning against
header/bearer-token gateways.

**Third-party dependencies.** This plan implies at least one JOSE/JWT library
(DPoP proof construction and verification) and a bcrypt implementation
(registration-token hashing). meshmcp is proprietary/read-only
(`LICENSE-DECISION.md`); any new dependency must be under a permissive license
(MIT/BSD/Apache-2.0 — no copyleft) and pass `govulncheck` (tracked as S33 in
`docs/ROADMAP-HARDENING.md`, itself still backlog — landing it is a
prerequisite, not a nice-to-have, once this plan introduces its first
third-party dependency). Hand-rolled JOSE *signing* is low-risk and consistent
with the repo's "fresh code, no untrusted code loaded" ethos; hand-rolled JOSE
**verification** is a known high-risk footgun (alg-confusion, key-confusion,
canonicalization bugs) — Feature C0 below should default to a vetted,
minimal, permissively-licensed library for the verify path unless a
hand-rolled implementation gets a heightened review and a dedicated fuzz
target on the proof parser.

---

## Feature A — SPIFFE identity labels (ship first)

**What.** Add a `spiffe://<trust-domain>/peer/<key>` URI as a *derived,
additive label* for every mesh identity, surfaced in audit records and
federation mappings. It is a display/interop label only — the WireGuard
public key remains the actual credential and the only thing enforcement
decisions key on.

**Why.** Cheap, zero trust-model risk, and it gives audit records and
cross-org federation a namespaced, standard identity string instead of a bare
platform-specific key — useful the moment a partner org runs its own
SPIFFE/SPIRE-based service mesh and wants to correlate identities. (WIMSE
covers similar ground via emerging IETF work; not building against it — its
current standardization status wasn't verified, so it's a "watch" item, not a
target.)

**Encoding decision.** The WireGuard/NetBird pubkey is standard base64
(confirmed in `acl.go:54` via `client.IdentityForIP`, and real examples in
`docs/reference.md`), not hex. Base64's standard alphabet (`+`, `/`) is
**not legal** in a SPIFFE path segment (`[a-zA-Z0-9._-]+`). Rather than
introduce a new encoding, decode the key to raw bytes and re-encode with
`base64.RawURLEncoding` — the same encoding `policy/capability.go` already
uses for its own tokens, and RFC-4648-§5 base64url without padding is fully
SPIFFE-legal. **Pin the decode side explicitly**: accept standard padded
base64 (`base64.StdEncoding`) as the input form, since that is what
`client.IdentityForIP` returns — do not silently also accept unpadded/URL
variants on input, to avoid two different raw-byte values round-tripping to
different-looking labels for what should be the same key.

**Signature decision (resolves an ambiguity found in review).**
`SpiffeID(trustDomain, peerKeyBase64 string) string` — a plain string return,
**no error**. A malformed key (fails to base64-decode) returns `""`, exactly
like an empty `trustDomain` does. This is consistent with "label, not
control": there is nothing to fail closed *on*, because nothing downstream
treats an empty label as meaningful. `federation.Boundary.SpiffeID` has the
same shape.

**Which trust domain applies to which record (resolves an ambiguity found in
review).** Two different trust domains exist and must not be conflated:
- `Config.TrustDomain` labels identities on **this gateway's own mesh** — used
  wherever `policy/audit.go` writes a `PeerKey` for a directly-connected mesh
  peer.
- `Mapping.TrustDomain` (per federated org) labels identities **crossing the
  federation boundary** — used only in the audit/record path that
  `federation/boundary.go` produces for a federated call. Note that
  `federate.go`'s boundary audit records key on `Peer: org`
  (`boundary.go`'s existing audit call), not a raw peer key — so
  `Boundary.SpiffeID(org, peerKey string) string` takes the **remote** peer
  key (when known, e.g. `"pubkey:<key>"`-mapped peers) and the **org's**
  configured trust domain, never the local gateway's `Config.TrustDomain`.
  For FQDN-glob-mapped peers with no stable individual pubkey, `SpiffeID`
  returns `""` — there is no peer key to label.
A local gateway record never uses `Mapping.TrustDomain`, and a federation
record never uses `Config.TrustDomain`. This must be enforced by which
function/call-site is used, not by convention alone.

**Type safety for the label.** Per review feedback, a bare `string` field
sitting directly beside the real `PeerKey` credential in `AuditRecord`
is one accidental `==`/policy-rule away from being misused as an identity
input. Define `type SpiffeLabel string` (in `policy/audit.go` or a small new
file) and use it for `AuditRecord.PeerSpiffeID` and the `Mapping.TrustDomain`
derivation — not to add behavior, but so that any future code path that tries
to compare or branch on it against a `policy.Caller`/`PeerKey`-typed value is
a compile error, not a silent grep-miss.

**Trust-domain format validation.** `Config.TrustDomain` and
`Mapping.TrustDomain` must be validated at config load (alongside the
existing `Policy.Validate()` glob/duration checks, S28 in
`docs/ROADMAP-HARDENING.md`) to be a syntactically valid SPIFFE trust domain
(lowercase DNS-label shape, no scheme, no path). Additionally, **flag (warn or
reject — operator's choice via config) any two `Mapping.TrustDomain` values
that collide** across different orgs, since a collision makes two distinct
orgs' audit SPIFFE IDs indistinguishable.

**Files:**
- `config.go` — add `TrustDomain string` to `Config` (alongside `Registry`/
  `Groups`, ~line 48-51): the gateway's own SPIFFE trust domain (e.g.
  `meshmcp.example.org`). Optional; SPIFFE labeling is skipped (fields left
  empty) if unset — no fail-closed behavior since this is a label, not a
  control. Validated at load per above if set.
- `policy/audit.go` — new small helper, colocated with `AuditRecord` (defined
  ~line 22-44): `func SpiffeID(trustDomain string, peerKeyBase64 string) SpiffeLabel`.
  Decodes the standard-base64 NetBird key to raw bytes and re-encodes with
  `base64.RawURLEncoding` before composing the URI. Adds one new **appended,
  `omitempty`** field to `AuditRecord`, e.g.
  `PeerSpiffeID SpiffeLabel \`json:"peer_spiffe_id,omitempty"\``. Must be
  appended after existing fields (after `Hash`, the current last field),
  never inserted — the hash chain covers the whole serialized record
  (`docs/spec/AUDIT-RECORD.md` §1.2/§3), so field order for existing
  deployments must not shift. Update `docs/spec/AUDIT-RECORD.md` and
  `docs/spec/audit-record.schema.json` together (this directory's stated
  contract, `docs/spec/AGENTS.md`) — `additionalProperties: false`, so the
  schema needs the new field added explicitly. **Note the mixed-fleet
  caveat:** a record written by a new binary (with `peer_spiffe_id` set) and
  re-verified by an *old* verifier binary that doesn't know the field will
  re-serialize without it and mismatch the hash — this is expected and
  acceptable (verifier binaries must be upgraded together with writers across
  a hash-chain-relevant field addition), but must be stated in
  `docs/spec/AUDIT-RECORD.md` as an explicit compatibility note, not left
  implicit.
- `federation/boundary.go` — add `TrustDomain string \`yaml:"trust_domain,omitempty"\``
  to `Mapping` (~line 29-35); in `NewBoundary`, build a `map[string]string`
  (org → trust domain) alongside the existing `principal` map (~line 42/60-64);
  validate for cross-org collisions at construction time; add a
  `Boundary.SpiffeID(org, peerKey string) SpiffeLabel` method next to the
  existing `Principal()` method (~line 90-95), with the peer-key-availability
  caveat above. No change to `Match`/`Org`/`Principal` semantics or callers.

**Not touched:** `acl.go`, any policy decision function, any enforcement path.
This is pure derived metadata, and the DoD's grep-check invariant (no
enforcement path reads `PeerSpiffeID`/`SpiffeID()`) is now backed by the
`SpiffeLabel` type as a second, structural line of defense.

**Verification:** see `docs/spec/OAUTH-STANDARDS-tests.md` Feature A.

---

## Feature B — Outbound OAuth 2.1 client + DPoP (remote MCP backend bridge)

**What.** A new backend kind that lets meshmcp act as a governed **client** to a
third-party remote MCP server (over the public internet) that itself requires
OAuth 2.1 per the MCP 2025-06-18 authorization spec, using DPoP-bound tokens
(RFC 9449) rather than plain bearer.

**Why here, why now.** `protocol/authorization/*.go` already fully models the
wire types for this (PRM/AS-metadata discovery, DCR client shapes, token
requests for every 2.1 grant) but has **zero call sites** — confirmed by
search. It's finished prep with no consumer. This is the one place OAuth 2.1
*client* behavior is unambiguously the right standard to speak, because the
other side of that connection is a real non-mesh party that already expects
it.

**Scope boundary (clarified in this revision):** Feature B builds and owns
the DPoP **signer/proof-construction** side only — the code path where
meshmcp is the OAuth *client* presenting proofs it creates. It does **not**
build a DPoP *verifier*. Verifying inbound DPoP proofs is a server-side
responsibility needed only by Feature C, and is specified as its own
component (Feature C0) precisely because "reuse Feature B's verification
side," as stated in the first revision of this document, was found by review
to reference a component that did not exist. Feature B's own tests verify
correctness from the *test fake AS's* point of view (it independently checks
the proof meshmcp sent), which is sufficient for B alone but must not be
read as satisfying C's verification requirement.

**Architecture, grounded in what exists:**
- Backends today are a strict two-kind union in `config.go`'s `Backend` struct
  (`Stdio []string` xor `HTTP string`, enforced at `loadConfig` ~line 246-248).
  `serveHTTP` (`serve.go` ~line 605) is a **reverse proxy** into a trusted local
  process — architecturally the wrong shape for dialing out to an untrusted
  remote server with auth headers. There is no existing outbound "MCP client"
  dialer to extend.
- Add a third kind: `Remote *RemoteBackendConfig \`yaml:"remote,omitempty"\`` in
  `Backend`, and change the two-way exclusivity check at `config.go:246-248` to
  a three-way exactly-one-of check.
- New file `remotebackend.go` (root package, matching `httpserve.go`/
  `httppolicy.go` naming), parallel to `serveStdio`/`serveHTTP` in `serve.go`'s
  dispatch (~line 185-196): a `serveRemote` backend factory that:
  1. Runs the MCP discovery dance using the **already-implemented, unused**
     helpers: `protocol/authorization.ProtectedResourceMetadataURLs`,
     `AuthorizationServerMetadataURLs`, `ParseChallenge`, `ResourceMetadataURL`.
  2. Performs the token request (`protocol/authorization.TokenRequest.Form()`)
     over a plain `*http.Client` following the repo's house style — fixed
     `Timeout` (20s, matching `control/netbird.go`'s convention), constructed
     via an injectable `Doer` interface (mirror `control/netbird.go:15`) so it
     stays mockable in tests, no retry layer (matches every existing outbound
     caller — errors wrapped with `%w` and propagated).
  3. Attaches a DPoP proof JWT (RFC 9449 §4) to the token request and to every
     resource call, keyed to a per-backend ECDSA P-256 keypair.
  4. Translates inbound mesh JSON-RPC into outbound Streamable-HTTP + bearer
     (DPoP-bound) + SSE to the real remote server.
  5. Reuses `httpEnforcer` (F16, `httppolicy.go`) on the **inbound** (mesh-facing)
     side so policy/audit/capability parity holds — this backend is governed
     exactly like any other, the only difference is what's on the outbound leg.

**DPoP signer.** New `policy/dpopsign.go`, structurally mirroring
`policy/sign.go`'s `Signer` (`GenerateSigner`/`SaveSigner`/`LoadSigner`, hex
`keyFile`, 0600 perms) but over `crypto/ecdsa` P-256 (ES256) instead of
Ed25519 — RFC 9449 DPoP proofs are conventionally ES256/RS256 and most
authorization servers expect an EC `jwk` thumbprint, not EdDSA. Same
"clear-the-signature-field, marshal canonical, sign" idiom the rest of
`policy/` already uses (`CapabilityClaims.signingBytes()`,
`DelegationToken.signingBytes()`), just producing a JWT (header + claims +
sig, base64url dot-joined) with an embedded `jwk` header instead of a bare
signature field.

**Domain separation from the existing Ed25519 signer (added per review).**
`policy/dpopsign.go`'s on-disk key file **must not** share a type or file
shape with `policy/sign.go`'s `keyFile` — even though the code structurally
mirrors it. Give the DPoP key file its own type with an explicit
`"key_type":"dpop-es256"` discriminator field, so a loader cannot be
accidentally pointed at the wrong key file and so a future maintainer cannot
copy-paste a verify call between the two signer types. On the verify side
(Feature C0), the JWT `alg` must be **pinned to `ES256`** by the verifier's
own configuration, never trusted from the incoming JWT header — this is the
standard alg-confusion defense and is a hard requirement, not a style
preference.

**DPoP key lifecycle.** The DPoP private key is a mutable, security-critical,
per-backend secret exactly like the refresh token below — but unlike the
refresh token, it does not change on a normal schedule. State explicitly:
the DPoP key is **operator-rotatable, not silently regenerated**. If the key
file is missing or fails to load at startup for a backend configured to use
one, that backend's startup fails (fatal), consistent with the existing S13
precedent ("a missing `audit_signing_key` is fatal, never silently
regenerated," `serve.go`). If an operator rotates the key, the old key's
outstanding tokens are naturally invalidated the next time the AS asks for a
fresh proof (DPoP proofs are per-request, not stored), so no separate
revocation mechanism is needed for this key specifically.

**Credential storage.** Do not invent a second secret store. Client
credentials (`client_id`/`client_secret`), the DPoP private key, and the
refresh token are per-backend named secrets resolved through the existing
`secrets.Store`/`secrets.Broker` (`secrets/broker.go`, wired per-backend in
`serve.go:419-426`/`:460` via `SetSecretResolver`) — e.g.
`{{secret:oauth_client_secret}}`, `{{secret:dpop_private_key}}`. Refresh-token
*rotation* at runtime needs an atomic rewrite, following `cmd/vault/main.go`'s
`rotate()` pattern (tmp file + rename), since unlike static grants this value
changes without an operator editing config.

**Server-side error/challenge surface meshmcp must recognize as a client**
(this is a wire-contract requirement, not an implementation detail — added
per review): the remote AS may return `401` with
`WWW-Authenticate: DPoP error="use_dpop_nonce"` to force a nonce round-trip,
or `400 invalid_dpop_proof` on a malformed/expired/replayed proof. `serveRemote`
must recognize both and retry-with-nonce or surface-and-stop respectively —
it must never treat an `invalid_dpop_proof` response as retryable with the
same proof.

**Verification:** see `docs/spec/OAUTH-STANDARDS-tests.md` Feature B.

---

## Feature C — Federation OAuth façade (split into C0–C3)

**What.** At the cross-org federation boundary (`federation/boundary.go`),
support a partner organization that does **not** run a WireGuard mesh peer:
self-service client registration (DCR, RFC 7591/7592), DPoP-bound token
issuance, and an RFC 8693 token-exchange step that turns an external token
into an internal `policy.CapabilityClaims` grant, with `authorization_details`
(RFC 9396) as the wire shape a partner uses to request a scoped grant.

**Why this is split (this revision's biggest structural change).** The first
revision landed DCR + RFC 7592 management + DPoP server verification +
nonce/replay + RAR mapping + RFC 8693 exchange + boundary `Mapping` extension
as one feature — larger than Features A and B combined, and containing the
plan's single highest-risk component (DPoP verification) with no dedicated
scope. Review found this both under-specifies the hardest part and
contradicts the "implemented + tested, then wired" discipline the codebase
already used for `policy/delegation.go` itself
(`docs/spec/ROUTER-DELEGATION.md`, "Not yet wired"). Splitting gives each
piece its own green `-race` gate before the next begins, and makes the DPoP
verifier a first-class, reviewable artifact instead of an assumed dependency.

### The exposure-model question (must be answered before any of C0–C3 begin)

> **DECISION RECORDED — 2026-07-23, owner sign-off.** The recommended
> resolution below is **adopted, in an extended form ("extended Option A")**,
> to additionally serve **hosted MCP clients** (e.g. claude.ai custom
> connectors) — a consumer the original analysis below did not contemplate.
> The façade ships as the **`meshmcp edge`** subcommand: a second,
> deliberately separate, minimal, **off-by-default** TLS ingress with an
> explicit operator-configured bind address and its own certificate, and its
> own fail-closed hash-chained audit log. Four deviations from the original
> Feature-C shape are recorded:
>
> - **D-A — the edge MAY carry exactly one tool-scoped MCP path.** The
>   "no tool-call path, no proxying, ever" bullet below is **superseded for
>   the edge listener only**: it may expose a single configured mesh backend
>   at `/mcp`, guarded in order by per-IP pre-auth rate limits, bearer
>   validation, per-client rate limits, the **unchanged** default-deny policy
>   engine, and an Ed25519 capability double-gate, with every decision
>   audited fail-closed. The mesh-internal invariant ("no open ports, ever"
>   for backends/plugins) is unchanged; README positioning becomes "no public
>   ingress **by default**; at most one explicit, off-by-default, tool-scoped
>   edge."
> - **D-B — open-approval DCR mode.** Hosted clients perform RFC 7591
>   registration without an initial access token, so C1's IAT gate cannot
>   apply to them. The edge supports two configurable modes: `token`
>   (spec-literal C1 IAT gate) and `open-approval` (default): registration is
>   open, but the client record lands **pending** and can complete no
>   authorization and obtain no token until an operator approves it.
>   Compensating controls replacing the IAT gate: per-IP registration rate
>   limit, a global `max_pending` cap plus pending-TTL GC (bounds the
>   disk-exhaustion → fail-closed-audit cascade this document calls out), and
>   audited state transitions.
> - **D-C — a new enumerated bearer exception: hosted-client access tokens.**
>   claude.ai presents bearer access tokens (no DPoP). The bearer terminates
>   at the edge: at issuance it is exchanged into an Ed25519
>   `policy.CapabilityClaims` (Subject `oauth:<client_id>`, audience- and
>   tool-bounded, TTL ≤ 1h per the `federationGrantMaxLifetime` precedent)
>   which is re-verified on every tool call; the bearer itself is opaque,
>   stored only as a SHA-256 hash, short-lived, refresh-rotated with family
>   revocation on reuse, and never crosses into the mesh. This extends the
>   "bearer-token exceptions" list; the central rule — every token accepted
>   as authorization for a tool call is DPoP-bound or an Ed25519 meshmcp
>   token — is preserved by the capability double-gate.
> - **D-D — `CapabilityClaims.Subject` semantics widen** from "the caller's
>   WireGuard public key" to "the transport-proven identity string" (for the
>   edge: `oauth:<client_id>`, proven by possession of the unexpired,
>   unrevoked access token the edge itself issued over TLS). The verifier
>   compares subjects as opaque strings; no code change.
>
> The original analysis is preserved below for context; where it conflicts
> with this record, this record wins.

**This is a product-positioning decision, not an engineering detail, and it
gates everything below.** Feature C's entire premise — serving "a partner
organization that does not run a WireGuard mesh peer" — requires an HTTP
surface reachable by parties with no mesh membership. But the product's
defining wedge (`README.md`, `docs/THREAT-MODEL.md` "no public application
ingress") and the roadmap's own stated design invariant
(`docs/ROADMAP-HARDENING.md`: *"No open ports, ever — every new backend and
plugin rides the mesh interface only"*) both forbid exactly this kind of
ingress. The first revision of this document was silent on how these
reconcile; that silence is not acceptable for a feature whose whole point is
external reachability.

**Recommended resolution (requires explicit operator/product sign-off before
C0 implementation begins — this is not something the plan can decide
unilaterally):** treat the façade as a **second, deliberately separate,
minimal, off-by-default ingress**, distinct from the mesh interface and from
the existing control-plane RBAC surface, with its own hardened threat-model
entry rather than being described as an extension of "no public ingress."
Concretely:
- Bound to a distinct configured listener (not the mesh interface, not the
  loopback-only `room`/`dash` surfaces) — its address must be explicit
  operator configuration, never a default-on bind.
- TLS-terminated with its own certificate, independent of mesh transport
  security (the mesh's WireGuard encryption does not cover this listener,
  since by definition the caller isn't a mesh peer).
- Scoped to exactly the endpoints in C1/C2 (registration, management,
  exchange) — no tool-call path, no proxying, ever, through this listener.
- `docs/THREAT-MODEL.md` gains a **new adversary**: "External non-mesh OAuth
  registrant/client" — a party that, until it completes registration and
  obtains a DPoP-bound token, holds no cryptographic identity meshmcp
  recognizes at all. This is a genuinely new class the existing threat model
  doesn't contemplate (every existing adversary is at minimum a mesh peer);
  it needs its own defended/limit bullets, not a note folded into the
  existing "compromised router" or federation sections.
- `docs/CAPABILITY-MATRIX.md` must list this ingress itself (not just the
  DCR/exchange features) as **Experimental/Labs, off by default** until the
  hardening below (rate-limiting, fail-closed audit, subject-token
  validation) is implemented and tested.

If, on review, the operator/product decision is instead "this ingress is out
of scope for meshmcp entirely" — e.g. federation with non-mesh partners
should be brokered by a separate, purpose-built edge service that then joins
the mesh on meshmcp's behalf — then C0–C3 should not be built at all, and
Feature C should be marked "rejected, out of scope" rather than "planned."
**This document takes no position on which resolution is correct** — it
requires a decision, and records the recommended default only so
implementation isn't blocked indefinitely.

### C0 — DPoP verification primitive (new; the gap this revision closes)

**What.** A server-side DPoP proof verifier, independent of and prerequisite
to C1–C2, in `policy/dpopsign.go` alongside the Feature-B signer (verifier and
signer live in the same file since they share the JWT-shape constants, but are
distinct exported types/functions — see the domain-separation note in
Feature B).

**Required checks (RFC 9449 §4.3/§7.1), each a named, independently testable
function or clearly delineated step — not folded into one opaque
`Verify(proof) bool`:**
1. **Algorithm pinning.** The verifier's own configuration fixes `ES256`;
   the proof JWT's own `alg` header is read only to confirm it matches the
   pinned value, never trusted to select the verification algorithm
   (alg-confusion defense).
2. **Structural/claims check.** `typ: "dpop+jwt"`, `htu` exact string match
   against the actual request URL (document the normalization rule used —
   e.g. scheme+host+path, query string excluded per common DPoP profile
   guidance — explicitly, so there is no ambiguity for the implementer),
   `htm` matches the request method, `jti` present and non-empty.
3. **Freshness window.** `iat` must fall within a configured window — **pin a
   concrete default** (recommended: ±60s clock skew, reject if `iat` is more
   than 300s old) rather than leaving this to implementation-time judgment.
4. **Key-confirmation binding.** The proof's embedded `jwk` thumbprint
   (`jkt`, RFC 7638) must equal the `cnf.jkt` bound to the access token being
   presented — this is the actual sender-constraint; without it, DPoP
   degrades to "any proof, from any key, is accepted alongside any token,"
   which is not meaningfully different from bearer.
5. **`ath` check on resource requests.** The proof's `ath` claim must equal
   base64url(SHA-256(access token)) — binds the proof to the specific token
   in use (§4.3), not just to the request shape.
6. **Replay tracking.** Every verified `jti` is recorded in a replay store
   before the request is treated as authorized; a repeated `jti` within its
   freshness window is rejected.

**Replay-store durability (a specific gap review found in the first
revision).** The only existing replay primitive in the codebase,
`policy.MemNonceStore` (`policy/delegation.go`), is in-memory and is an
acceptable **starting point**, but its retention only needs to cover the
freshness window pinned in check 3 above — **explicitly size the store's
retention to that window** (e.g. keep every `jti` for `iat`-window + clock
skew, then evict) so memory is bounded, and **explicitly document** that a
gateway restart clears the replay set: because retention is bounded by the
freshness window, a proof captured before restart and replayed after restart
is only exploitable if it is *also* still within its freshness window,
which is small (≤300s per check 3) by design. This is stated here as an
accepted, bounded residual risk, not silently ignored: if an operator's
threat model requires surviving a replay across a restart, the replay store
must be made durable (e.g. backed by the same file-store discipline as
`FileApprovalStore`), and this document flags that as a configuration
option to expose, not a mandatory default.

**Nonce lifecycle (server-issued `DPoP-Nonce`, RFC 9449 §8).** The verifier
issues a fresh nonce on the first proof-less/no-nonce request (via
`WWW-Authenticate: DPoP error="use_dpop_nonce"`, matching the client-side
handling Feature B already recognizes), requires the next proof to embed
that exact nonce, and **treats each issued nonce as single-use** — a second
proof presenting an already-consumed nonce is rejected. Nonce TTL: pin a
concrete default (recommended: 300s), tracked in the same bounded replay
store as `jti`.

**Error responses.** The verifier's HTTP-facing error surface must emit the
RFC 9449/OAuth-standard error codes (`invalid_dpop_proof`, `use_dpop_nonce`)
so a compliant client (including meshmcp's own Feature-B client, when C is
tested against B) can react correctly — this is part of the wire contract
required for C0 to be usable by anything, not an optional nicety.

### C1 — DCR registration + management store

**Design, in order of the request lifecycle:**

1. **Registration (RFC 7591 `POST /oauth2/register`).** Gated by a configured
   initial access token with a `client:register` scope.
   **Bearer-token exception, explicitly scoped (resolves the
   self-contradiction review found):** this initial access token, and the
   RFC 7592 `registration_access_token` used for management (below), are
   **bearer credentials by necessity** — a first-time registrant has no
   DPoP key yet, and RFC 7591/7592 define these as bearer per spec. This is
   a deliberate, minimal exception to the central design rule, not an
   oversight, and it is compensated by: (a) the initial access token is
   scoped to `client:register` only, never usable for tool access; (b) the
   `registration_access_token` is bcrypt-hashed at rest (below) and
   presented only over the C-specific TLS listener; (c) rate-limiting
   (below) bounds brute-force/abuse exposure; (d) **once a client completes
   its first token request and thereby establishes a DPoP key (Feature C2),
   all subsequent token-endpoint traffic for that client is DPoP-bound** —
   the bearer exception is confined to the registration/management surface
   and never extends to tool-access tokens.
2. **Management (RFC 7592 `GET/PUT/DELETE /oauth2/register/{client_id}`).**
   New file-backed store mirrors `policy/approval_token.go`'s
   `FileApprovalStore` conventions: `0700` dir, one `0600` JSON file per
   `client_id`, atomic `os.Rename` for any state transition.
   `registration_access_token` stored **bcrypt-hashed**, looked up via
   bcrypt's own constant-time compare (not a manual `==`) — **pin a cost
   factor explicitly (recommended: 12)** and **pre-hash the presented token
   with SHA-256 before bcrypt**, since bcrypt silently truncates input past
   72 bytes and an unbounded-length token would otherwise lose entropy
   without any visible error.
3. **`registration_source` provenance.** Every stored client record carries
   `registration_source` (`"internal"` for admin-provisioned entries, `"dcr"`
   for self-registered). The delete path refuses any record with
   `registration_source == "internal"`.
   **Fail-closed on read failure (a gap review found — this is the same bug
   class as the P0-3/F22 audit-write-fail-open incident this codebase
   already fixed once):** if the stored record cannot be read, is
   unparseable, or has a missing/unrecognized `registration_source` value,
   the delete (and any other mutating operation) is **refused**, never
   defaulted to "not internal, therefore allowed." A corrupt or
   partially-written record must never be treated as a deletable `"dcr"`
   record by omission.
4. **Rate-limiting / quota (a gap review found — `/register` is the one
   surface reachable by parties with no established identity at all, and it
   performs bcrypt, which is deliberately CPU-expensive).** Required, not
   optional: `http.MaxBytesReader` and `ReadHeaderTimeout`/`ReadTimeout` on
   every C1 endpoint (mirroring the existing S26/S27 controls already applied
   to `/v1/approve`/`/v1/deny` and `dash`/`room`), a per-initial-access-token
   cap on the number of live registered `client_id`s (bounds disk/inode
   exhaustion — one file per client_id, otherwise unbounded), and a
   request-rate limit specifically on the bcrypt-bearing management path
   (bounds CPU-exhaustion via repeated failed-comparison attempts). This
   matters more than a typical rate-limit nicety: because audit writes are
   fail-closed (P0-3/F22), a disk-exhaustion DoS against `/register` could
   cascade into a **global gateway outage**, not merely façade
   unavailability — this is the concrete reason the control is required, not
   discretionary.
5. **Fail-closed on the C1 audit path.** Every registration, management, and
   deletion operation is an auditable state transition; if the audit write
   for that transition fails, the operation itself must fail (deny), per the
   same F22 semantics already established for tool-call audit. A client must
   never end up registered, modified, or deleted without a corresponding
   audit record landing.

### C2 — RFC 8693 exchange + RAR mapping

**Internal token to reuse — do not reinvent, and use the correct shape
(review found the first revision's choice was wrong).** The exchanged grant
is a **`policy.CapabilityClaims`**, minted via the existing
`Signer.IssueCapability(CapabilityClaims, time.Time) (string, error)`
(`policy/capability.go`) — **not** a `policy.DelegationToken`. The first
revision proposed reusing `IssueDelegation`/`AuthorizeDelegated`, but
`DelegationToken` binds a per-request `ReqHash`, a `Router` identity, and an
`Audience` for one specific forwarding hop (`policy/delegation.go`) — there is
no single request at exchange time, and a non-mesh partner has no "router"
WireGuard identity to populate `Router` with, nor is there a meaningful
`routerDec` for `AuthorizeDelegated` to intersect against. `CapabilityClaims`
is the correct fit: it is exactly "a reusable, scoped, time-bounded grant
keyed to a subject and a set of tool/corpus globs," with no per-request
binding required. If a *specific forwarded call* through the façade is added
in a later phase, that is a distinct design question (a genuine delegation,
with a real router identity) and should not be conflated with the exchange
step itself.

**Subject-token validation (the plan's most severe gap, per the security
review — Critical-rated).** The exchange's job is not merely to "authenticate
the external party" in the abstract; it must, as a hard requirement:
1. Validate the presented `subject_token`'s **signature** against a per-org
   **pinned** JWKS or issuer key (configured per `Mapping`, extended below) —
   never accept an unverified or self-asserted subject token.
2. Validate the `subject_token`'s **issuer** matches the org's configured,
   pinned issuer — this is what prevents a token minted by an unrelated IdP,
   or by the *wrong* org's IdP, from resolving to any org's grant.
3. Validate the `subject_token`'s **audience** contains meshmcp's exchange
   endpoint identity — this is what prevents a token minted for an unrelated
   purpose (e.g. some other SaaS integration at the partner) from being
   replayed here. Without this check, a token issued by Partner A's IdP for
   a completely different consumer could be presented at meshmcp's exchange
   endpoint and accepted, because nothing would have checked *what the token
   was for*.
4. Validate `exp`/`nbf` on the subject token itself, independent of any
   exchange-token expiry applied afterward.
5. **Resolve org from the validated issuer, not from the subject claim.**
   `federation.Boundary`'s `Mapping` gains a new match form (alongside
   `"pubkey:<key>"`/FQDN-glob) keyed on the subject token's issuer, and this
   new form does **not** inherit the existing `"*"` wildcard mapping
   behavior (`boundary.go`'s `OrgFor`) — an unmapped issuer resolves to no
   org, full stop, never a wildcard org. This closes the specific attack
   where a subject string happens to collide with a different org's
   principal.

**RAR mapping — strict/closed decoding (strengthened per review).** RFC
9396's `authorization_details` is intentionally open-ended/extensible
(arbitrary `type` values, nested structures). "Reject anything the mapper
cannot represent" is not, by itself, a strong enough guarantee — an entry of
a *known* `type` carrying additional fields the mapper doesn't recognize
could otherwise be silently accepted with those extra fields ignored, which
is a parser-differential / confused-deputy risk (the partner and meshmcp
disagree about what was granted). The requirement is therefore:
- Meshmcp defines and documents a **closed, enumerated set** of accepted
  `authorization_details` `type` value(s) (name them concretely when C2 is
  implemented — this document requires the enumeration to exist and be
  closed, not that it be fixed here).
- Each accepted type is decoded with **strict, unknown-field-rejecting**
  parsing (Go's `json.Decoder.DisallowUnknownFields()` or equivalent) — an
  entry with any field the decoder does not explicitly account for causes
  the **entire exchange request** to be rejected (400), not partially
  mapped.
- **Multi-entry semantics are specified, not left implicit:** when a request
  carries multiple `authorization_details` entries, the resulting internal
  grant is the **union** of their tool/corpus globs, and the whole union is
  then intersected against the org's configured `Grant` (below) — state this
  explicitly so "how do multiple entries combine" isn't discovered at
  implementation time.
- The field-by-field mapping (RAR `actions`/`locations`/`datatypes` → tools
  glob / backend+audience / corpora glob) is defined at implementation time
  against the enumerated type(s), and is itself part of C2's Definition of
  Done.

**Scope intersection.** The minted `CapabilityClaims`'s `Tools`/`Corpora` is
the intersection of the (unioned, per above) requested `authorization_details`
and the org's existing configured `Grant.Tools`/`Grant.Corpora`
(`federation/boundary.go`) — never the requested set alone. This existing
`Grant` mechanism is unchanged and remains the source of truth for what an
org may reach at all.

**Lifetime.** Export `policy.MaxDelegationLifetime` (currently unexported
`maxDelegationLifetime`, 5 min, in `policy/delegation.go`) — or, since C2 now
mints `CapabilityClaims` rather than `DelegationToken`, apply
`policy/capability.go`'s own existing `maxCapLifetime` (24h) as the ceiling
instead, whichever is the intended validity window for a federation grant.
**This document requires the implementer to state which cap applies and
why** — a federation grant handed to an external, non-mesh party arguably
warrants a *shorter* ceiling than the general-purpose 24h capability cap, not
the same one; this is a decision this document flags but does not make.

**DPoP requirement.** Every C2 request (the exchange call itself, and any
subsequent use of the minted grant against a tool-facing endpoint through the
façade) requires a valid DPoP proof, verified by C0, presented before any
other request processing — a request with a missing or invalid proof is
rejected before the subject token is even parsed (ordering matters: proof
validity gates everything else, so an attacker cannot use a malformed subject
token to probe the exchange logic without first holding a valid
proof-of-possession key).

### C3 — Wire into `federate.go`

Only after C0, C1, and C2 are each independently implemented and tested does
this sub-phase connect the façade to `federate.go`'s live
`buildBoundaryServer` path, following the same staging discipline the
codebase already used for `policy/delegation.go` itself (implemented +
tested, then wired — `docs/spec/ROUTER-DELEGATION.md`, "Not yet wired").
Until C3 lands, C0–C2 exist as a standalone, independently-callable module
with no effect on any live mesh-peer federation path.

**Verification:** see `docs/spec/OAUTH-STANDARDS-tests.md` Feature C
(subdivided C0–C3).

---

## Build order

1. **Feature A (SPIFFE labels)** — additive, no risk, ships independently.
2. **Feature B (outbound DPoP/OAuth client)** — no dependency on Feature C;
   the DPoP signer (`policy/dpopsign.go`) built here is reused (as a sibling
   verifier in the same file, not the same component) by Feature C0.
3. **Feature C0 (DPoP verifier)** — depends on Feature B's signer only for
   shared JWT-shape constants; otherwise independent and must be built and
   tested as its own unit before C1/C2 begin.
4. **Feature C1 (DCR store)** — depends on C0 for token-endpoint DPoP
   enforcement once a client has registered; the registration/management
   endpoints themselves do not depend on C0 (they're bearer-gated by
   design, per the scoped exception above).
5. **Feature C2 (RFC 8693 exchange + RAR)** — depends on C0 (DPoP
   enforcement on the exchange call) and C1 (a client must be registered
   before it can exchange a token).
6. **Feature C3 (wire into `federate.go`)** — depends on C0–C2 all being
   implemented and tested standalone first, and additionally depends on the
   **exposure-model question above being resolved with explicit sign-off**
   — do not begin C3, or even C0–C2 implementation, until that resolution is
   recorded.

## Roadmap bookkeeping

`docs/ROADMAP-HARDENING.md` should gain: **F34** (remote OAuth-protected MCP
backend + DPoP client, Feature B), **F35** (DPoP verification primitive,
Feature C0), an extension of **F31** (federated identity) to explicitly
include the DCR/8693/RAR façade (Features C1-C3) with its exposure-model
caveat, and a new supporting item **S61** (SPIFFE identity labels, Feature A)
in the S45-S60 range. `docs/CAPABILITY-MATRIX.md` should list all of A/B/C0
as **Planned** until each lands with `-race` tests, and C1-C3 specifically as
**Planned, exposure model unresolved** until the sign-off above happens —
per the existing maturity convention, a capability is never marked
Stable/Beta ahead of its tests and, for C1-C3, ahead of a resolved trust
boundary. `docs/THREAT-MODEL.md` gains the new "external non-mesh OAuth
registrant/client" adversary described above, independent of whether C1-C3
are ultimately built.
