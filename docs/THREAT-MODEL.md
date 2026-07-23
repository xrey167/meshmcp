# meshmcp Threat Model

This document states, for each adversary, what meshmcp defends and what it does
**not**. It is deliberately conservative: a control is only listed as a defense
where code and tests establish the property. Where a guarantee has a limit, the
limit is stated. Headline claims in the README are bounded by this document.

## Positioning and trust boundaries

meshmcp is a **self-hosted agent firewall for private MCP servers**. Its wedge:
no public application ingress, transport-bound workload identity, enforceable
per-identity tool/method policy, request-specific human approval, and a
gateway-signed tamper-evident decision log.

Core boundaries:

- **Transport (WireGuard/NetBird).** Provides confidentiality, integrity, and a
  cryptographic peer identity (public key). Membership is **authentication**,
  not authorization.
- **Gateway (enforcement point).** Derives identity from the authenticated
  transport at every enforcement point and applies default-deny policy to
  privileged and administrative operations. Never trusts identity supplied in
  headers, JSON-RPC `_meta`, request bodies, or filenames.
- **Backend MCP server.** Treated as a semi-trusted execution environment; a
  malicious backend is explicitly modeled below.

Engineering invariants: treat every mesh peer as potentially compromised;
default-deny privileged operations; security-config errors fail startup rather
than silently falling back; do not claim exactly-once execution where only
delivery/replay behavior is guaranteed; do not describe a log as complete or
non-repudiable beyond what the verifier establishes.

---

## Adversaries

### 1. Malicious ordinary mesh peer

A peer that is a legitimate WireGuard member but should have limited or no
privilege.

- **Defended:** Reaching a mesh port grants nothing. The **control plane** is
  default-deny RBAC keyed on the caller's WireGuard public key (roles:
  `control.admin`, `enrollment.issue`, `registry.read/write`,
  `policy.read/write`); an ordinary peer cannot mint setup keys, mutate the
  registry, replace policy, or list administrative state, and every allow/deny
  is audited (F-P2). The **approval plane** requires a mandatory approver ACL on
  the mesh — an empty ACL no longer means "any peer may approve" (F-P2.2). Tool
  calls are default-deny per identity.
- **Limit:** Authorization is only as correct as the deployed ACL/policy. A peer
  granted a role holds that role.

### 2. Compromised agent (prompt-injected / jailbroken)

The model or agent process is adversarial but sits behind the gateway.

- **Defended:** Policy is enforced at the gateway, out of reach of any prompt.
  An **ID-less or ambiguous `tools/call` cannot bypass tool policy** — every
  `tools/call` is classified by method name and passes full authorization;
  id-less/`null`-id and duplicate-key/parser-differential messages are rejected
  (F-P1). Taint/data-flow labels can block exfiltration tools after untrusted
  data enters a session.
- **Limit:** The agent can still do anything its identity is *authorized* to do.
  Least-privilege policy is the operator's responsibility.

### 3. Compromised router / confused deputy

An aggregating router forwards a caller's request upstream.

- **Defended (when pinned).** With `delegation_key` on the router and
  `router_delegation.trusted_public_keys` pinned on the upstream backend, every
  forwarded `tools/call` carries a signed, short-lived (≤5 min), single-use
  delegation token bound to (caller, router, audience, backend, tool, request
  hash, expiry, nonce), and the upstream authorizes the **intersection** of
  caller ∩ router ∩ delegation scope — a compromised router cannot widen a
  caller's authority, and a caller cannot exceed what the router itself may do.
  `required: true` refuses any token-less `tools/call` (it gates `tools/call`
  only — other JSON-RPC methods such as `resources/read` stay governed by the
  backend policy's `methods` rules); a mint failure denies at the router rather
  than forwarding unsigned; both identities + the nonce land in the audit
  record. Unsigned origin `_meta` remains informational and is never trusted as
  identity. See `docs/spec/ROUTER-DELEGATION.md`.
- **No-authority fallback:** without the key/pin pair there is NO delegated
  identity — the router forwards under its own WireGuard identity exactly as
  before, defended only by its default-deny caller ACL and (optional) router
  policy. Registry-discovered upstreams have no audience pin and always take
  this unsigned path. Limits when pinned: `tools/call` on stdio backends only,
  and replay protection is a **per-gateway-process** nonce store (per-gateway
  replay windows in a multi-gateway HA deployment).

### 4. Compromised gateway

The enforcement point itself is compromised.

- **Not defended (by design boundary).** The gateway is the enforcement point;
  if it is compromised, it can allow calls and forge its own audit signatures.
  External checkpoint anchoring (below) limits undetected audit rollback.

### 5. Malicious or buggy backend MCP server

- **Defended:** Secrets are injected only after authorization; secret **names**
  (never values) appear in audit; and the gateway performs **response-side
  redaction** — injected secret values (raw and JSON-escaped forms) are scrubbed
  from the backend→agent stream and traces, so a backend cannot trivially echo an
  injected credential back to the agent. The guarantee is **credential
  isolation**.
- **Limit:** Redaction defeats the trivial echo, not a determined leak. A
  malicious backend that receives an injected secret is within the secret's
  exposure boundary and can transform it (encode, split, exfiltrate out of band).
  Egress restriction on the backend is Labs; prefer short-lived scoped
  credentials so an escaped value is low-value.

### 6. Stolen approval credentials

- **Defended (partial):** Approval identity is derived from the transport, and
  the mesh-served approver requires a mandatory ACL (F-P2.2).
- **Limit:** Approvals are currently per-(peer, tool) ambient grants with an
  optional TTL. **Request-bound, signed, single-use approval objects** (bound to
  argument hash, backend, session, nonce, expiry; replay-protected) are Phase 3
  and not yet implemented. Until then an approval authorizes a (peer, tool) pair
  within its TTL rather than one specific argument set.

### 7. Writable audit storage

An adversary who can write the audit file (but lacks the signing key).

- **Defended:** `audit verify` recomputes each record hash, verifies every
  `PrevHash` link and Merkle root against the signed checkpoint, rejects
  duplicate/non-monotonic sequence numbers, mixed signers, and a `Count` that
  does not match the covered span. It reports four honest states — **invalid**,
  **untrusted_key** (no pinned key), **unsealed** (valid but a tail is not
  covered), **sealed** (valid, trusted, fully covered) — and only a *sealed*
  result pinned to an expected key is complete and trusted (F-P5). An edit to a
  covered record fails verification.
  The whole hash chain — including the unsealed tail — is verified (each
  record's stored hash and `PrevHash` link), and a gateway restart continues the
  same chain (the writer and checkpointer are seeded from the verified tail;
  appending to an unverifiable log is refused).
- **Limit:** Records after the last checkpoint (an *unsealed* tail) are
  hash-chain-verified but not yet Merkle-sealed/signed; a checkpoint seals them.

### 8. Gateway crash during a side-effecting call

- **Honest guarantee:** meshmcp guarantees in-order frame **delivery** and
  duplicate suppression on reconnect. It does **not** guarantee exactly-once
  tool **execution**. By default an unknown-outcome `tools/call` is never
  auto-retried after dispatch. The router's per-upstream `retry_tools` globs
  let the OPERATOR classify specific tools as idempotent/read-only: a matching
  call is re-dispatched to another replica after an ambiguous transport
  failure, and every dispatch carries the same
  `_meta["meshmcp.io/idempotency-key"]` so the backend can deduplicate.
- **Backend-side enforcement (framework-built backends):** servers built on
  the `mcp` framework can enforce the key with `mcp.Idempotency(store, ttl)`:
  the first claimant of a key executes and records the terminal outcome,
  concurrent duplicates single-flight onto it, and replays within the TTL get
  the recorded outcome (results above `mcp.MaxCachedResultBytes` are returned
  once but not cached — their replays get an error, never a silent second
  execution). Claims are scoped per (tool, key): the key namespace is
  client-controllable, so the same key presented on two different tools never
  shares a claim — an unscoped claim would let one tool's cached result
  silently answer, and suppress, a different tool's call. A claim-store error
  refuses the call (fail closed: a broken store must never allow a
  possibly-duplicate execution). Claims live in memory (`MemClaimStore`,
  single process, bounded at 4096 live claims — at the cap NEW keys are
  refused fail-closed, so untrusted clients flooding distinct keys can wedge
  keyed calls until claims expire; use the PostgreSQL store or upstream rate
  limiting where that matters) or PostgreSQL (`pgstore`, shared across
  replicas — required for the cross-replica retry to be safe). This is
  at-most-once per (tool, key) within the TTL, not global exactly-once.
- **Foreign backends:** for external servers proxied by the gateway the key
  remains conveyed, not enforced — a backend that ignores it executes a
  retried call twice, so classify only tools where that is safe. Unlisted
  tools keep the deny-default.

### 9. Concurrent gateways restoring the same session (split-brain)

- **Defended (store layer):** an atomic compare-and-swap lease primitive with a
  monotonic fencing generation and expiry (`session.LeaseStore`:
  `AcquireLease` / `RenewLease` / `ReleaseLease` / `SaveIfOwned`) guarantees that
  at most one gateway can hold a session's lease, and a superseded owner is
  fenced out of writes (its stale generation fails `SaveIfOwned`). Proven for
  both `MemStore` and `FileStore` with concurrent single-winner and fencing
  tests.
- **Defended (server path):** the session server routes through the lease API
  end to end: it acquires the lease on session create, gates every checkpoint
  with `SaveIfOwned` (a fenced write makes the superseded gateway yield), takes
  over via `TakeoverLease` only on a reattach carrying the session creator's
  transport-verified identity, and reaps with `DeleteIfOwner`. Checkpoints are
  serialized per session so an older snapshot can never commit after a newer
  one over a slow store. Proven end to end by the migration harness
  (`session/storetest.RunSessionMigration`): crash one gateway, reattach to a
  second, rehydrate + lease takeover — run against `MemStore` on every test
  run and against live PostgreSQL (`pgstore`) when `MESHMCP_TEST_PG_DSN` is
  set.
- **Defended (expiry-driven standby):** takeover is no longer reattach-driven
  only. The server renews every held lease at ~TTL/3 (so expiry means "owner
  alive"), releases leases on clean shutdown (owner cleared, generation and
  state preserved), and — when `session_failover: standby` is configured — a
  standby sweep adopts sessions whose lease is released or expired past a
  conservative 2×TTL margin (≥3×TTL of total owner silence), respawning the
  backend under the creator's persisted identity before the client returns.
  The claim is `AcquireLease`'s generation CAS — `TakeoverLease` remains
  reserved for the identity-verified creator reattach — so exactly one
  claimer wins and a paused-not-dead owner is fenced out of
  `SaveIfOwned`/`RenewLease` the instant the claim commits (its renewal then
  fails and it yields). The margin tunes availability only; no interleaving
  can produce two unfenced writers, and the identity binding on client
  reattach is unchanged (the sweep never talks to a client). Records written
  by pre-upgrade builds (no persisted `peer_fqdn`) and degraded generation-0
  sessions (whose owner never held a lease and is therefore unfenceable) are
  categorically never adopted (degraded sessions also never checkpoint on a
  lease-capable store, so an unfenced write can never regress a record a peer
  has since taken over), as are records stamped with a newer schema version
  than the running build (pgstore stamps and filters `SchemaVersion` exactly
  like `FileStore`). The sweep requires a PostgreSQL session store: config
  validation rejects `session_failover: standby` over a file store, and the
  server independently disables the sweep over `FileStore`, because a file
  lock stolen from a paused-not-dead holder could regress the generation an
  adoption committed (every `FileStore` mutation now re-verifies its lock
  token immediately before the commit rename, narrowing that hole for the
  reattach-driven path that remains supported there). Proven by renew/sweep
  race tests (`session/sweep_race_test.go`) plus the end-to-end
  paused-gateway flow.
- **Defended (deliberate live move, v2 first slice):** ownership of ONE live
  session can be moved from a source gateway to a destination gateway on operator
  command, in a two-phase prepare → ready → commit protocol
  (`session.Server.MoveSessionTo` / `ServeMoveControl`), WITHOUT reopening the
  split-brain window. The source keeps owning and serving at generation G through
  prepare and ready; the destination only PRE-WARMS (spawns/restores its backend
  in a `warming` map, takes NO lease, pumps NO client). Commit is the SAME single
  `TakeoverLease` generation-CAS the reactive paths use — the one indivisible flip
  G→G+1 — and the destination promotes its warm backend to serving ONLY after that
  CAS wins; the source freezes its client (detach + final checkpoint at G) BEFORE
  commit and is hard-fenced by the generation bump (its next `SaveIfOwned`/renew
  fails → yields). So at no instant do two runtimes process the session's traffic,
  and a crash at ANY step leaves exactly one resumable owner: before the CAS the
  source holds the live lease at G (quiesce ≠ release) and resumes; after the CAS
  the destination owns G+1 and resumes; never both, never neither. This is
  additive — no new `MigrationMode`, and reactive rehydrate/adopt/sweep are
  unchanged. Identity is untouched: `TakeoverLease` stays reserved for the
  verified-creator reattach, and the operator move instead gates commit on a
  CONSUMED single-use grant ("this destination may receive this one session, once"
  — `air move grant` / `air.ConsumeMoveGrant`), never an arbitrary peer. v1
  supports only `MigrateHandshake` (stateless; source drains to a quiescent
  request boundary or refuses) and `MigrateBackend` (checkpoint-capable; the
  backend is authoritative and dedups any residual); `MigrateFull` and
  no-checkpoint stateful backends are refused at prepare (deny-by-default), as are
  degraded generation-0 (unfenceable) sessions. Proven by the full crash-recovery
  matrix in `session/move_test.go` (deterministic, `-count=20`) and the
  public-API `storetest.RunSessionLiveMove` conformance against `MemStore` and
  live PostgreSQL.
- **Limit:** there is no exactly-once tool execution across a failover (§8) OR a
  move, and adoption/move resumes from the owner's last checkpoint — a failover
  taken mid-request keeps handshake-mode's existing in-flight-response window, and
  the live move does not itself redirect the client (the creator lands on the
  destination by the same client-driven reattach + mesh discovery, so the operator
  redirects discovery as part of the drain; a creator that reattaches to the
  source post-commit is a normal, allowed creator reattach). `FileStore`'s CAS
  holds only on a single host / lock-correct shared filesystem, and only for
  crash-or-alive holders (a process paused past the 10s lock-staleness window has
  its lock stolen; the pre-commit token check shrinks, but cannot close, the
  resulting write-back window) — cross-host deployments, the standby sweep, and
  cross-host live moves need the PostgreSQL store (`session_store: postgres://...`).

### 10. Malformed / adversarial JSON-RPC

- **Defended:** The policy filter rejects batches, unparseable lines, oversized
  lines, id-less/`null`-id `tools/call`, empty/mistyped `params.name`, duplicate
  security-relevant keys, and trailing data. A fuzz test asserts a deny-all
  policy never forwards a `tools/call` for any single-line input (F-P1).

### 11. Compromised control-plane operator

- **Defended (partial):** Every privileged control action is authorized by role
  and audited with actor key, action, target, result, and correlation id.
- **Limit:** An operator with `control.admin` can, by definition, administer.
  Separation of duties beyond the role set, and optimistic-concurrency
  protection on policy replacement, are follow-ups.

### 12. External OAuth registrant / hosted MCP client (edge only)

A party on the public internet — e.g. a hosted MCP client such as a claude.ai
custom connector, or anyone who finds the endpoint — talking to the optional,
off-by-default `meshmcp edge` ingress. Until it completes registration,
operator approval, and authorization, it holds **no identity meshmcp
recognizes at all** — a genuinely new class: every other adversary here is at
minimum a mesh peer. (This surface exists only when an operator explicitly
runs `meshmcp edge`; see the recorded exposure-model decision in
[docs/spec/OAUTH-STANDARDS.md](spec/OAUTH-STANDARDS.md).)

- **Defended:** The edge is a separate, explicitly-configured TLS listener that
  exposes exactly one tool-scoped MCP path plus the OAuth endpoints — never the
  mesh, the control plane, or other backends. Registration is rate-limited
  per IP and bounded (`max_pending` cap + pending TTL); a pending or denied
  client can complete no authorization and obtain no token. Authorization
  requires an explicit operator approval (pairing-style) plus PKCE (S256
  only) with exact redirect-URI match. Every issued access token is opaque,
  SHA-256-hashed at rest, TTL ≤ 1h, and bound at issuance to an Ed25519
  `CapabilityClaims` (subject `oauth:<client_id>`, audience- and tool-bounded)
  that is re-verified on every tool call; the policy engine additionally
  applies default-deny per-identity rules. Every decision and lifecycle
  transition lands in the edge's own fail-closed, hash-chained audit log.
- **Limit:** Availability of the edge listener itself is exposed to the
  internet (mitigated, not eliminated, by rate limits and body caps). An
  approved client is trusted to the extent of its granted tools until revoked
  — approval quality is the operator's judgment, as with any pairing.

### 13. Holder of a stolen edge bearer token

An adversary who exfiltrates a hosted client's access or refresh token (e.g.
from the client's own infrastructure).

- **Defended:** Access tokens expire in ≤ 1h and are audience- and tool-bounded
  by their embedded capability; a stolen token cannot reach tools or backends
  outside its grant, and every use is audited under the client's identity.
  Refresh tokens rotate on every use; reuse of a rotated refresh token revokes
  the entire token family (theft-detection semantics). Revoking the client
  kills its tokens, capabilities (via the revocation store), and sessions.
- **Limit:** Within its TTL and grant scope, a stolen access token authorizes
  calls exactly as the legitimate client — bearer possession is the proof
  (recorded as deviation D-C in the exposure-model decision). Short TTLs and
  the audit trail bound the window and make abuse attributable, not
  impossible.

---

## Audit: what "tamper-evident" means here

The audit log is a **gateway-signed tamper-evident decision log**. It proves
that the *records the gateway wrote* were not edited after signing, provable
against a pinned public key for the sealed portion. It does **not** prove that
every real-world action was observed, and gateway signatures are **not** caller
non-repudiation (the gateway signs, not the caller). A key-holding insider who
controls both the log and its local checkpoints can roll both back together;
defense against that requires **external anchoring**, which is now implemented:
every signed checkpoint can be witnessed outside the gateway — appended to a
self-linked local anchor file (`audit_anchor`) and/or POSTed to a peer
gateway's witness endpoint (`audit_anchor_url` → `meshmcp control
--anchor-witness`, which pins the signer key, verifies the signature, and
records checkpoints append-only with per-signer dedup). `meshmcp audit verify
--anchors` cross-checks the checkpoints against the witness and exits non-zero
on disagreement **even when the chain verifies sealed internally** — the
rollback case signatures alone cannot catch. The four verification states are
unchanged; the anchor verdict (`anchored` / `anchor_partial` /
`anchor_mismatch`) is orthogonal, added evidence.

**Witness-trust assumption, stated plainly:** anchoring converts "trust the
gateway host" into "trust that the gateway host and the witness do not collude
(or are not controlled by the same insider)." A witness on the same host, or
writable by the same insider, adds nothing — run it on an independently
administered peer. Peer delivery is asynchronous and best-effort — a slow or
unreachable witness delays witnessing but never blocks a checkpoint or an
audited call — so checkpoints not yet witnessed (`anchor_partial`, e.g. during
a witness outage or in the short delivery window) remain rollable until the
witness records them or `meshmcp audit anchor` replays them; the verifier
reports that window honestly rather than hiding it. RFC 3161 timestamping
remains future work behind the same `Anchor` interface.

## Delivery vs. execution guarantees (summary)

| Property | Guarantee |
|---|---|
| In-order frame delivery | Yes, within a session |
| Duplicate suppression on reconnect | Yes |
| Gateway restart continuity of audit chain | Verified on read; restart-safe append is in progress |
| Exactly-once tool execution | **No** — framework-built backends using `mcp.Idempotency` give at-most-once per (tool, idempotency key) within the claim TTL (with result replay); foreign backends get the key conveyed only |
| Automatic retry of unknown-outcome mutating call | **No** — only safe/idempotent-keyed calls may retry |
| Cross-gateway session HA | **No** with file storage; needs a CAS-capable shared store |

See `docs/spec/SECURITY-CLOSURE.md` for the per-finding reproduction, fix,
tests, and residual risk, and `docs/CAPABILITY-MATRIX.md` for maturity.
