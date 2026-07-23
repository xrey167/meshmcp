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

- **Status: experimental.** Today the router forwards using its own WireGuard
  identity and conveys the downstream caller only as unsigned `_meta`, which is
  informational and must never be trusted as identity. A signed short-lived
  delegation token bound to (caller, router, audience, backend, tool, request
  hash, expiry, nonce), with upstream policy computing the intersection of
  caller ∩ router ∩ delegation scope, is the intended design (Phase 4, not yet
  implemented). Until then, treat router aggregation as **Labs**: put a
  default-deny caller ACL on the router and do not rely on delegated identity.

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
  tool **execution**. After an ambiguous side effect, a non-idempotent tool call
  is not automatically retried (Phase 6, in progress). Do not retry an
  unknown-outcome mutating call without an enforced idempotency key.

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
- **Limit:** takeover is *reattach-driven only* — a standby gateway never
  claims an expired lease on its own (`RenewLease`/`ReleaseLease` are unused;
  a long-lived session's lease lapses and the fencing generation is what keeps
  writes safe). There is no exactly-once tool execution across a failover
  (§8). `FileStore`'s CAS holds only on a single host / lock-correct shared
  filesystem; cross-host deployments need the PostgreSQL store
  (`session_store: postgres://...`).

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
defense against that requires **external anchoring** (the `Anchor` /
`FileAnchor` interface exists; a witnessed external anchor is Labs).

## Delivery vs. execution guarantees (summary)

| Property | Guarantee |
|---|---|
| In-order frame delivery | Yes, within a session |
| Duplicate suppression on reconnect | Yes |
| Gateway restart continuity of audit chain | Verified on read; restart-safe append is in progress |
| Exactly-once tool execution | **No** — requires an end-to-end idempotency protocol |
| Automatic retry of unknown-outcome mutating call | **No** — only safe/idempotent-keyed calls may retry |
| Cross-gateway session HA | **No** with file storage; needs a CAS-capable shared store |

See `docs/spec/SECURITY-CLOSURE.md` for the per-finding reproduction, fix,
tests, and residual risk, and `docs/CAPABILITY-MATRIX.md` for maturity.
