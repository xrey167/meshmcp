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

- **Defended:** Secrets are injected only into declared backend-owned argument
  locations and never returned to the agent by the gateway; secret **names**
  (never values) appear in audit. The guarantee is **credential isolation**.
- **Limit:** A malicious backend that receives an injected secret is within the
  secret's exposure boundary and can misuse or attempt to echo it. Response-side
  redaction and egress restriction are partial/Labs (Phase 8).

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
- **Limit:** Records after the last checkpoint (an *unsealed* tail) are
  tamper-evident only once a checkpoint seals them.

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
- **Limit:** the session *server's* failover path does not yet route through the
  lease API (it still checkpoints via unconditional `Save`); wiring
  lease-expiry-driven takeover + per-write fencing into the server is the
  remaining step. `FileStore` provides CAS only for a single host / lock-correct
  shared filesystem and is **not** cross-gateway HA — production needs a real
  CAS backend (PostgreSQL, etcd, or Redis). Until the server wiring lands, do
  not run two gateways over one shared session store in production.

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
