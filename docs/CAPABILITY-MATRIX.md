# Capability Maturity Matrix

Maturity of each capability, so the security core is not conflated with
experimental breadth. Levels:

- **Stable** — a v0.1 core invariant, continuously tested, safe to depend on.
- **Beta** — works and tested, but semantics or API may still change.
- **Experimental (Labs)** — useful but not a security guarantee; do not rely on
  it as a control until promoted.
- **Planned** — designed, not yet implemented.

For each capability: supported transports, the security guarantee, known
limitations, required external services, persistence model, test coverage, and
production recommendation. Guarantees are bounded by
[docs/THREAT-MODEL.md](THREAT-MODEL.md).

## Stable v0.1 core

| Capability | Level | Transports | Guarantee | Known limits | External svc | Persistence | Tests | Production |
|---|---|---|---|---|---|---|---|---|
| Private mesh transport + transport-bound identity | Stable | stdio, HTTP | Caller identity is the WireGuard key proved by the transport; no public application ingress | Depends on a correctly configured NetBird/WireGuard mesh | NetBird mgmt (or static keys) | none | mesh/acl tests | Recommended |
| MCP gatewaying (stdio) | Stable | stdio | Transparent pass-through with policy enforcement on the wire | — | none | none | filter/mcp tests | Recommended |
| MCP gatewaying (Streamable HTTP) | Beta | HTTP | Same classifier + tool/method decisions as stdio (conformance-tested) | Per-session controls (taint/secrets/capabilities) remain stdio-only | none | none | httppolicy + conformance tests | Recommended |
| Per-identity tool/method policy | Stable | stdio, HTTP | Default-deny tools; opt-in method governance; ID-less/ambiguous `tools/call` cannot bypass policy | — | none | none | filter + fuzz | Recommended |
| Control-plane RBAC | Stable | mesh HTTP | Default-deny, transport-derived roles; ordinary peers cannot administer; fail-closed startup | Bootstrap credential redesign + policy optimistic-concurrency are follow-ups | registry/policy dirs | files | control RBAC tests | Recommended |
| Request-specific human approval | Beta | mesh HTTP | Mandatory approver ACL; approver identity from transport | Per-(peer,tool) ambient grant, not yet request-bound/single-use (Phase 3) | approver store dir | files | approvals tests | Use with a tight TTL |
| Gateway-signed tamper-evident audit | Stable | n/a | Four-state signed verification; only *sealed* + pinned key is complete & trusted | Not caller non-repudiation; insider rollback needs external anchoring | optional anchor | JSONL + checkpoints | signed-verify + state tests | Recommended; pin `--pubkey`, seal + anchor |
| Scoped session resumption | Beta | stdio, HTTP | In-order delivery + duplicate suppression on reconnect; cross-gateway failover on identity-verified reattach (lease takeover + fenced, serialized checkpoints) | No exactly-once execution; takeover is reattach-driven only (no expiry-driven standby claim) | optional PostgreSQL (`pgstore`) | files or PostgreSQL (`session_store` DSN) | session + storetest conformance and end-to-end migration (both backends, incl. live PostgreSQL) | Cross-host HA needs the PostgreSQL store; `FileStore` is single-host |
| Signed capabilities | Beta | stdio, HTTP | Short-lived Ed25519 grants upgrade a default-deny; pinned roots; fail-closed | Revocation-store failure handling hardening ongoing (Phase 9) | none | files | capability tests | Recommended with pinned roots |

## Experimental / Labs

These are useful but are **not** security guarantees yet. Several are slated to
move behind an explicit "Labs" boundary until the core invariants are
continuously tested.

| Capability | Level | Why Labs |
|---|---|---|
| Router aggregation / delegated identity | Experimental | Router forwards under its own identity; downstream caller is unsigned `_meta`. Signed delegation (Phase 4) not yet implemented — potential confused deputy. Use a default-deny caller ACL. |
| Federation (cross-org) | Experimental | Same delegation/identity-intersection gaps as the router at the org boundary. |
| Air (agent orchestration) | Experimental | Control-endpoint hardening in progress (see PR #9); not a core security surface. |
| Air Component Cards v1 | Experimental | Caller-filtered discovery metadata with stable ID, kind, version, advertised owner, canonical features, and lifecycle. Cards are validated and backward-compatible, but unsigned and advisory: live transport identity, ACL, policy, and capability verification remain authoritative. |
| Pub/sub fabric | Experimental | Rich delivery semantics; at-least-once with caveats; not part of the security wedge. |
| GraphRAG / knowledge graph | Experimental | Payload-layer feature. |
| Agent memory fabric | Experimental | Payload-layer feature. |
| Scheduler | Experimental | Orchestration convenience. |
| Marketplace / plugins | Experimental | Extension surface. |
| Mobile workflows | Experimental | Companion UX. |
| Cost governance | Experimental | Budgeting/quota heuristics. |
| Automatic policy generation (`insight`) | Experimental | Generates least-privilege drafts to review; not an enforcement control by itself. |
| DPoP verification primitive (server-side, F35/Feature C0) | Experimental | `policy.DPoPVerifier` (RFC 9449 §4.3/§7.1/§8): alg pinning, htu/htm/jti/iat checks, jkt key-confirmation, ath, bounded jti replay tracking, single-use nonce lifecycle. Green under `policy/dpopverify_test.go`, including a direct signer↔verifier interop test. `meshmcp edge` now constructs the verifier (replay store in-process by default, shared/durable via `oauth.dpop_replay_store` + `pgstore`), but the edge's public surface is bearer-only — proof enforcement is still not wired into any live HTTP handler. The Feature C exposure-model question is now **resolved** (extended Option A — see the decision record in `docs/spec/OAUTH-STANDARDS.md`); the live façade ships as `meshmcp edge` (rows below). |
| Public edge ingress (`meshmcp edge`: OAuth AS + hosted-client MCP endpoint) | Experimental | The product's only public listener — off by default, explicit operator bind + TLS required. Serves RFC 9728/8414 metadata, RFC 7591 DCR (open-approval or IAT-gated), OAuth 2.1 code+PKCE with operator-in-the-loop consent, and one tool-scoped Streamable-HTTP MCP path. Deny-by-default policy + capability double-gate + fail-closed audit; see THREAT-MODEL adversaries 12–13. Experimental until the conformance harness and a real-world claude.ai deployment have soaked. |
| Hosted-client identity (`oauth:<client_id>`) | Experimental | A synthetic, edge-issued identity for hosted MCP clients (e.g. claude.ai connectors), proven by possession of an unexpired, unrevoked edge-issued token — weaker than a WireGuard transport key (deviation D-C/D-D in the exposure-model decision). Scope it with tight default-deny rules; never grant it control-plane roles. |

## Planned (designed, not implemented)

| Capability | Phase |
|---|---|
| Request-bound, signed, single-use approval objects | 3 |
| Wire the signed delegation-token primitive (done + tested) into the router/upstream proxy path + caller ACL | 4 |
| Restart-safe audit append (seed from verified tail; refuse unverifiable) | 5 |
| External audit anchoring interface (witnessed) | 5 |
| Lease renewal + expiry-driven automatic failover (today a standby only takes over on the creator's reattach; the CAS/fencing lease primitive and its server wiring are done and migration-proven) | 6 |
| Backend-side idempotency-key ENFORCEMENT (the router ships operator retry classification via `retry_tools` + a stable conveyed `_meta` idempotency key; a backend honoring the key end-to-end is the remaining half) | 6 |
| Extend stdio/HTTP parity to per-session controls (taint/secrets/capabilities); classification + tool/method decisions are done + conformance-tested | 7 |
| Backend egress restriction for secrets (response-side redaction is done) | 8 |
| Extend strict config (`KnownFields`) to the remaining subsystem configs (gateway config + control ACL done) | 9 |
| MCP protocol-version negotiation + supported-version matrix | 9 |
| Required CI (build/test/race/vuln/fuzz) and signed releases + SBOM | 11 |
| Trust Card + Library: signed provenance and install lifecycle layered over Component Cards and marketplace manifests; discovery never auto-activates code | Ecosystem 2 |
| Universal Resolver: resolve stable IDs, names, intents, and resource references without widening authority or choosing ambiguous names | Ecosystem 3 |
| Continuity Capsules: target-accepted work/artifact references only; no identity swap, token transfer, hidden-context replay, or automatic execution | Ecosystem 4 |
| Governed Automations: schedules and events resolve a concrete actor; every effect passes normal policy, approval, and audit | Ecosystem 5 |
| Native companion app over the existing mobile bindings, with hardware-backed device identity and explicit confirmation for privileged actions | Ecosystem 6 |

## Recommended v0.1 production surface

Use the **Stable** and audited **Beta** rows over stdio and Streamable HTTP:
private mesh + transport identity, tool/method policy, control-plane RBAC,
mandatory-ACL approvals (tight TTL), and sealed+pinned signed audit. Treat every
Labs capability as convenience, not a control.
