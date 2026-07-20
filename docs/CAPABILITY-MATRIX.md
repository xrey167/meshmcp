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
| MCP gatewaying (Streamable HTTP) | Beta | HTTP | Same policy pipeline as stdio | Enforcement-parity conformance suite (Phase 7) still landing | none | none | httppolicy tests | Recommended, verify parity for your config |
| Per-identity tool/method policy | Stable | stdio, HTTP | Default-deny tools; opt-in method governance; ID-less/ambiguous `tools/call` cannot bypass policy | — | none | none | filter + fuzz | Recommended |
| Control-plane RBAC | Stable | mesh HTTP | Default-deny, transport-derived roles; ordinary peers cannot administer; fail-closed startup | Bootstrap credential redesign + policy optimistic-concurrency are follow-ups | registry/policy dirs | files | control RBAC tests | Recommended |
| Request-specific human approval | Beta | mesh HTTP | Mandatory approver ACL; approver identity from transport | Per-(peer,tool) ambient grant, not yet request-bound/single-use (Phase 3) | approver store dir | files | approvals tests | Use with a tight TTL |
| Gateway-signed tamper-evident audit | Stable | n/a | Four-state signed verification; only *sealed* + pinned key is complete & trusted | Not caller non-repudiation; insider rollback needs external anchoring | optional anchor | JSONL + checkpoints | signed-verify + state tests | Recommended; pin `--pubkey`, seal + anchor |
| Scoped session resumption | Beta | stdio, HTTP | In-order delivery + duplicate suppression on reconnect | Single-node; not cross-gateway HA; no exactly-once execution | shared dir (dev) | files | session tests | Single-node only |
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
| Pub/sub fabric | Experimental | Rich delivery semantics; at-least-once with caveats; not part of the security wedge. |
| GraphRAG / knowledge graph | Experimental | Payload-layer feature. |
| Agent memory fabric | Experimental | Payload-layer feature. |
| Scheduler | Experimental | Orchestration convenience. |
| Marketplace / plugins | Experimental | Extension surface. |
| Mobile workflows | Experimental | Companion UX. |
| Cost governance | Experimental | Budgeting/quota heuristics. |
| Automatic policy generation (`insight`) | Experimental | Generates least-privilege drafts to review; not an enforcement control by itself. |

## Planned (designed, not implemented)

| Capability | Phase |
|---|---|
| Request-bound, signed, single-use approval objects | 3 |
| Wire the signed delegation-token primitive (done + tested) into the router/upstream proxy path + caller ACL | 4 |
| Restart-safe audit append (seed from verified tail; refuse unverifiable) | 5 |
| External audit anchoring interface (witnessed) | 5 |
| Wire the CAS/fencing session-lease primitive (done at store layer) into the server failover path | 6 |
| Explicit tool retry classification + enforced idempotency keys | 6 |
| stdio/HTTP enforcement-parity conformance suite + capability matrix | 7 |
| Response-side secret redaction + egress restriction | 8 |
| Strict config (`KnownFields`) across all security config + typo negative tests | 9 |
| MCP protocol-version negotiation + supported-version matrix | 9 |
| Required CI (build/test/race/vuln/fuzz) and signed releases + SBOM | 11 |

## Recommended v0.1 production surface

Use the **Stable** and audited **Beta** rows over stdio and Streamable HTTP:
private mesh + transport identity, tool/method policy, control-plane RBAC,
mandatory-ACL approvals (tight TTL), and sealed+pinned signed audit. Treat every
Labs capability as convenience, not a control.
