# Backlog task tracker

Live execution status for [BACKLOG.md](BACKLOG.md), one row per item. Updated
in the same PR that ships each item. Mission definition of done: every
non-blocked item done — implemented, tested (unit + end-to-end where the item
allows), wired, documented, and merged to main. Blocked items carry their
reason and are excluded from the DoD until unblocked. Section F (items 31–44)
is in-flight authoring by a parallel session and enters this tracker when its
content lands in BACKLOG.md.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | GitHub Actions billing | **blocked** | Account/billing action — operator only |
| 2 | Dependabot #19 cosign-installer | **done** | Merged 2026-07-23 |
| 3 | Approvals hosting decision | **done** | Decided: gateway-colocated; rationale in AIR-ECOSYSTEM.md |
| 4 | Steer hosting decision | **done** | Decided (a): agent-runtime concern; rationale in AIR-ECOSYSTEM.md (shipped with task 3) |
| 5 | Transactional Handoff v2 | todo | After 7+8; the flagship |
| 6 | Spaces / `group:` fan-out | **done** | group: resolves to members via /v1/groups; per-member independently governed steer/ring fan-out; group never authority |
| 7 | Idempotency-key enforcement | **done** | mcp.Idempotency middleware + Mem/PG claim stores; review fixed (tool,key) scoping |
| 8 | Lease renewal + standby sweep | **done** | Always-on renewal, release-on-shutdown, opt-in standby adoption at 2xTTL margin; 5 review findings fixed |
| 9 | HTTP per-session policy parity | **done** | Taint + secrets + capabilities on Streamable HTTP; per-session state, SSE redaction; refused features still refused |
| 10 | AKS pillars 1–3 | **done** | Record-level subgraph scoping + provenance, supersede/alias, RAG entity-linking, governed graph loop; Phase 4 deferred |
| 11 | F25 multi-tenant control plane | **v1 done** | Per-tenant policy/registry/enrollment/audit keyed on transport identity in the authorize chokepoint; per-tenant RBAC (no cross-tenant super-role); one hash chain per tenant; deny-by-default; single-tenant byte-identical. Full isolation matrix in control/tenant_test.go. Honest boundary: shared NetBird PAT (groups+attribution, not account isolation), shared anchor witness. See MULTI-TENANT.md |
| 12 | F31 SSO/OIDC mapping | **done** | Verified OIDC claim -> transport-key-bound additive attribution; SSO groups drive policy group: rules; transport stays root; 0 review findings |
| 13 | F30 drag-to-handoff | todo | Blocked on 5 until 5 ships |
| 14 | Native mobile shell + APNs/FCM | **blocked** | Needs mobile toolchain + physical device |
| 15 | S33 govulncheck in CI | **blocked-CI** | Workflow YAML can be pre-staged; unverifiable until 1 |
| 16 | Witnessed audit anchoring | **done** | Self-linked FileAnchor + governed PeerAnchor witness + verify cross-check; review fixed hot-path stall |
| 17 | Backend secret-egress restriction | todo | Containment scope per threat model |
| 18 | OTel/OTLP exporter | **done** | Zero-dep OTLP/HTTP logs sink; drop-not-block proven; bounded shutdown drain |
| 19 | Wave-2 minors | in-progress | Batch A done (S19 jti replay, S21 bounded dash tail, S51 audit rotation, S49 config lint); batch B queued |
| 20 | Placeholder modules | **done (scoped)** | meshmcp-app: decided no purpose (WORKSPACE-MODULES.md); cross-store doctor scoped, blocked-external (meshmcp-service has no git remote to ship to) |
| 21 | Router delegation wiring | **done** | Minted per-call, verified when pinned, caller from token; review fixed side-effecting caller-leg |
| 22 | Postgres CAS in CI | **blocked-CI** | Workflow YAML can be pre-staged; unverifiable until 1 |
| 23 | Fenced-dispatch regression test | **done** | Bound proven in handshake + backend modes |
| 24 | FileStore lock-steal hardening | **done** | Owner-token release; steal contract preserved |
| 25 | Thin policy test spots | **done** | 8 new test files: cosign, pending, groups, shadow, cost/quota, windows, merkle, checkpoint |
| 26 | Steer close/resume race fix | **done** | Atomic sendClose (structural) + reconnectLoop drain-wait (parallel session, defensive); quarantine removed |
| 27 | Manifest gating decision | **done** | Decided (b): distribution-only; boundary documented in MARKETPLACE.md |
| 28 | SpiffeLabel schema/doc pairing | **done** | trust_domain config; stdio+HTTP emit; chain byte-identity proven |
| 29 | `air stream` over the mesh | **done** | Shipped 2026-07-23; review fixed escape-injection + inbound-line cap |
| 30 | `frameAttack` rename | **done** | Shipped 2026-07-23 |

## Execution order

30 → 24 → 23 → 25 → 21 → 26 → 28 → 29 → 27 → 3+4 (docs) → 7 → 8 → 16 → 18 →
19 (batches) → 9 → 6 → 10 → 5 → 13 → 12 → 11 → 20 → pre-stage 15+22 YAML.

One PR per task; the tracker row flips in that same PR; backlog re-checked
after every merge.
