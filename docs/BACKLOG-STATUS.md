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
| 4 | Steer hosting decision | todo | Direction: document "agent-runtime concern" rationale |
| 5 | Transactional Handoff v2 | todo | After 7+8; the flagship |
| 6 | Spaces / `group:` fan-out | todo | |
| 7 | Idempotency-key enforcement | todo | mcp framework middleware + pgstore table |
| 8 | Lease renewal + standby sweep | todo | |
| 9 | HTTP per-session policy parity | todo | |
| 10 | AKS pillars 1–3 | todo | Phase 4 stays deferred by design |
| 11 | F25 multi-tenant control plane | todo | |
| 12 | F31 SSO/OIDC mapping | todo | |
| 13 | F30 drag-to-handoff | todo | Blocked on 5 until 5 ships |
| 14 | Native mobile shell + APNs/FCM | **blocked** | Needs mobile toolchain + physical device |
| 15 | S33 govulncheck in CI | **blocked-CI** | Workflow YAML can be pre-staged; unverifiable until 1 |
| 16 | Witnessed audit anchoring | todo | |
| 17 | Backend secret-egress restriction | todo | Containment scope per threat model |
| 18 | OTel/OTLP exporter | todo | |
| 19 | Wave-2 minors | todo | Thematic batches: policy UX / transfer UX / client builds / misc |
| 20 | Placeholder modules | todo | Doctor implementable; sibling modules have no git remote — local + documented |
| 21 | Router delegation wiring | todo | **Security priority — first meaty task** |
| 22 | Postgres CAS in CI | **blocked-CI** | Workflow YAML can be pre-staged; unverifiable until 1 |
| 23 | Fenced-dispatch regression test | todo | |
| 24 | FileStore lock-steal hardening | todo | |
| 25 | Thin policy test spots | todo | |
| 26 | Steer close/resume race fix | **done** | Atomic sendClose; quarantine removed from ci.yml; zero review findings |
| 27 | Manifest gating decision | **done** | Decided (b): distribution-only; boundary documented in MARKETPLACE.md |
| 28 | SpiffeLabel schema/doc pairing | todo | |
| 29 | `air stream` over the mesh | todo | |
| 30 | `frameAttack` rename | **done** | Shipped 2026-07-23 |

## Execution order

30 → 24 → 23 → 25 → 21 → 26 → 28 → 29 → 27 → 3+4 (docs) → 7 → 8 → 16 → 18 →
19 (batches) → 9 → 6 → 10 → 5 → 13 → 12 → 11 → 20 → pre-stage 15+22 YAML.

One PR per task; the tracker row flips in that same PR; backlog re-checked
after every merge.
