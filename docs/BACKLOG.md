# Backlog

The standing list of open work, grouped by what unblocks it. Last full review:
2026-07-23, after the deep audit and its follow-up wave (conformance harnesses,
`pgstore`, checkpoint-ordering fix, metrics, retry classification, steer logical
addressing, Air Node hosting slices 1–3, the `air database` PostgreSQL executor,
and the HTTP embedder all shipped). An item leaves this file when it merges;
docs claiming status must track this file, not the other way around.

## A. Operational unblocks

1. **GitHub Actions billing** — Actions is locked out, so no CI validates
   merges on a runner. Fixing it also enables the `-race` pass the newest
   concurrency code (checkpoint serialization, shared replay stores, ring
   limiter) has never had — local dev runs with CGO disabled.
2. **Dependabot PR #19** — `sigstore/cosign-installer` 4.1.2 bump for the
   release workflow. Open, mergeable, harmless.

## B. Open design decisions

3. **Approvals hosting in `air node`** — should a node host the co-sign
   approver? It pulls the cosign store into the node process. Approving is an
   operator-device role, so a phone/laptop node arguably fits — but it moves
   where approval state lives. Decide before building.
4. **Steer hosting in `air node`** — the steer inbox belongs to the agent
   runtime; a node hosting it would proxy steers into some local process.
   Leaning "no — document why" over building it. Decide, then either build or
   record the rationale in AIR-ECOSYSTEM.md.

## C. Roadmap bets (each is a project)

5. **Transactional Handoff v2** — true live-session migration
   (prepare → ready → commit, checkpoint adapters, single-use grants, lease
   fencing, split-brain recovery tests). The declared flagship; its store-layer
   prerequisites (distributed CAS lease store, fenced serialized checkpoints,
   migration harness) are all shipped.
6. **Spaces / `group:` fan-out** — named agent/device groups; one action fans
   out as N individually policy-checked, audited calls. `air/target.go` already
   reserves the `group` kind; nothing resolves it yet.
7. **Backend-side idempotency-key enforcement** — the other half of Phase 6: a
   backend honoring `_meta["meshmcp.io/idempotency-key"]` so a retried
   mutating call becomes exactly-once. The router conveys the key today
   (`retry_tools`); nothing enforces it.
8. **Lease renewal + expiry-driven automatic failover** — takeover is
   reattach-driven only; `RenewLease`/`ReleaseLease` are unused outside tests
   and a standby never claims a dead gateway's sessions on its own.
9. **HTTP transport per-session policy parity** — taint labels, secret
   injection, and capability upgrades remain stdio-only; Streamable-HTTP needs
   per-session state / SSE body rewriting (capability-matrix Phase 7).
10. **Air Knowledge System pillars** — the accepted architecture's Phase 1–3
    (air-kg provenance backend, air-rag hardening, air-agent-graph via a
    caller-side governing gateway), plus the deliberately LLM-gated Phase 4.
    See AIR-KNOWLEDGE-SYSTEM.md.
11. **F25 · multi-tenant control plane** — per-tenant policy stores,
    enrollment, and audit isolation over one dark control service.
12. **F31 · SSO/OIDC → mesh identity mapping** — org SSO driving policy at the
    federation seam.
13. **F30 · Control-Room drag-to-handoff UX** — the visual layer over Handoff;
    blocked on item 5.
14. **Native mobile shell + direct APNs/FCM notifier** — externally blocked:
    needs the mobile toolchain and a physical device. The `gomobile` binding
    package and the vendor-credential-free webhook notifier already ship
    (MOBILE.md).

## D. Hardening backlog (Wave-2 residue)

15. **S33** — govulncheck + fork-pin audit as a CI gate (ties to item 1).
16. **Phase 5 residue** — witnessed external audit anchoring interface.
17. **Phase 8 residue** — backend egress restriction for injected secrets
    (response-side redaction ships; egress control does not).
18. **OTel/OTLP exporter** — the full-fat sibling of the shipped Prometheus
    `/metrics` endpoint, on the same `AuditSink` seam.
19. **Wave-2 minors** — S19 (capability jti replay cache), S21 (bounded
    dashboard read), S44 (per-tool timeout/concurrency middleware), S45 (thin
    connect-only client build), S46 (physical-roam integration test), S49–S51
    (policy lint/templates, policy hot-reload, audit-log rotation), S53–S60
    (drop `--resume` receipts, CAS gc, `--json` CLI output, rate-limit
    retry-after metadata, capability sub-grants, federation metering, NL
    mesh-ops verbs, Control-Room multiplayer presence).
20. **Empty placeholder modules** — `meshmcp-app` (empty) and
    `meshmcp-service` (the planned cross-store doctor for promptd/agentd/skilld
    dangling-reference detection).

## Suggested default order

**1 → 2** (unblock CI and let it validate everything already merged), then
**7 + 8** (they complete the reliability story Phase 6 started), then **5**
(Handoff v2, the differentiator). Items 3–4 need only a yes/no; the answer is a
small PR either way.
