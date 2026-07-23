# Backlog

The standing list of open work. Each item carries its user story, the ways to
go (with a recommendation where one is warranted), and what landing it brings.
Last full review: 2026-07-23, after the deep audit and its follow-up wave
(conformance harnesses, `pgstore`, the checkpoint-ordering fix, Prometheus
metrics, retry classification, steer logical addressing, Air Node hosting
slices 1–3, the `air database` PostgreSQL executor, and the HTTP embedder all
shipped). Section E was added the same day from a subsystem deep-dive
(policy / session-lease / Air). An item leaves this file when it merges; docs
claiming status must track this file, not the other way around. There are no
literal TODO/FIXME markers in the source tree — this file is the only backlog.

Suggested default order: **1 → 2** (unblock CI, let it validate everything
already merged), then **7 + 8** (they complete the reliability story Phase 6
started), then **5** (Handoff v2, the differentiator). Items 3–4 need only a
decision; the answer is a small PR either way. Of the section-E items, **21**
(router delegation) carries real security weight and should ride ahead of any
new router-facing features; **22** and **26** piggyback on item 1 for nearly
free.

---

## A. Operational unblocks

### 1. GitHub Actions billing

- **Story:** As the maintainer, I want every merge validated on a clean runner,
  so that "green" means something beyond one Windows dev machine.
- **Ways to go:** Fix the billing state in GitHub settings; or move CI to a
  self-hosted runner if billing is a non-starter.
- **Brings:** Validation of the whole recent wave on Linux/macOS, and the first
  `-race` pass over the newest concurrency code (checkpoint serialization,
  shared replay stores, the ring limiter) — local dev runs with CGO disabled
  and cannot produce one. Also unblocks items 15, 22, and 26 and the release
  pipeline.

### 2. Dependabot PR #19 — cosign-installer 4.1.2

- **Story:** As a release consumer, I want binaries signed by an up-to-date,
  unvulnerable toolchain, so that supply-chain trust in releases holds.
- **Ways to go:** One-click merge; it touches only the workflow file.
- **Brings:** Closes the last open Dependabot item at zero risk (Actions is not
  even running until item 1 lands).

---

## B. Open design decisions

### 3. Approvals hosting in `air node`

- **Story:** As an operator on a laptop or phone, I want one command that makes
  my device present on the mesh *and* able to receive and resolve co-sign
  requests, so that being "the approver" does not require a second daemon.
- **Ways to go:** (a) Add `--approvals-port/--approvals-store/--approvals-allow`
  to `air node`, reusing the existing approver server behind the shared
  accept-loop pattern — mechanically easy, the hosting-slice template fits.
  (b) Decide approvals remain a gateway/dedicated-process concern and record
  the rationale in AIR-ECOSYSTEM.md. The real question is where the cosign
  store (pending-approval state) should live: node-local state dies with the
  device.
- **Brings:** (a) completes the "one device = one process" story for operator
  devices; (b) keeps approval state centralized and auditable in one place.
  Either answer closes the item.

### 4. Steer hosting in `air node`

- **Story:** As an agent author, I want my agent steerable the moment its node
  announces, so that "reachable" and "steerable" are not separate setups.
- **Ways to go:** (a) Do not build it — the steer inbox belongs to the agent
  runtime itself (an agent that wants steering should embed the presence client
  and its own inbox); document the rationale. (b) Build a thin proxy: the node
  hosts a steer port and forwards envelopes to a local process — which adds a
  hop and a trust question (the node then speaks for the agent).
  **Recommendation: (a).**
- **Brings:** (a) keeps the identity story clean — steers land at the identity
  that executes them; (b) buys convenience at the cost of blurring who received
  the steer.

---

## C. Roadmap bets (each is a project)

### 5. Transactional Handoff v2 — live session migration

- **Story:** As a user mid-task on my laptop, I want to move a *live* agent
  session to my desktop — not just an inert context capsule — so that
  long-running work follows me across devices without a restart.
- **Ways to go:** Build the prepare → ready → commit protocol on the shipped
  substrate: the source gateway freezes and drains the session, checkpoints
  through the fenced store, the destination acquires via a single-use grant
  plus `TakeoverLease`, commit swaps ownership atomically, abort rolls back.
  Needs checkpoint adapters per backend mode and split-brain recovery tests —
  `session/storetest.RunSessionMigration` is the scaffold to extend.
- **Brings:** The product differentiator — no MCP gateway does live session
  movement. Every prerequisite (distributed CAS leases, fencing, serialized
  checkpoints, the end-to-end migration harness) is merged, so this is now
  purely protocol work.

### 6. Spaces / `group:` fan-out

- **Story:** As an operator, I want to say "steer *the research team* to
  refocus" and have it reach every member as individually authorized, audited
  actions, so that group coordination does not mean N manual commands.
- **Ways to go:** Resolve `group:<name>` (the grammar in `air/target.go`
  already reserves the kind) against the config `groups:` map or Presence
  labels; fan out as N independent calls, each entering its destination's
  ACL/policy separately; return a per-member receipt list — the
  `air.action-result/v1` envelope generalizes naturally to N recipients.
- **Brings:** The first multi-device coordination primitive, and the foundation
  the ecosystem doc's Spaces vision (shared activity boards, group automations)
  builds on.

### 7. Backend-side idempotency-key enforcement

- **Story:** As the operator of a payments backend, I want a retried
  `tools/call` carrying the same idempotency key to execute *exactly once*, so
  that transport ambiguity can never double-charge.
- **Ways to go:** A keyed result cache in the `mcp` server framework
  (middleware: on `_meta["meshmcp.io/idempotency-key"]`, atomically claim the
  key; the first execution stores its result, replays return it). Backing
  store: in-memory for single-process backends, a `pgstore` table for
  replicated ones — the replay-store pattern is already written.
- **Brings:** Upgrades `retry_tools` from "the operator promises the tool is
  idempotent" to *enforced* exactly-once, letting even mutating tools be safely
  classified. Closes capability-matrix Phase 6 completely.

### 8. Lease renewal + expiry-driven automatic failover

- **Story:** As an operator running two gateways, I want the sessions of a
  crashed gateway claimed by the survivor *without waiting for each client to
  reconnect*, so that server-initiated work (subscriptions, tasks) survives
  too.
- **Ways to go:** Wire `RenewLease` into a per-session heartbeat while serving;
  add a standby sweep that lists sessions with expired leases and proactively
  rehydrates them (the client's reattach is still identity-bound). The
  dangerous edge is a paused-not-dead gateway — the fencing generation already
  protects the write side; the sweep needs conservative expiry margins.
- **Brings:** True active-passive HA rather than reattach-driven failover, and
  the lease TTL machinery finally earns its keep.

### 9. HTTP transport per-session policy parity

- **Story:** As a security team running Streamable-HTTP backends, I want taint
  tracking, secret injection, and capability upgrades to apply there exactly as
  on stdio, so that transport choice never weakens policy.
- **Ways to go:** Give the HTTP enforcer per-session state keyed on MCP session
  IDs, and add SSE/response body rewriting for redaction and label extraction.
  The stdio `Filter` is the reference implementation to port behind the shared
  `ClassifyRPC`.
- **Brings:** Removes the biggest honest limitation in the capability matrix;
  HTTP backends stop being second-class policy citizens.

### 10. Air Knowledge System pillars (Phases 1–3)

- **Story:** As an agent builder, I want a provenance-native knowledge graph
  and hardened retrieval where every triple and chunk is identity-stamped and
  subgraph-scoped, so that "what does my agent know and where did it learn it"
  is provable.
- **Ways to go:** Follow AIR-KNOWLEDGE-SYSTEM.md's accepted sequence: Phase 1
  air-kg on the complete Phase-0 spine (single-writer serialization, KnowHash
  provenance), Phase 2 air-rag hardening (the HTTP embedder raised its
  ceiling), Phase 3 the governed agent-loop runner through a caller-side
  gateway. Phase 4 (LLM-gated generation) stays deliberately deferred.
- **Brings:** Turns the kg/rag verbs from features into the knowledge substrate
  the vision docs sell.

### 11. F25 · Multi-tenant control plane

- **Story:** As a platform team, I want one control service hosting many
  orgs/teams with isolated policy stores, enrollment, and audit, so that
  meshmcp can be operated *for* customers, not just by them.
- **Ways to go:** Introduce a tenant dimension in `control/` — per-tenant RBAC
  roots, storage prefixes, and audit chains — with tenancy derived from the
  enrolling identity, never from request data; the existing transport-derived
  RBAC is the pattern to extend.
- **Brings:** The commercial shape: managed meshmcp. Also forces the storage
  abstractions (registry, policy store) to mature.

### 12. F31 · SSO/OIDC → mesh identity mapping

- **Story:** As an enterprise admin, I want org SSO groups to drive mesh policy
  ("the finance group may call billing tools"), so that joining or leaving the
  company automatically grants and revokes tool access.
- **Ways to go:** Map verified OIDC claims to mesh identities at the federation
  seam or at enrollment time (an attested "this WireGuard key belongs to
  alice@corp" record); policy rules then match on mapped groups. The edge
  ingress already provides an OAuth surface to anchor the flow.
- **Brings:** The enterprise-adoption unlock — identity lifecycle stops being
  manual key management.

### 13. F30 · Control-Room drag-to-handoff

- **Story:** As an operator watching the Control Room, I want to drag a live
  session tile from gateway A to gateway B, so that migration is a gesture
  instead of a CLI incantation.
- **Ways to go:** Pure UX over item 5's protocol — blocked until it exists;
  then it is a Control Room front-end plus a control-plane endpoint invoking
  prepare/commit.
- **Brings:** The demo that sells Handoff v2; no independent backend work.

### 14. Native mobile shell + direct APNs/FCM notifier

- **Story:** As a phone user, I want Face-ID-gated approvals and share-sheet
  drops in a real app with hardware-backed keys, so that the phone is a
  first-class mesh citizen.
- **Ways to go:** `gomobile bind ./mobile` → an xcframework/aar wrapped in thin
  SwiftUI/Kotlin shells (the binding package ships); a direct APNs/FCM notifier
  needs vendor credentials held by the operator's relay. Externally blocked on
  the mobile toolchain and a physical device — it cannot be finished from this
  repo alone.
- **Brings:** The consumer half of the Air vision. The vendor-credential-free
  webhook notifier already covers push delivery until then (MOBILE.md §4).

---

## D. Hardening backlog (Wave-2 residue)

### 15. S33 · govulncheck + fork-pin audit in CI

- **Story:** As the maintainer, I want dependency vulnerabilities and drifting
  fork pins caught at PR time, so that the next grpc-style advisory is a CI
  failure, not a Dependabot surprise.
- **Ways to go:** Add a govulncheck job plus a replace-directive pin check to
  ci.yml. Depends on item 1.
- **Brings:** Automated supply-chain hygiene for a codebase whose selling point
  is provable security.

### 16. Witnessed external audit anchoring (Phase 5 residue)

- **Story:** As an auditor, I want checkpoint hashes escrowed outside the
  gateway, so that even a compromised gateway cannot silently rewrite history.
- **Ways to go:** An `Anchor` interface posting sealed checkpoint roots to an
  external witness — another mesh peer, a transparency log, or RFC 3161
  timestamping — with `audit verify` cross-checking anchored roots.
- **Brings:** Upgrades "tamper-evident" toward "tamper-proof against the
  operator", closing the insider-rollback limit the threat model currently
  concedes.

### 17. Backend secret-egress restriction (Phase 8 residue)

- **Story:** As a security team, I want a backend that received an injected
  secret to be unable to exfiltrate it out of band, so that credential
  isolation holds against a malicious backend, not just a careless one.
- **Ways to go:** Egress policy on backend subprocesses — network namespaces or
  per-backend firewall rules restricting them to mesh-only connectivity. Honest
  scope: this is containment, not cryptography; short-lived scoped credentials
  remain the primary mitigation.
- **Brings:** Closes the determined-leak caveat in threat-model §5.

### 18. OTel/OTLP exporter

- **Story:** As an SRE, I want meshmcp's traces and metrics in my existing
  observability stack, so that agent traffic correlates with everything else I
  run.
- **Ways to go:** An `AuditSink` observer exporting OTLP. This adds the otel
  dependency — a deliberate exception to the dependency-light ethos, which is
  why it stayed separate from the shipped hand-rolled Prometheus endpoint.
- **Brings:** Fleet-grade observability with span context across
  gateway→backend hops.

### 19. Wave-2 minors

- **Story:** Each is a small "as an operator I want this sharp edge removed":
  S19 (capability jti replay cache), S21 (bounded/tailing dashboard read),
  S44 (config-driven per-tool timeout/concurrency middleware), S45 (thin
  connect-only client build), S46 (physical-roam integration test), S49–S51
  (policy lint/templates, policy hot-reload, audit-log rotation), S53–S60
  (drop `--resume` receipts, CAS gc / `fetch --gc`, `--json` CLI output,
  rate-limit retry-after metadata, capability delegation/sub-grants, federation
  metering/billing export, natural-language mesh-ops verbs, Control-Room
  multiplayer presence).
- **Ways to go:** Independent afternoon-sized PRs, best batched thematically —
  policy UX (S49–S51), transfer UX (S53–S55), client builds (S45).
- **Brings:** Accumulated polish; none is load-bearing alone, which is why they
  are minors.

### 20. Empty placeholder modules

- **Story:** As a capability-plane operator, I want `meshmcp-service`'s planned
  cross-store doctor detecting dangling references between promptd, agentd, and
  skilld before they bite at serve time — and I want `meshmcp-app` to either
  gain a purpose or stop existing.
- **Ways to go:** Implement the doctor per the plan already written in the
  agentd/promptd docs (§2.2/M7); for `meshmcp-app`, decide between a concrete
  purpose and deletion — deleting is a valid answer.
- **Brings:** Closes the workspace's named-but-empty gaps so the module list
  tells the truth.

---

## E. Gaps from the 2026-07-23 subsystem deep-dive

Findings from a code-level audit of `policy/`, `session/` + `pgstore/`, and
Air. Items overlapping the sections above were folded into items 1, 8, and 9;
everything else lands here.

### 21. Wire delegation into the router

- **Story:** As a security team fronting backends with an aggregating router, I
  want upstreams to verify a *signed* delegation bound to the original caller,
  so that a compromised router cannot act as a confused deputy with its own
  broad identity.
- **Ways to go:** The primitive is complete and adversarially tested
  (`policy/delegation.go`: `IssueDelegation` / `VerifyDelegation` /
  `AuthorizeDelegated`, scope intersection, nonce replay) but has **zero
  production call sites** — the live router forwards the caller as unsigned
  `_meta` (`cmd/meshmcp/router.go:230-264`), exactly the pattern
  `delegation.go:12-18` warns must never be trusted. Wire it: the router mints
  a per-call delegation token; upstream gateways verify against a pinned router
  authority key and compute caller ∩ router ∩ delegation scope. Roll out behind
  config with the unsigned-`_meta` hint as the migration fallback.
- **Brings:** Closes the single largest enforcement gap; router aggregation
  graduates from Labs to supported, and threat-model §3 flips from
  "experimental" to defended.

### 22. Postgres CAS path in CI

- **Story:** As the maintainer, I want the production HA lease SQL exercised on
  every PR, so that the code guarding split-brain is not opt-in tested.
- **Ways to go:** Once item 1 lands, add a `postgres:16` service container to
  the workflow and set `MESHMCP_TEST_PG_DSN`; every currently-skipping
  `pgstore` integration test (conformance, migration, executor) runs for free.
- **Brings:** The `FOR UPDATE` serialization and `ON CONFLICT` arbitration
  stop depending on a developer remembering to run Docker locally.

### 23. Fenced-gateway residual dispatch regression test

- **Story:** As a security reviewer, I want the documented one-message residual
  window (a fenced gateway dispatching one last inbound message before its next
  `SaveIfOwned` detects the takeover, `session/server.go:465` vs `:472`)
  asserted by a test, so that the bound cannot silently widen.
- **Ways to go:** Extend the migration harness: race a takeover against an
  in-flight message on the losing gateway; assert at most one residual dispatch
  reaches its backend and that the fence yields on the next checkpoint; assert
  `MigrateBackend` mode removes the residual entirely.
- **Brings:** A documented window becomes a proven bound — the difference
  between a comment and a guarantee.

### 24. FileStore lock-steal hardening

- **Story:** As a single-host operator, I want a process stalled past the 10s
  staleness window unable to delete the *new* holder's lock, so that the
  dev-default store cannot corrupt itself under a long GC pause or laptop
  sleep.
- **Ways to go:** Write an owner token into the lock file
  (`session/flock.go:35-46`) and make `release()` check-before-remove; or, at
  minimum, assert the single-host caveat loudly at startup. The window is
  within the documented caveat — this is hardening, not a broken promise.
- **Brings:** The FileStore's stall edge closes; `pgstore` remains the answer
  for anything multi-host.

### 25. Thin policy test spots

- **Story:** As the maintainer of a security product, I want every
  security-relevant primitive pinned by direct tests, so that "hardened core"
  is uniformly true rather than true on average.
- **Ways to go:** Targeted table tests for ambient `FileCosign` (one test today
  despite its role), `groups.go`, `shadow.go`, rate-limit `Cost`/quota
  accounting, and `Window` overnight/timezone edges; add dedicated
  `merkle_test.go` / `checkpoint_test.go` covering odd-node promotion and the
  error-retention path (`checkpoint.go:154-171`), both only indirectly covered
  today.
- **Brings:** The audit-spine and policy edges gain the same direct coverage
  the headline paths already have.

### 26. Un-quarantine the steer tests

- **Story:** As the maintainer, I want the steer suite running on every OS with
  its real race fixed, so that quarantined tests stop hiding a client-visible
  bug.
- **Ways to go:** `TestTaskSteer` passes locally under `-race -count=20` and
  needs cross-OS confirmation (rides item 1).
  `TestSteerDeliveryRequiresApplicationAck` exposes a genuine close/resume
  sequencing race on synchronous transports: a one-shot client's graceful
  drain can race a just-finalized session into a terminal
  `errSessionNotFound`. Fix belongs in the `session/` reconnect path — treat a
  drain-phase reattach against a finalizing session as retriable — then
  re-enable the test.
- **Brings:** One fewer quarantine, one real race fixed where users would
  eventually hit it.

### 27. Marketplace manifests gating execution

- **Story:** As an operator who installs signed plugin bundles, I want the
  signature to mean something at runtime — or the docs to say plainly that it
  does not — so that the trust boundary is where I think it is.
- **Ways to go:** (a) Enforce at startup: the compiled-in plugin set must match
  installed, signed manifests (`policy/manifest.go:14-24`), refusing on
  mismatch. (b) Document the admission system as governing *distribution* only
  (compile-time inclusion remains the execution gate, per the no-dynamic-loading
  stance) and close. Both are defensible; (b) is smaller and matches the
  existing extension philosophy.
- **Brings:** Either a real runtime gate or an honest boundary statement;
  today it is ambiguous.

### 28. `SpiffeLabel` schema/doc pairing

- **Story:** As a federation operator, I want the SPIFFE identity label on
  audit records emitted per a documented schema, so that downstream consumers
  can rely on it.
- **Ways to go:** Finish the derivation + schema/doc pairing promised in
  OAUTH-STANDARDS Feature A (`policy/audit.go:48-52` admits the field partly
  exists to unblock test compilation); or remove the field if the feature is
  abandoned.
- **Brings:** An additive audit field becomes real instead of vestigial.

### 29. `air stream` over the mesh

- **Story:** As an operator, I want to tail a remote gateway's governed events
  without file access to its disk, so that Air's "over the mesh" promise holds
  for observation too.
- **Ways to go:** Add a mesh mode to `air stream`
  (`cmd/meshmcp/airstream.go:20-22` self-declares this as the next step):
  subscribe to the gateway-hooks event bus over the identity-gated pub/sub
  channel and render the same decision-coloured rows the file tail renders.
- **Brings:** Closes the one place Air's "over the mesh" claim is aspirational.

### 30. `frameAttack` typo

- **Story:** As a contributor, I do not want to keep propagating a misspelled
  constant, so that grep for the ATTACH frame finds it.
- **Ways to go:** Mechanical rename `frameAttack` → `frameAttach` across
  `session/` (`session/frame.go:24` and spread).
- **Brings:** Cosmetic clarity; zero behavior change.
