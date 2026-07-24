# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/) once it reaches 1.0.

## [Unreleased] — v0.1 security hardening

A security-focused hardening pass turning the prototype into a defensible v0.1
core. Each item was reproduced against the tree, given a failing regression test
first, fixed with the smallest robust change, and documented in
`docs/spec/SECURITY-CLOSURE.md`.

### Security — fixed

- **ID-less `tools/call` bypass**: a `tools/call` without an `id` was handled as
  a notification and skipped tool policy. Dispatch is now by method name first;
  id-less/null-id/empty-name/duplicate-key tool calls are rejected as
  protocol-invalid. Canonical JSON parsing rejects duplicate security-relevant
  keys. (Also fuzzed.)
- **Control-plane authorization**: the control plane (enrollment, registry,
  policy) had no authorization — any mesh peer could administer it. Added
  default-deny, transport-derived RBAC keyed on the WireGuard public key, audited
  actions, body limits, strict decoding, path-traversal and full policy
  validation, and fail-closed startup without an ACL.
- **Approval-plane authorization**: a mesh-served approver required no approver
  ACL (any peer could approve). It is now mandatory (fail-closed startup).
- **Request-bound approvals**: replaced ambient `(peer, tool)` co-sign with
  signed, short-lived, single-use approval tokens bound to the exact peer,
  backend, tool, and canonical arguments; atomic single-use consume.
- **Audit verification honesty**: `audit verify` now reports four honest states
  (invalid / untrusted-key / unsealed / sealed); only a sealed log pinned to an
  expected key is complete and trusted. Rejects duplicate/non-monotonic
  sequences, mixed signers, and count/coverage mismatch.
- **Router failover**: unknown-outcome mutating (`tools/call`) requests are no
  longer auto-retried on transport failure after dispatch (double-execution
  risk); only safe/read-only methods fail over.
- **Session ownership**: added an atomic compare-and-swap lease primitive with a
  monotonic fencing generation and expiry, so two gateways cannot concurrently
  own a session; a superseded owner is fenced out of writes.
- **Router/federation delegation**: added signed, hop-bound, single-use
  delegation tokens and an upstream scope-intersection (caller ∩ router ∩
  delegation) so a router cannot widen a caller's authority.
- **Secret handling**: response-side redaction scrubs injected secret values
  from backend responses and traces (defeats trivial echo).
- **Strict config**: gateway config now uses strict YAML decoding so a
  security-field typo fails startup.
- **Capability revocation**: `IsRevoked` fails closed when the revocation store
  is unavailable/corrupt (was fail-open).
- **stdio/HTTP parity**: a shared `ClassifyRPC` gives stdio and Streamable-HTTP
  the same classification and tool/method decisions (conformance-tested).

### Changed

- **Go module path** renamed `meshmcp` → `github.com/xrey167/meshmcp` (breaking
  for importers; see `docs/MIGRATION.md`).
- Corrected absolute security claims in the README to match what code and tests
  establish; added `docs/THREAT-MODEL.md` and `docs/CAPABILITY-MATRIX.md`.

### Added

- **x402 payment gating + payment evidence (Experimental)** — the public edge
  can now gate priced tools behind an x402 payment: an unpaid `tools/call` on a
  priced tool returns HTTP `402 Payment Required` with an x402
  `PaymentRequirements` body, a verified `X-PAYMENT` forwards to the backend, and
  a `payment` receipt is written on the **same** signed, hash-chained audit
  record that already carries the caller's mesh identity — correlating
  *who-paid-for-which-call* while storing **references only** (`payment_ref` /
  `payer_ref` one-way hashes), never a wallet address or raw payment token. An
  opt-in **free dry-run route** (`X-Meshmcp-Dry-Run`) validates identity + policy
  and returns a synthetic result with dry-run-marked evidence, so a client can
  prove compatibility and rehearse the evidence shape before paying. The gate
  runs **after** the capability + policy double-gate (payment never widens what
  a deny-by-default policy withheld), settlement is delegated to a pluggable
  `PaymentVerifier` (built-in dev verifier for tests/demos; production injects a
  real facilitator), and the whole block is off unless `backend.payment.enabled`
  — an edge without it is byte-identical to before. New additive `payment` field
  on the audit record (omitempty; existing chains verify unchanged). See
  [docs/spec/PAYMENT-EVIDENCE.md](docs/spec/PAYMENT-EVIDENCE.md).
- **Resolved Send v1 + Universal Node actions** — Air can now select a
  transport-stamped Nearby identity once and carry it through Send, Drop, or a
  transport-key-bound session Steer without copying an address. The web, CLI,
  and MCP app resolve the identity's current advertised inbox immediately before
  delivery, reuse the existing resumable governed transport, and return the same
  bounded metadata-only result envelope only after a `drop.complete.v1` inbox
  confirms nonce-bound installation and exact payload/byte totals. Missing,
  rejected, or uncertain completion is an error. Friendly-name ambiguity and
  unsafe or oversized selectors fail closed, and core resolver errors do not
  reflect them. Raw `host:port` remains an explicit backward-compatible path
  with its legacy response shape; discovery still never grants authority
  because the receiver's ACL and policy decide the real action. Session/Home
  JSON now carries an optional `peer_key` so clients can identity-bind Steer;
  this is an additive wire change and a source-compatibility consideration for
  Go consumers that use positional `SessionInfo`/`Session` composite literals.
- **Component Card v1 ecosystem spine** — Air catalogs now carry a backward-compatible,
  validated descriptor for each reachable component: stable ID, kind, version, advertised
  owner identity, canonical versioned features, and lifecycle. Stable-ID-aware catalog
  changes distinguish a rename or address move from remove+add, and the same metadata feeds
  Air catalog/map/home/change views. Cards are discovery metadata only—transport identity,
  ACL, policy, co-sign, and capability verification remain authoritative. Added
  `docs/ECOSYSTEM.md` for the **discover → understand → use → continue** contract and the
  Trust Library, Universal Resolver, Continuity Capsule, automation, and native-companion
  roadmap.
- **Air Handoff / Continuity** — exact-key-bound, expiring Context Capsules for
  moving active-work context between agent devices. The receiver stores offers
  inertly, stamps the transport-verified source, requires an explicit local
  accept, and continues only through a receiver-selected governed tool. Includes
  atomic inbox persistence (private POSIX modes; inherited user-private ACLs
  required on Windows), identity-bound offer replay handling, bounded
  application ACK/NACK, atomic `dispatching` claims, exact-key pinning for both
  device and destination-agent hops, bounded durable delivery-attempt receipts,
  explicit unknown-outcome re-arm, archival replay tombstones, restart-safe
  audit correlation, and an explicit non-goal of cross-key live session takeover.
  See `docs/AIR-CONTINUITY.md`.
- **Air vision arc** — new identity-gated, firewalled, audited CLI verbs:
  `air browse` (a backend's tools/resources/prompts, filtered to your identity),
  `air stream` (watch governed Air activity live by tailing the audit ledger,
  decision-coloured and rotation-aware), `air vision` (terminal inventory of
  images the mesh dropped into a drop inbox) with `air serve --gallery` to view
  the pixels inline over the mesh, and `air bind` ("rebind, the Air way": watch
  the ledger and fire a declared reaction — `print` or deny-by-default `run` —
  when a record matches glob triggers). See `docs/AIR-VISION.md`.
- CI workflow (build/test/race on Linux/macOS/Windows, gofmt, vet, mod verify,
  advisory staticcheck/govulncheck, fuzz smoke); release workflow (cross-platform
  archives, checksums, SBOM, cosign keyless signing); Dependabot.
- `SECURITY.md`, `LICENSE-DECISION.md`, `CONTRIBUTING.md`, this changelog, and a
  release checklist.

### Added — HA, live migration, multi-tenancy, and enterprise identity

The backlog-completion wave. Every item shipped with adversarial review, tests,
and honest docs; see `docs/BACKLOG.md` and the capability matrix for scope.

- **Transactional Handoff v2 — live session move.** A deliberate prepare → ready
  → commit relocation of a *live* session's ownership between gateways: the
  source serves until commit, the destination pre-warms its backend, and commit
  is a single generation-CAS ownership swap gated on a consumed single-use grant
  (`air move grant`). Crash at any step leaves exactly one resumable owner. The
  Control Room's **drag-to-handoff** (`room --control`) fires it, dual-authorized
  (room token + the room's own operator identity). `docs/AIR-CONTINUITY.md`.
- **Cross-gateway HA on PostgreSQL.** A distributed CAS lease/session store
  (`pgstore`, `session_store: postgres://…`), always-on lease renewal,
  release-on-shutdown, and opt-in expiry-driven **standby failover adoption**
  (`session_failover: standby`) — a standby warms a crashed gateway's sessions
  before the client returns. `docs/HA-TOOLMESH.md`.
- **Multi-tenant control plane** (`tenants:` control ACL) — per-tenant policy,
  registry, enrollment, and audit chain, partitioned by the transport-proven key
  inside the one authorization chokepoint (cross-tenant access absent by
  construction; no cross-tenant super-role). `docs/MULTI-TENANT.md`.
- **SSO/OIDC group mapping** (gateway `oidc:` + `POST /v1/sso/attest`) — a
  verified OIDC token maps to additive `group:<name>` attribution over the
  WireGuard root (per-issuer pinned algorithm, fail-closed, bound to the
  transport key; never a replacement for it). `docs/SSO.md`.
- **Router signed delegation** (`delegation_key` + per-backend `router_delegation`)
  — the confused-deputy defense wired end to end: an upstream verifies a
  per-call token bound to the original caller and authorizes caller ∩ router ∩
  delegation, not the router's own identity.
- **HTTP transport policy parity** (F16 completion) — per-session taint, secret
  injection with JSON+SSE response redaction, and signed capability upgrades now
  apply to Streamable-HTTP backends at parity with stdio.
- **Witnessed audit anchoring** — `audit verify --anchors` cross-checks each
  sealed checkpoint against a self-linked file and/or an RBAC-gated peer witness
  (`/v1/anchor`), exiting non-zero on disagreement even when the chain seals —
  detecting a key-holding insider's rewrite.
- **Backend-side idempotency enforcement** (`mcp.Idempotency`) — per-(tool, key)
  single-flight claim middleware with Mem/PostgreSQL claim stores; the router
  conveys the key via `retry_tools`.
- **Spaces / `group:` fan-out** — operator groups resolve to present members
  (`GET /v1/groups`), and `air steer`/`air ring` fan out one governed
  single-target call per member, each independently audited; a group is never
  authority.
- **Observability** — an OTLP/HTTP logs exporter (`audit_otlp`, zero new deps)
  and a Prometheus `/metrics` endpoint (`metrics_listen`), both metadata-only
  observer sinks; size-based audit rotation (`audit_rotate_bytes`); a bounded
  incremental dashboard tail.
- **Backend egress restriction** (`egress_wrapper`) — an operator-supplied OS
  jailer (`firejail --net=none`, bwrap, netns) prepended fail-closed to a stdio
  backend, denying a secret-holding backend its out-of-band exfil path.
- **SPIFFE identity labels** (`trust_domain` → `peer_spiffe_id` on audit
  records), **capability sub-grants** (`--delegate-pub` → attenuated single-use
  `capability delegate`), **`config lint`**, **`fetch --gc`**, **`federate
  usage`**, **`air stream --bus`** (subscribe the hook bus over the mesh),
  **`air node` service hosting** (inbox/ring/screen/cast), **`air steer --to`**
  identity-bound addressing, and a thin **`meshmcp-connect`** client binary.

- **`meshmcp edge`** — an off-by-default, tool-scoped public OAuth ingress so
  hosted MCP clients that cannot join the mesh (e.g. claude.ai custom
  connectors) can connect: OAuth 2.1 + PKCE, dynamic client registration
  (RFC 7591/7592), consent, capability-bound tokens, Streamable HTTP with
  sessions/SSE, a revocation cascade, and an end-to-end conformance harness.
  See `docs/EDGE.md` and the threat-model addendum (adversaries 12–13).
- **Audit durability** — every committed record fsyncs by default
  (`audit_fsync: false` to opt out); a torn trailing write from power loss is
  conservatively repaired on boot while any mid-chain tamper still refuses to
  start. Store **schema versioning** across audit/paired/grant/edge
  (fail-closed reject-newer) and session/registry (tolerant).
- **Stable identity & config lifecycle** — a canonical per-user data dir
  (`$MESHMCP_HOME`, else the OS config dir) ends CWD-relative identity forks;
  SIGHUP hot-reloads policy rules AND peer/control ACLs with no restart;
  `meshmcp profile` remembers a default gateway; SIGTERM (and, for the eight
  formerly signal-less servers, any stop) drains gracefully with audit flush.
- **Trust lifecycle** — `operators` config + `air operator add/remove` onboard
  a second operator without YAML surgery; `meshmcp approve` binds the approver
  to a configured operator instead of a self-asserted `$USER`;
  **`meshmcp revoke-device`** severs pairing, grants, outstanding capability
  tokens (new subject-level revocation in the verifier), the operator surface,
  and the NetBird peer in one audited pass; `meshmcp uninstall` removes local
  state (dry-run by default). See `docs/RUNBOOK.md`.
- **Supportability** — leveled logging (`$MESHMCP_LOG` / `--verbose`) with the
  historical output format preserved; `meshmcp diag --bundle` support bundles
  (secret-redacted config, doctor report, audit chain verdict, versions);
  an error-presentation layer where common failures name their next command;
  pairing declines carry the operator's reason to `air join`.
- **Quality** — the two formerly quarantined steer tests are fixed at the root
  (a session clean-finalization race) and CI runs the whole suite with no
  skips; first benchmarks (policy decision, audit append ± fsync, chain
  verify, session checkpoint); one design language (`agent-os.css`) across
  Air/Approvals/Dashboard/Control Room; community health files; runnable
  `mcpclient` godoc example; `meshmcp version` reports commit/date provenance.

### Known issues

### Fixed

- **Session graceful-close race (structural fix)**: `endpoint.sendClose` now
  commits the close atomically with the CLOSE frame write, so a one-shot
  sender (steer/push) whose peer finalizes the session first can no longer
  redial and misreport a fully acknowledged delivery as "requested resume
  session is no longer available". Complements the reconnectLoop drain-phase
  wait shipped in the same cycle; an unknown resume id remains a terminal
  rejection. Deterministic regression: `TestGracefulDrainCloseNeverReattaches`.

- The license is unresolved (proprietary/read-only); see `LICENSE-DECISION.md`.
  Cutting the first tag is blocked on that owner decision, not on the pipeline:
  all five release targets cross-compile clean and the workflow is ready.
- GitHub-hosted CI is red for an infrastructure reason (Actions jobs are never
  assigned a runner — an account/billing-level setting); the full
  `go test -race ./...` suite is green locally with no skips.
- staticcheck stays advisory until honnef.co/go/tools supports go1.26.
