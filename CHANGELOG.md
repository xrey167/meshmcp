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

### Fixed

- **Session graceful-close race**: `endpoint.sendClose` now commits the close
  atomically with the CLOSE frame write, so a one-shot sender (steer/push)
  whose peer finalizes the session first can no longer misreport a fully
  acknowledged delivery as "requested resume session is no longer available".
  An unknown resume id remains a terminal rejection. `TestTaskSteer` and
  `TestSteerDeliveryRequiresApplicationAck` are un-quarantined in CI.

### Known issues

- Several enforcement primitives (request-bound approval grant UI, session-lease
  failover wiring, delegation in the router proxy path) are implemented and
  tested but not yet wired end-to-end; see the capability matrix.
- The license is unresolved (proprietary/read-only); see `LICENSE-DECISION.md`.
