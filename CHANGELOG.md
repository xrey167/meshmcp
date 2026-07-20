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

- CI workflow (build/test/race on Linux/macOS/Windows, gofmt, vet, mod verify,
  advisory staticcheck/govulncheck, fuzz smoke); release workflow (cross-platform
  archives, checksums, SBOM, cosign keyless signing); Dependabot.
- `SECURITY.md`, `LICENSE-DECISION.md`, `CONTRIBUTING.md`, this changelog, and a
  release checklist.

### Known issues

- `mcp:TestTaskSteer` is a pre-existing flaky test (fix staged separately).
- Several enforcement primitives (request-bound approval grant UI, session-lease
  failover wiring, delegation in the router proxy path) are implemented and
  tested but not yet wired end-to-end; see the capability matrix.
- The license is unresolved (proprietary/read-only); see `LICENSE-DECISION.md`.
