<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# policy

## Purpose
The enforcement core. `policy` turns the gateway into an MCP-aware firewall: it parses the newline-delimited JSON-RPC stream between an MCP client and a backend, authorizes each `tools/call` (and governed method) by the caller's cryptographic identity, and records a tamper-evident audit trail. The central type is `Filter` (an `io.ReadWriteCloser` wrapping a backend), driven by an `Engine` that yields a three-valued `Decision` (allow / deny / co-sign). Everything that makes meshmcp a *control plane* — rate limits, time windows, taint/data-flow labels, human co-sign, signed capabilities, credential injection, hash-chained + Merkle-checkpointed audit — lives here.

## Key Files
| File | Description |
|------|-------------|
| `policy.go` | The `Policy` DSL types (rules, `DefaultAllow`, rate limits, time windows, labels, `require_cosign`) and matching. |
| `engine.go` | `Engine`: stateful per-backend decision maker. `DecideToolCall` returns a `Decision{Outcome, RuleID, Reason, AddLabels}`; `RuleID == -1` marks a policy-**default** decision. |
| `filter.go` | `Filter` + `handleLine`/`handleToolCall`/`handleMethod`/`handleNotification`. Parses each line, decides, audits, traces, injects secrets, and forwards or denies. Strips capability tokens from **every** governed line. |
| `capability.go` | Signed Ed25519 capability grants: `CapabilityClaims`, `Signer.IssueCapability`, `CapabilityVerifier.Verify`, `stripCapability`, `applyCapability`. Fail-closed; pinned roots; subject/audience/tool-bound; only upgrades a policy-default deny. |
| `secret.go` | `SecretResolver` seam: injects `{{secret:NAME}}` into an authorized outbound call (implemented by `secrets/`). |
| `cosign.go` · `pending.go` | `FileCosign` (human approvals) and `FilePending` (held `require_cosign` calls awaiting a decision). |
| `audit.go` | `AuditRecord` and `AuditLog`: the structured, hash-chained audit entry per tool call. |
| `chain.go` | Verify an audit log's hash chain is intact (`VerifyResult`). |
| `merkle.go` · `sign.go` · `checkpoint.go` · `verify_signed.go` | RFC-6962-style Merkle tree, Ed25519 `Checkpoint` signing, external `Anchor` witness, and signed-log verification — the non-repudiation layer. |
| `trace.go` | `TraceOptions` + tracer: gateway-wide JSON trace of every message (both directions). |
| `replay.go` | Reconstruct client→server requests from a trace (`ReplayReq`) for `meshmcp replay`. |
| `analyze.go` | `PeerStat` aggregation over an audit log (feeds `insight/` and the dashboard). |

## For AI Agents

### Working In This Directory
This package enforces the security guarantees. **Preserve these invariants** (all covered by tests):
- **Fail-closed**: any parse/verify/binding/time error → deny, and the call never reaches the backend.
- **Decision precedence**: an explicit rule deny (`RuleID != -1`) and `OutcomeCosign` always win; a capability only upgrades a policy-**default** deny (`RuleID == -1`).
- **Strip-before-forward ordering**: capability tokens and injected secrets must never reach the backend/trace/audit. Audit + trace happen on the token-free line; secret injection is **last**, so the resolved value reaches only the backend.
- **Identity is proven, not claimed**: `Caller.PeerKey` is the transport-proven WireGuard key; capabilities are subject-bound to it.
- **Batches**: top-level JSON-RPC arrays are refused when enforcing (can't authorize per-entry).

### Testing Requirements
- `CGO_ENABLED=1 go test ./policy/ -race`. Rich table/echo-backend harness; capability, taint, cosign, and signed-audit invariants each have dedicated tests (`capability_test.go`, `filter_engine_test.go`, `pending_test.go`, `sign_test.go`).
- When touching `filter.go` or `capability.go`, add a test asserting the token/secret does **not** appear in the backend's recorded bytes.

### Common Patterns
- `Decision.RuleID == -1` is the sentinel for "no rule matched" (default branch) — precedence logic keys off it.
- The `Engine` is shared across all of a backend's connections (per-identity rate limits / co-sign); treat its state as concurrent.

## Dependencies

### Internal
- Consumed by root `serve.go` (`NewFilterEngine`, `SetCapabilityVerifier`, `SetSecretResolver`, `SetPendingStore`).
- `secrets/` implements `SecretResolver`; `insight/` reads `AuditRecord`/`analyze.go` output.

### External
- `crypto/ed25519`, `crypto/sha256` (stdlib) — signatures and hash chain. No third-party crypto.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
