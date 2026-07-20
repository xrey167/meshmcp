# Approval Token Specification (Phase 3)

Request-specific human approval. An **ApprovalToken** authorizes exactly one
operation — a specific requesting peer calling a specific tool on a specific
backend with a specific argument set — once, within a short TTL. It replaces the
ambient `(peer, tool)` co-sign, under which approving `transfer($10)` also
authorized `transfer($10000)`.

## Binding

An approval is bound to, and its signature covers, all of:

| Field | Meaning |
|---|---|
| `peer_key` | requesting peer's WireGuard public key (transport-proven) |
| `backend` | backend identity the call targets |
| `tool` | tool name |
| `args_hash` | SHA-256 of the **canonical** arguments (see below) |
| `session` | optional session id |
| `nonce` | unique per approval (replay identifier) |
| `decision` | `approve` or `deny` |
| `approver` | approving peer key/identity |
| `policy_hash` | optional policy version/hash in force at approval time |
| `created_at`, `expires_at` | validity window (Unix seconds) |
| `pubkey`, `sig` | Ed25519 signer (gateway) + signature over all fields |

The **binding key** used for storage/lookup is
`SHA-256(peer_key ‖ backend ‖ tool ‖ args_hash)`. Any change to the peer,
backend, tool, or arguments yields a different key, so an approval for one
operation cannot be located for another.

### Canonical arguments

`args_hash` is computed over a canonicalized form of the JSON arguments: the
bytes are parsed and re-encoded (Go's `encoding/json` sorts object keys), so
key-order and insignificant-whitespace differences hash equally, while any value
change produces a different hash. Non-JSON argument bytes are hashed as-is.

## Lifecycle

1. **Request.** A `require_cosign` tool call with no matching approval returns a
   co-sign outcome; the gateway records a pending request (peer, backend, tool,
   and — for a request-bound flow — the canonical arguments) so the approver UI
   can show the human the exact operation.
2. **Grant.** An authorized approver (identity derived from the transport, see
   the approver ACL) approves the specific pending request. The gateway signs an
   `ApprovalToken` bound to that exact request and stores it `0600`.
3. **Consume.** On the caller's retry, the gateway recomputes the binding from
   the *actual* call and **atomically consumes** a matching, non-expired,
   validly-signed approval. Consumption is a single `rename`, so exactly one
   caller can consume a given approval even under concurrency; a second attempt
   (replay) finds nothing.

## Guarantees and requirements

- **Argument-bound.** An approval for one argument set does not authorize
  another. Changing the arguments or backend invalidates the approval.
- **Single-use.** Consumed exactly once (atomic `rename`); replays fail.
- **Short TTL, non-disableable.** Default 5 min, clamped to ≤ 1 h; a
  zero/negative configured TTL falls back to the default — it can never mean
  "never expires".
- **Signed & pinned.** Tokens are Ed25519-signed; a token is trusted only when
  its `pubkey` matches the store's pinned expected key.
- **Restrictive storage.** Approval files are written `0600`.
- **Fail-closed.** No matching/valid/unexpired approval ⇒ the call stays
  co-sign-pending (denied), never allowed.

## Gateway result and connection semantics

When a call requires approval the gateway returns a structured co-sign result
referencing the held request; it does **not** hold the original connection open.
The caller retries with the same request once approved. (Documentation must not
claim the connection is held open — it is not.)

## Implementation

- `policy/approval_token.go` — `ApprovalToken`, `ApprovalRequest`,
  `canonicalArgsHash`, `FileApprovalStore` (`Grant`, atomic `ConsumeApproval`),
  `RequestApprovalStore` interface.
- `policy/engine.go` — `DecideToolCallBound` consumes a request-bound approval
  for a `require_cosign` rule when a store is attached
  (`Engine.SetRequestApprovals`); otherwise it falls back to the legacy ambient
  co-sign store.
- `policy/filter.go` — the tool-call path calls `DecideToolCallBound` with the
  backend and the actual arguments.

Tests: `policy/approval_token_test.go` — argument binding, canonical-args
stability, single-use, concurrent-single-winner, backend binding, TTL
(expiry + non-disableable + clamp), signature/pinning, `0600` perms, and an
end-to-end filter test.

## Not yet wired (follow-up)

The **approver HTTP service** (`approvals.go`) still grants the legacy ambient
`(peer, tool)` approval; granting a request-bound `ApprovalToken` (and showing
the human the exact canonical operation) uses `FileApprovalStore.Grant`, which
is ready but not yet connected in the CLI/UI. The enforcement primitive and the
gateway decision path are complete and tested; the approver UI grant path is the
remaining integration step.
