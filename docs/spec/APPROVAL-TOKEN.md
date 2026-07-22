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
  backend and the actual arguments, and records the held call's `ArgsHash` +
  `PolicyHash` on the `Pending` record so the approver can mint a bound token.
- `approvals.go` — with `--approval-key`, `/v1/approve` reads the held
  `Pending` and calls `FileApprovalStore.Grant`, minting a signed, single-use,
  argument-bound approval (`Pending.ApprovalRequest()`).
- `serve.go` / `config.go` — the backend option `approval_signing_key` (the
  Ed25519 key **shared** with the approver) makes the gateway
  `SetRequestApprovals`; it is loaded fail-closed and requires `cosign_store`.

Tests: `policy/approval_token_test.go` — argument binding, canonical-args
stability, single-use, concurrent-single-winner, backend binding, TTL
(expiry + non-disableable + clamp), signature/pinning, `0600` perms, and an
end-to-end filter test. `approvals_test.go` — the approver mints a correctly
request-bound token from a held record (`TestApproverMintsRequestBoundApproval`)
and fails closed with no held call. `config_test.go` — the config guard.

## Enabling request-bound approvals

Request-bound approvals are **opt-in**. Generate one shared Ed25519 key and give
it to both sides (the approver signs; the gateway pins its public key):

```yaml
# gateway backend
backends:
  - name: pay
    stdio: ["./pay-server"]
    cosign_store: ./cosign            # shared directory
    approval_signing_key: ./approval.key   # shared key; fail-closed if unreadable
    policy: { default_allow: false, rules: [ { peers: ["*"], tools: ["transfer"], allow: true, require_cosign: true } ] }
```

```sh
# approver (e.g. on a phone-facing host), same key + directory
meshmcp approvals --store ./cosign --approval-key ./approval.key --approver 'pubkey:<phone-key>'
```

With the key set, a `require_cosign` call is released ONLY by a signed,
single-use token bound to its exact arguments and policy version; ambient
`meshmcp approve` grants no longer release it. With no key configured, the
ambient co-sign path is unchanged.
