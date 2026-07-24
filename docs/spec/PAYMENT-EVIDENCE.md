# meshmcp Payment Evidence & x402 Gating — v0.1 (Experimental)

Status: draft · Owner: meshmcp · Maturity: **Experimental (Labs)** — see
[CAPABILITY-MATRIX.md](../CAPABILITY-MATRIX.md). The 402 handshake, dry-run
route, and evidence pipeline are tested end to end with a built-in verifier;
on-chain settlement is delegated to a pluggable facilitator and is **not** a
security guarantee yet.

## Why

A **public, paid** remote MCP has to answer four questions at once for every
call: *who* is calling, *whether policy allows it*, *whether they paid*, and
*what proof survives afterward*. meshmcp already answers the first, second, and
fourth — transport/OAuth identity, a deny-by-default policy engine plus an
Ed25519 capability, and a signed, hash-chained audit log. Payment evidence adds
the third **without a parallel system**: the payment receipt rides on the same
audit record that already carries the caller's identity, so the log proves
*who-paid-for-which-call* in one signed line — and it does so **without ever
storing a wallet**.

## The guarantee

For a payment-gated call, meshmcp records a `payment` object on the call's audit
record (see [AUDIT-RECORD.md](AUDIT-RECORD.md) §1.1). That object is a receipt
of **references, never instruments**:

- **No wallet address.** The one address in the system is the server's own
  `pay_to`, advertised publicly in the 402 challenge — it is a payee, not
  evidence, and never appears in a record.
- **No raw payment token** and **no followable transaction.** `payment_ref` is
  `sha256(domain ‖ salt ‖ 0x00 ‖ settlement-reference)` and `payer_ref` is the
  same construction over the payer id. Both are one-way: comparable and
  verifiable, not reversible.
- **Correlatable to mesh identity.** The paying identity is the *same record's*
  `peer` / `peer_key` / `peer_spiffe_id`. A `payer_ref` additionally lets an
  auditor see that two payments came from one payer — a stable pseudonym — with
  no path back to a wallet.

Because `payment` is an additive `omitempty` field, a record for an unpaid call
is byte-identical to a pre-payment build, and every existing chain, hash, and
signed checkpoint verifies unchanged.

## The x402 flow (edge)

Payment gating is opt-in per backend on the public [edge](../EDGE.md) ingress,
and runs **after** the capability + policy double-gate — payment never buys
access a deny-by-default policy withheld.

```
client                         meshmcp edge                       backend
  │  tools/call (priced, no pay)     │                                │
  │─────────────────────────────────▶│  identity ✓  policy ✓          │
  │  402 Payment Required            │  (not paid)                    │
  │◀─────────────────────────────────│  Accept-Payment: x402          │
  │  { accepts: [PaymentRequirements]}│  audit: x402/require (deny)    │
  │                                   │                                │
  │  tools/call + X-PAYMENT           │                                │
  │─────────────────────────────────▶│  verify payment (facilitator)  │
  │                                   │  audit: x402/settle (allow,    │
  │                                   │         payment evidence)      │
  │                                   │────────── forward ────────────▶│
  │  result [+ X-PAYMENT-Response]   │◀───────── result ──────────────│
  │◀─────────────────────────────────│                                │
```

- **402 challenge** — HTTP `402 Payment Required`, header `Accept-Payment:
  <scheme>`, body `{"error":"payment_required","accepts":[PaymentRequirements]}`.
  `PaymentRequirements` carries `scheme`, `network`, `asset`,
  `maxAmountRequired`, `payTo`, `resource` (a URL identifying the tool),
  `facilitator`, and `freeDryRun`.
- **Payment** — the client presents `X-PAYMENT` (base64-encoded JSON, x402
  convention). meshmcp hands it to the configured `PaymentVerifier`; a real
  deployment injects a facilitator client that verifies and settles, returning
  opaque settlement + payer references. On success the call forwards and the
  settlement is recorded as `x402/settle`. On failure the call is re-challenged
  with 402.
- **Verifier** — `PaymentVerifier` is an interface. The built-in
  `devPaymentVerifier` checks payload well-formedness and that the amount meets
  the price, then treats the payment as settled with a deterministic reference —
  enough to test and demo the whole path, but it performs **no** on-chain
  settlement or signature check. Enabling payment without either injecting a
  real verifier or explicitly setting `dev_insecure_verifier: true` is a
  **fail-closed construction error** — meshmcp never silently accepts unsettled
  payments (the same rule the DPoP replay store and signing key follow).

## The free dry-run route

When `free_dry_run` is enabled, a request carrying `X-Meshmcp-Dry-Run` runs
identity + policy validation and returns a **synthetic** tools/call result
*without charging and without invoking the backend*. The result's `_meta`
carries `meshmcp/payment` with `dry_run: true`, and an `x402/dry-run` record is
written. A client can therefore prove compatibility — the 402-aware transport,
the tool schema, the response envelope, and the exact evidence shape it will see
when paying — at no cost and with no side effects.

## Configuration

```yaml
backend:
  name: carbon-tools
  addr: gateway.mesh:9101
  tools: ["estimate_*", "verify_*"]
  policy: { default_allow: false, rules: [ ... ] }   # unchanged, still deny-by-default
  payment:
    enabled: true
    scheme: x402                     # default
    network: base-sepolia
    asset: USDC
    pay_to: "0xYourServerReceivingAddress"
    facilitator: "https://facilitator.example/x402"   # advisory; the injected verifier does the work
    free_dry_run: true
    # dev_insecure_verifier: true    # local/demo ONLY — accepts unsettled payments; omit in production and inject a real verifier
    # salt: "<secret>"               # SECRET; prefer salt_env/salt_file; auto-generated + persisted if unset
    # salt_env: MESHMCP_PAYMENT_SALT
    # salt_file: /run/secrets/payment_salt
    prices:                          # tool-name globs (path.Match), non-overlapping
      "estimate_*": "1000"           # POSITIVE INTEGER in minor units, string
      "verify_footprint": "5000"
```

Validation rejects an enabled block with no `asset`, no `pay_to`, no prices, a
price that is not a canonical positive integer in minor units, a malformed glob,
**overlapping** price globs (overlap would make the charged price ambiguous), or
a `salt` equal to the (public) backend name. A disabled or absent block is inert.

The evidence **salt is a secret** (see Privacy below): supply it via `salt_env`
or `salt_file`, or leave all three unset and the edge generates a 32-byte secret
once and persists it at `<state_dir>/payment_salt` (0600), reused across
restarts. It is never defaulted to a public value.

## Verifier contract (normative)

The gate delegates payment *validity* to the injected `PaymentVerifier` and
enforces only what it can see. An injected production verifier **MUST**, before
returning success:

1. Verify the payment pays `req.PayTo` on `req.Network` in `req.Asset` for an
   amount **≥** `req.MaxAmountRequired`.
2. Verify the payment authorization's cryptographic proof (signature).
3. **Settle** the authorization so it is single-use at the facilitator/on-chain
   layer, and return a stable, unique settlement `Reference` (and, if known, the
   opaque `Payer`). Returning success with an empty `Reference` is rejected by
   the gate (fail-closed).

What the gate enforces itself, independent of the verifier: single-use of the
returned `Reference` (see below), a settled `Amount` **≥** the configured price
(integer compare in minor units), a bounded verifier timeout, and a bounded
`X-PAYMENT` size. What the gate does **not** check (and therefore fully trusts
the verifier for): `PayTo`, `Network`, and the payment's signature. A
mis-implemented verifier that skips (1)/(2) can accept wrong-recipient or forged
payments — the verifier is a trusted security collaborator.

## Privacy

`payment_ref`/`payer_ref` are one-way salted hashes, but the payer-id and
settlement-reference spaces are **public/enumerable** (wallet-derived ids, tx
hashes). Their unlinkability therefore rests entirely on the **secrecy** of the
salt: with a guessable salt, anyone holding the exported audit log can brute-force
the hashes and de-anonymize payers. meshmcp treats the salt as a mandatory secret
(auto-generated, persisted, never the backend name), which closes the default
weakness — but do **not** rotate the salt in place: historical records hash under
the salt in force when they were written, so rotation makes old `payment_ref`
values incomparable (breaking restart-reseed) and old `payer_ref` values
un-correlatable. A keyed/versioned salt set is planned. `Amount` is retained in
evidence but is derivable from the priced tool, so it adds a small correlation
surface only.

## Single-use, durability, and scale

- **Single-use is enforced by the gate**, keyed on the salted `payment_ref`.
  One settled payment authorizes exactly one call; a replay is denied
  (`x402/replay`) regardless of verifier idempotency.
- **Restart durability (single instance):** on startup the gate reseeds its
  consumed set from the `x402/settle` records in the already-verified audit
  chain, so a restart does **not** re-open past payments to replay.
- **Bounded:** the in-process set is size-capped and **fails closed** on overflow
  (denies new payments) rather than evicting a still-replayable reference.
- **Multi-instance is NOT yet safe:** the consumed set is per-process, so two
  edge instances behind one URL have independent replay windows (double-spend
  across instances). Until a shared store lands, **run payment behind a single
  instance.** A `payment.single_use_store` (postgres, atomic claim, fail-closed
  when configured-but-unsupplied — mirroring `oauth.dpop_replay_store`) is the
  planned HA control.
- **Redeem-before-forward:** redeemed before the backend call (airtight vs.
  concurrent replay); a backend failure or error result *after* settlement writes
  a compensating `x402/backend-error` / `x402/tool-error` record so the ledger
  reflects the true outcome, but the payment is spent (a settlement matter, not a
  silent re-serve). An audit-write failure after settlement likewise fails closed.

## Non-goals / planned hardening

- On-chain settlement correctness is the facilitator's, not meshmcp's — no
  production facilitator client ships yet, so a production deployment must inject
  one (enabling payment without a verifier is a fail-closed construction error).
- **Scope:** only `tools/call` is billable. Non-tool methods (`resources/read`,
  `prompts/get`, completion) are protocol plumbing and are **not** payment-gated —
  expose billable work as a tool, not a resource/prompt. An unpriced tool (no
  matching price glob) is free.
- **Not bound to the caller / not fresh:** `X-PAYMENT` is a bearer instrument;
  the gate binds a redemption to (tool, args-hash, rpc-id) in the receipt but does
  not yet issue a per-challenge server nonce, so a leaked payment could be
  presented by a different approved client before it is redeemed. Per-client
  challenge nonces + expiry are planned.
- **No idempotent retry:** a served response lost in transit cannot be recovered
  by re-presenting the payment (it is now redeemed); a served-result cache keyed
  by reference is planned.
- **No automated reconciliation** of recorded settlements against
  facilitator/on-chain truth; retain the raw settlement id in the facilitator
  keyed to the salted `payment_ref` for out-of-band reconciliation.
- Gating lives at the public edge (the paid-remote surface). The
  `PaymentEvidence` type is in `policy`, so a future mesh-gateway gate can emit
  the same evidence.

## Reference implementation

`policy/payment.go` (`PaymentEvidence`, `NewPaymentEvidence`, `DryRunEvidence`),
the additive `AuditRecord.Payment` field in `policy/audit.go`, and the edge gate
in `edge/payment.go` (`PaymentRequirements`, `PaymentVerifier`, `gatePayment`,
`devPaymentVerifier`), configured by `edge.PaymentConfig`. Tests:
`policy/payment_test.go`, `edge/payment_test.go`, `edge/config_test.go`.
