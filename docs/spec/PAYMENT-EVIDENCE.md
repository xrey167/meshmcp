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
  `maxAmountRequired`, `payTo`, `resource` (the tool), `facilitator`, and
  `freeDryRun`.
- **Payment** — the client presents `X-PAYMENT` (base64-encoded JSON, x402
  convention). meshmcp hands it to the configured `PaymentVerifier`; a real
  deployment injects a facilitator client that verifies and settles, returning
  opaque settlement + payer references. On success the call forwards and the
  settlement is recorded as `x402/settle`. On failure the call is re-challenged
  with 402.
- **Verifier** — `PaymentVerifier` is an interface. The built-in
  `devPaymentVerifier` checks payload well-formedness and the required
  amount/asset, then treats the payment as settled with a deterministic
  reference — enough to test and demo the whole path, but it performs **no**
  on-chain settlement or signature check. Production supplies its own verifier.

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
    salt: carbon-tools               # optional; scopes payer_ref (defaults to backend name)
    prices:                          # tool-name globs (path.Match), non-overlapping
      "estimate_*": "1000"           # minor units, string
      "verify_footprint": "5000"
```

Validation rejects an enabled block with no `asset`, no prices, an empty price,
a malformed glob, or **overlapping** price globs (overlap would make the charged
price depend on non-deterministic map order). A disabled or absent block is
inert.

## Non-goals / limits (v0.1)

- On-chain settlement correctness is the facilitator's, not meshmcp's — the
  built-in verifier is a dev stand-in.
- `payer_ref` unlinkability is only as strong as the salt; a public/guessable
  payer-id space plus a known salt is correlatable by brute force. Use a secret
  salt where payer anonymity matters.
- Gating lives at the public edge (the paid-remote surface). The
  `PaymentEvidence` type is in `policy`, so a future mesh-gateway gate can emit
  the same evidence.

## Reference implementation

`policy/payment.go` (`PaymentEvidence`, `NewPaymentEvidence`, `DryRunEvidence`),
the additive `AuditRecord.Payment` field in `policy/audit.go`, and the edge gate
in `edge/payment.go` (`PaymentRequirements`, `PaymentVerifier`, `gatePayment`,
`devPaymentVerifier`), configured by `edge.PaymentConfig`. Tests:
`policy/payment_test.go`, `edge/payment_test.go`, `edge/config_test.go`.
