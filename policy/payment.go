package policy

import (
	"crypto/sha256"
	"encoding/hex"
)

// PaymentEvidence is the additive, optional payment receipt attached to an
// AuditRecord for a call that was gated on payment (e.g. an x402 paid MCP
// call). It records that a payment settled for a specific call by an already-
// identified caller — the mesh identity is carried by the SAME record's Peer /
// PeerKey / PeerSpiffeID fields, so the signed, hash-chained log proves
// who-paid-for-which-call without a second correlation store.
//
// It is deliberately a receipt of REFERENCES, never of instruments: it carries
// NO wallet address, NO raw payment token, and NO transaction that could be
// followed on-chain to a wallet. PaymentRef and PayerRef are one-way hashes
// (see NewPaymentEvidence), so the evidence is comparable and verifiable but
// not reversible to a payer's financial identity. Raw settlement details, if an
// operator keeps them at all, live in the payment facilitator — never in this
// shared, exportable audit log.
//
// The type follows the audit record's additive-field discipline: it is only
// ever set on records for paid/dry-run calls and is emitted omitempty, so
// records for unpaid calls are byte-identical to a pre-payment build and every
// existing chain, hash, and checkpoint verifies unchanged (see
// docs/spec/AUDIT-RECORD.md §1.4 and docs/spec/PAYMENT-EVIDENCE.md).
type PaymentEvidence struct {
	// Scheme is the payment scheme that settled the call, e.g. "x402".
	Scheme string `json:"scheme"`
	// Network is the settlement network label, e.g. "base-sepolia". Optional.
	Network string `json:"network,omitempty"`
	// Asset is the settlement asset label, e.g. "USDC". Optional.
	Asset string `json:"asset,omitempty"`
	// Amount is the amount charged in the asset's minor units, kept as a string
	// so exact precision survives JSON without a float. Optional.
	Amount string `json:"amount,omitempty"`
	// PaymentRef is a one-way hash of the settlement reference (the facilitator's
	// tx/settlement id). It proves a specific settlement backed this call without
	// exposing the on-chain transaction. Empty on a dry-run.
	PaymentRef string `json:"payment_ref,omitempty"`
	// PayerRef is a one-way, per-backend-salted hash of the payer identity. The
	// same payer yields the same PayerRef (so repeat payments correlate to one
	// payer) but it cannot be reversed to a wallet. Empty on a dry-run.
	PayerRef string `json:"payer_ref,omitempty"`
	// DryRun marks evidence produced by the free dry-run route: the call was
	// validated (identity + policy + schema) but nothing was charged and the
	// backend was not invoked, so PaymentRef/PayerRef are absent. It exists so a
	// client can rehearse the exact evidence shape it will see when paying.
	DryRun bool `json:"dry_run,omitempty"`
	// Request binds the receipt to the EXACT call it paid for: a canonical hash of
	// the tool arguments (CanonicalArgsHash). With the record's Tool and RPCID it
	// makes the receipt non-repudiable for a specific request, so a settlement
	// cannot later be claimed to have paid for a different call. Optional.
	Request string `json:"request,omitempty"`
}

// Payment-evidence hash domains. Distinct prefixes keep the payment-ref and
// payer-ref pre-images from ever colliding, and version the scheme so a future
// derivation change is unambiguous.
const (
	paymentRefDomain = "meshmcp-payment-ref-v1\x00"
	payerRefDomain   = "meshmcp-payer-ref-v1\x00"
)

// NewPaymentEvidence builds settled (non-dry-run) evidence. reference is the
// facilitator's opaque settlement id and payer is the facilitator's opaque
// payer id; BOTH are one-way hashed here and never stored raw. salt scopes the
// payer hash to a deployment/backend so a PayerRef is not comparable across
// unrelated gateways (pass the backend name at minimum; a secret salt is a
// hardening option). Either derived ref is omitted when its input is empty.
func NewPaymentEvidence(scheme, network, asset, amount, reference, payer, salt string) PaymentEvidence {
	ev := PaymentEvidence{Scheme: scheme, Network: network, Asset: asset, Amount: amount}
	if reference != "" {
		ev.PaymentRef = hashRef(paymentRefDomain, salt, reference)
	}
	if payer != "" {
		ev.PayerRef = hashRef(payerRefDomain, salt, payer)
	}
	return ev
}

// DryRunEvidence builds evidence for the free dry-run route: the payment-shaped
// receipt a caller sees, marked DryRun with no settlement or payer reference.
func DryRunEvidence(scheme, network, asset, amount string) PaymentEvidence {
	return PaymentEvidence{Scheme: scheme, Network: network, Asset: asset, Amount: amount, DryRun: true}
}

// hashRef is the one-way derivation for reference fields: hex(sha256(domain ||
// salt || 0x00 || value)). The 0x00 separator keeps a (salt, value) pair from
// colliding with a differently-split pair.
func hashRef(domain, salt, value string) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte(salt))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}
