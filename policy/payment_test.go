package policy

import (
	"bytes"
	"strings"
	"testing"
)

// The whole point of PaymentEvidence is that it proves a payment without
// carrying a wallet: the raw settlement reference and payer id are one-way
// hashed, so neither the pre-image nor a wallet address ever reaches the log.
func TestPaymentEvidenceHidesWalletDetails(t *testing.T) {
	const (
		reference = "0xdeadbeefsettlementtx"
		payer     = "0xWALLETshouldNeverAppear"
		salt      = "carbon-tools"
	)
	ev := NewPaymentEvidence("x402", "base-sepolia", "USDC", "1000", reference, payer, salt)

	if ev.PaymentRef == reference || strings.Contains(ev.PaymentRef, reference) {
		t.Fatalf("payment_ref leaked the raw reference: %q", ev.PaymentRef)
	}
	if ev.PayerRef == payer || strings.Contains(ev.PayerRef, payer) {
		t.Fatalf("payer_ref leaked the raw payer id: %q", ev.PayerRef)
	}
	if ev.PaymentRef == "" || ev.PayerRef == "" {
		t.Fatalf("settled evidence must carry both derived refs, got %+v", ev)
	}
	if ev.Scheme != "x402" || ev.Asset != "USDC" || ev.Amount != "1000" {
		t.Fatalf("descriptor fields not preserved: %+v", ev)
	}
}

// PayerRef is a stable pseudonym: the same payer correlates across calls, a
// different payer (or a different salt) does not.
func TestPayerRefCorrelatesButDoesNotCollide(t *testing.T) {
	a := NewPaymentEvidence("x402", "", "", "", "ref1", "payer-A", "backendX")
	b := NewPaymentEvidence("x402", "", "", "", "ref2", "payer-A", "backendX")
	if a.PayerRef != b.PayerRef {
		t.Fatal("same payer must yield the same payer_ref (so repeat payments correlate)")
	}
	if a.PaymentRef == b.PaymentRef {
		t.Fatal("different settlements must yield different payment_refs")
	}

	other := NewPaymentEvidence("x402", "", "", "", "ref3", "payer-B", "backendX")
	if other.PayerRef == a.PayerRef {
		t.Fatal("different payers must not share a payer_ref")
	}
	salted := NewPaymentEvidence("x402", "", "", "", "ref4", "payer-A", "backendY")
	if salted.PayerRef == a.PayerRef {
		t.Fatal("a different salt must not produce a comparable payer_ref across deployments")
	}
}

func TestDryRunEvidenceCarriesNoSettlement(t *testing.T) {
	ev := DryRunEvidence("x402", "base-sepolia", "USDC", "1000")
	if !ev.DryRun {
		t.Fatal("dry-run evidence must set DryRun")
	}
	if ev.PaymentRef != "" || ev.PayerRef != "" {
		t.Fatalf("dry-run must not carry settlement/payer refs: %+v", ev)
	}
}

// A record WITHOUT payment evidence must serialize byte-identically to a
// pre-payment build (the omitempty additive-field guarantee): the "payment"
// key is absent, so existing chains and hashes are unchanged.
func TestAuditRecordWithoutPaymentIsUnchanged(t *testing.T) {
	var buf bytes.Buffer
	a := NewAuditLog(&buf, func() string { return "T" })
	a.write(AuditRecord{Backend: "kg", Peer: "p", Method: "tools/call", Tool: "read_file", Decision: "allow", Rule: 0})
	if strings.Contains(buf.String(), "payment") {
		t.Fatalf("a record with no PaymentEvidence must not emit a payment key: %s", buf.String())
	}
}

// A record WITH payment evidence stays inside the tamper-evident chain: it
// hashes, chains, and verifies like any other record.
func TestAuditChainVerifiesWithPaymentEvidence(t *testing.T) {
	var buf bytes.Buffer
	a := NewAuditLog(&buf, func() string { return "T" })
	a.write(AuditRecord{Backend: "edge:carbon", Peer: "oauth:c1", Method: "tools/call", Tool: "estimate", Decision: "allow", Rule: 0})
	ev := NewPaymentEvidence("x402", "base-sepolia", "USDC", "1000", "settle-1", "payer-A", "carbon")
	a.write(AuditRecord{Backend: "edge:carbon", Peer: "oauth:c1", Method: "x402/settle", Tool: "estimate", Decision: "allow", Rule: -1, Payment: &ev})

	if !strings.Contains(buf.String(), `"payment":`) {
		t.Fatalf("paid record must emit payment evidence: %s", buf.String())
	}
	res, err := VerifyChain(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK || res.Count != 2 {
		t.Fatalf("chain with a payment record should verify (2 records): %+v", res)
	}
}
