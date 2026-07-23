package air

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validActionReceipt(t *testing.T) ActionReceipt {
	t.Helper()
	receipt, err := NewActionReceipt(ActionPush, ActionRecipient{
		Name:      "Analyst",
		FQDN:      "analyst.mesh",
		PublicKey: "full-wireguard-public-key",
		Service:   ServiceInbox,
		Address:   "100.64.0.9:9110",
	}, "clip.txt", 12, time.Date(2026, time.July, 22, 12, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewActionReceipt: %v", err)
	}
	return receipt
}

func TestActionReceiptResolvedRoundTripContainsMetadataOnly(t *testing.T) {
	receipt := validActionReceipt(t)
	if receipt.Schema != ActionReceiptSchemaV1 || receipt.Action != ActionPush || receipt.Status != ActionDelivered {
		t.Fatalf("unexpected receipt identity: %+v", receipt)
	}
	if receipt.Recipient.PublicKey != "full-wireguard-public-key" || receipt.Recipient.Address != "100.64.0.9:9110" {
		t.Fatalf("resolved recipient not retained: %+v", receipt.Recipient)
	}

	b, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "launch-code-red") || strings.Contains(string(b), "secret") {
		t.Fatalf("receipt leaked payload/secret material: %s", b)
	}
	var roundTrip ActionReceipt
	if err := json.Unmarshal(b, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if err := roundTrip.Validate(); err != nil {
		t.Fatalf("round-trip receipt invalid: %v", err)
	}
}

func TestActionReceiptAllowsLegacyRawRecipient(t *testing.T) {
	receipt, err := NewActionReceipt(ActionDrop, ActionRecipient{
		Service: ServiceInbox,
		Address: "peer.mesh:9110",
	}, "report.pdf", 7, time.Date(2026, time.July, 22, 12, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Recipient.PublicKey != "" || receipt.Recipient.FQDN != "" || receipt.Recipient.Address != "peer.mesh:9110" {
		t.Fatalf("raw recipient changed: %+v", receipt.Recipient)
	}
}

func TestActionReceiptValidationBounds(t *testing.T) {
	base := validActionReceipt(t)
	tests := []struct {
		name   string
		mutate func(*ActionReceipt)
	}{
		{"schema", func(r *ActionReceipt) { r.Schema = "air.action-receipt/v2" }},
		{"action", func(r *ActionReceipt) { r.Action = "execute" }},
		{"status", func(r *ActionReceipt) { r.Status = "maybe" }},
		{"service", func(r *ActionReceipt) { r.Recipient.Service = ServiceRing }},
		{"missing address", func(r *ActionReceipt) { r.Recipient.Address = "" }},
		{"zero port", func(r *ActionReceipt) { r.Recipient.Address = "peer.mesh:0" }},
		{"high port", func(r *ActionReceipt) { r.Recipient.Address = "peer.mesh:65536" }},
		{"control in identity", func(r *ActionReceipt) { r.Recipient.FQDN = "peer\x1b.mesh" }},
		{"C1 control in identity", func(r *ActionReceipt) { r.Recipient.Name = "peer\u009b31m" }},
		{"blank public key", func(r *ActionReceipt) { r.Recipient.PublicKey = " " }},
		{"blank payload name", func(r *ActionReceipt) { r.PayloadName = " " }},
		{"long payload name", func(r *ActionReceipt) { r.PayloadName = strings.Repeat("x", MaxActionPayloadNameBytes+1) }},
		{"C1 control in payload name", func(r *ActionReceipt) { r.PayloadName = "report\u009b31m.pdf" }},
		{"negative bytes", func(r *ActionReceipt) { r.Bytes = -1 }},
		{"too many bytes", func(r *ActionReceipt) { r.Bytes = MaxActionPayloadBytes + 1 }},
		{"bad time", func(r *ActionReceipt) { r.Time = "yesterday" }},
		{"long fractional time", func(r *ActionReceipt) { r.Time = "2026-07-22T12:30:00." + strings.Repeat("1", 100) + "Z" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := base
			tt.mutate(&got)
			if err := got.Validate(); err == nil {
				t.Fatalf("invalid receipt accepted: %+v", got)
			}
		})
	}
}

func TestActionResultRoundTripAndValidation(t *testing.T) {
	receipt := validActionReceipt(t)
	result, err := NewActionResult(receipt.Recipient, []ActionReceipt{receipt})
	if err != nil {
		t.Fatal(err)
	}
	if result.Schema != ActionResultSchemaV1 || result.Payloads != 1 || result.Bytes != receipt.Bytes {
		t.Fatalf("unexpected action result: %+v", result)
	}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip ActionResult
	if err := json.Unmarshal(b, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if err := roundTrip.Validate(); err != nil {
		t.Fatalf("round-trip action result invalid: %v", err)
	}

	mutations := map[string]func(*ActionResult){
		"schema":        func(r *ActionResult) { r.Schema = "air.action-result/v2" },
		"status":        func(r *ActionResult) { r.Status = "partial" },
		"payload count": func(r *ActionResult) { r.Payloads++ },
		"byte total":    func(r *ActionResult) { r.Bytes++ },
		"recipient":     func(r *ActionResult) { r.Receipts[0].Recipient.Address = "other.mesh:9110" },
		"empty":         func(r *ActionResult) { r.Payloads = 0; r.Bytes = 0; r.Receipts = nil },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := result
			candidate.Receipts = append([]ActionReceipt(nil), result.Receipts...)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatalf("invalid result accepted: %+v", candidate)
			}
		})
	}
}

func TestActionResultBoundsAggregateBytes(t *testing.T) {
	base := validActionReceipt(t)
	base.Bytes = MaxActionPayloadBytes
	receipts := make([]ActionReceipt, MaxActionTotalBytes/MaxActionPayloadBytes+1)
	for i := range receipts {
		receipts[i] = base
	}
	if _, err := NewActionResult(base.Recipient, receipts); err == nil {
		t.Fatal("aggregate result bound was not enforced")
	}
}
