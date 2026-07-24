package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestAuditRecordSchema_AllowsPeerSpiffeID guards the AUDIT-RECORD.md /
// audit-record.schema.json pairing (docs/spec/AGENTS.md's stated contract):
// the schema has "additionalProperties": false, so a record marshaled with
// PeerSpiffeID set must have a corresponding "peer_spiffe_id" schema property,
// or every such record becomes schema-invalid. This is a minimal structural
// check (required keys + no unknown keys), not a full JSON Schema validator —
// the repo has no schema-validation dependency to build one on.
func TestAuditRecordSchema_AllowsPeerSpiffeID(t *testing.T) {
	schemaBytes, err := os.ReadFile("../docs/spec/audit-record.schema.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	if schema.AdditionalProperties {
		t.Fatalf("expected additionalProperties:false in the schema")
	}
	if _, ok := schema.Properties["peer_spiffe_id"]; !ok {
		t.Fatalf("schema must declare peer_spiffe_id under additionalProperties:false, or every record with the field becomes schema-invalid")
	}

	// Write real records (so seq/prev_hash/hash are populated as they would
	// be on a live log), one without and one with PeerSpiffeID set.
	var buf bytes.Buffer
	a := NewAuditLog(&buf, func() string { return "T" })
	a.write(AuditRecord{Backend: "kg", Peer: "p", Method: "tools/call", Decision: "allow", Rule: 0})
	a.write(AuditRecord{
		Backend:      "kg",
		Peer:         "p",
		Method:       "tools/call",
		Decision:     "allow",
		Rule:         0,
		PeerSpiffeID: SpiffeID("meshmcp.example.org", netbirdShapedKey),
	})

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 written records, got %d", len(lines))
	}
	sawSpiffeID := false
	for _, line := range lines {
		var asMap map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &asMap); err != nil {
			t.Fatal(err)
		}
		if _, ok := asMap["peer_spiffe_id"]; ok {
			sawSpiffeID = true
		}
		for k := range asMap {
			if _, ok := schema.Properties[k]; !ok {
				t.Errorf("record field %q has no matching schema property (additionalProperties:false would reject it): %s", k, line)
			}
		}
		for _, req := range schema.Required {
			if _, ok := asMap[req]; !ok {
				t.Errorf("record is missing schema-required field %q: %s", req, line)
			}
		}
	}
	if !sawSpiffeID {
		t.Fatalf("expected at least one written record to carry peer_spiffe_id")
	}
}

// TestAuditRecordSchema_AllowsDelegationFields guards the same schema/doc
// pairing for the Phase-4 router-delegation attribution fields: a record
// carrying delegated_caller / delegation_router / delegation_nonce must stay
// schema-valid under additionalProperties:false.
func TestAuditRecordSchema_AllowsDelegationFields(t *testing.T) {
	schemaBytes, err := os.ReadFile("../docs/spec/audit-record.schema.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	for _, field := range []string{"delegated_caller", "delegation_router", "delegation_nonce"} {
		if _, ok := schema.Properties[field]; !ok {
			t.Fatalf("schema must declare %s under additionalProperties:false, or every delegated record becomes schema-invalid", field)
		}
	}

	var buf bytes.Buffer
	a := NewAuditLog(&buf, func() string { return "T" })
	a.write(AuditRecord{
		Backend: "svc", Peer: "router.mesh", Method: "tools/call", Decision: "allow", Rule: 0,
		DelegatedCaller: "CALLER", DelegationRouter: "ROUTER", DelegationNonce: "n1",
	})
	line := strings.TrimSpace(buf.String())
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &asMap); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"delegated_caller", "delegation_router", "delegation_nonce"} {
		if _, ok := asMap[field]; !ok {
			t.Errorf("written record is missing %s: %s", field, line)
		}
	}
	for k := range asMap {
		if _, ok := schema.Properties[k]; !ok {
			t.Errorf("record field %q has no matching schema property (additionalProperties:false would reject it): %s", k, line)
		}
	}
	for _, req := range schema.Required {
		if _, ok := asMap[req]; !ok {
			t.Errorf("record is missing schema-required field %q: %s", req, line)
		}
	}
}

// TestAuditRecordSchema_AllowsPayment guards the same schema/doc pairing for the
// additive payment-evidence field: a record carrying a payment receipt must stay
// schema-valid under additionalProperties:false, and the nested payment object's
// own keys must all be declared (its subschema is additionalProperties:false
// too).
func TestAuditRecordSchema_AllowsPayment(t *testing.T) {
	schemaBytes, err := os.ReadFile("../docs/spec/audit-record.schema.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	paymentSchemaRaw, ok := schema.Properties["payment"]
	if !ok {
		t.Fatalf("schema must declare payment under additionalProperties:false, or every paid record becomes schema-invalid")
	}
	var paymentSchema struct {
		AdditionalProperties bool                       `json:"additionalProperties"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(paymentSchemaRaw, &paymentSchema); err != nil {
		t.Fatalf("parse payment subschema: %v", err)
	}
	if paymentSchema.AdditionalProperties {
		t.Fatalf("payment subschema must be additionalProperties:false, or an unknown evidence key would slip past the schema/record parity guard")
	}

	var buf bytes.Buffer
	a := NewAuditLog(&buf, func() string { return "T" })
	ev := NewPaymentEvidence("x402", "base-sepolia", "USDC", "1000", "settle-ref", "payer-id", "backend")
	a.write(AuditRecord{
		Backend: "edge:carbon", Peer: "oauth:c1", Method: "x402/settle", Tool: "estimate",
		Decision: "allow", Rule: -1, Payment: &ev,
	})
	line := strings.TrimSpace(buf.String())
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &asMap); err != nil {
		t.Fatal(err)
	}
	rawPayment, ok := asMap["payment"]
	if !ok {
		t.Fatalf("written paid record is missing payment: %s", line)
	}
	for k := range asMap {
		if _, ok := schema.Properties[k]; !ok {
			t.Errorf("record field %q has no matching schema property: %s", k, line)
		}
	}
	// Every key of the emitted payment object must be a declared subschema
	// property, since the subschema is additionalProperties:false.
	var payMap map[string]json.RawMessage
	if err := json.Unmarshal(rawPayment, &payMap); err != nil {
		t.Fatal(err)
	}
	for k := range payMap {
		if _, ok := paymentSchema.Properties[k]; !ok {
			t.Errorf("payment field %q has no matching subschema property: %s", k, string(rawPayment))
		}
	}
}
