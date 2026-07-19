package policy

import "testing"

func TestPatternDLPDeniesAndLabels(t *testing.T) {
	h, err := NewPatternDLP([]DLPSpec{
		{Patterns: []string{`AKIA[0-9A-Z]{16}`}, Deny: true},
		{Patterns: []string{`\b\d{3}-\d{2}-\d{4}\b`}, Label: "pii"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// A secret-looking arg is denied.
	deny := h.DecideTool(ToolCallInfo{Arguments: []byte(`{"key":"AKIAABCDEFGHIJKLMNOP"}`)}, Decision{Outcome: OutcomeAllow, Allow: true})
	if deny.Outcome != OutcomeDeny {
		t.Fatalf("expected DLP deny, got %v", deny.Outcome)
	}

	// An SSN-looking arg is labeled but not denied.
	lab := h.DecideTool(ToolCallInfo{Arguments: []byte(`{"note":"ssn 123-45-6789"}`)}, Decision{Outcome: OutcomeAllow, Allow: true})
	if lab.Outcome != OutcomeAllow {
		t.Fatalf("label rule should not deny, got %v", lab.Outcome)
	}
	found := false
	for _, l := range lab.AddLabels {
		if l == "pii" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected pii label, got %v", lab.AddLabels)
	}

	// Clean args pass through unchanged.
	clean := h.DecideTool(ToolCallInfo{Arguments: []byte(`{"path":"README.md"}`)}, Decision{Outcome: OutcomeAllow, Allow: true})
	if clean.Outcome != OutcomeAllow || len(clean.AddLabels) != 0 {
		t.Fatalf("clean args altered: %+v", clean)
	}
}

func TestNewPatternDLPRejectsNoOpAndBadRegex(t *testing.T) {
	if _, err := NewPatternDLP([]DLPSpec{{Patterns: []string{"x"}}}); err == nil {
		t.Error("expected error for a spec that neither denies nor labels")
	}
	if _, err := NewPatternDLP([]DLPSpec{{Patterns: []string{"("}, Deny: true}}); err == nil {
		t.Error("expected error for a bad regex")
	}
}
