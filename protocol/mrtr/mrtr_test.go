package mrtr_test

import (
	"encoding/json"
	"testing"

	"meshmcp/protocol/mrtr"
)

func TestInputResponseRequestParams(t *testing.T) {
	// The client retries a request answering a prior InputRequiredResult.
	raw := `{
		"inputResponses": {"github_login": {"action": "accept", "content": {"name": "octocat"}}},
		"requestState": "AEAD-protected blob"
	}`
	var p mrtr.InputResponseRequestParams
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.RequestState != "AEAD-protected blob" {
		t.Fatalf("requestState lost: %q", p.RequestState)
	}
	if _, ok := p.InputResponses["github_login"]; !ok {
		t.Fatalf("inputResponses lost: %+v", p.InputResponses)
	}

	// A retry may carry only requestState (no responses).
	var p2 mrtr.InputResponseRequestParams
	if err := json.Unmarshal([]byte(`{"requestState":"blob"}`), &p2); err != nil {
		t.Fatalf("unmarshal state-only: %v", err)
	}
	if p2.RequestState != "blob" || p2.InputResponses != nil {
		t.Fatalf("state-only mismatch: %+v", p2)
	}
}
