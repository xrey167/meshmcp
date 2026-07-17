package prompt_test

import (
	"encoding/json"
	"testing"

	"meshmcp/protocol/content"
	"meshmcp/protocol/prompt"
)

// TestGetResultDecode covers prompt.Message.UnmarshalJSON (the content-block
// decoder in the prompts/get path), previously untested.
func TestGetResultDecode(t *testing.T) {
	raw := `{
		"description": "A code review prompt",
		"messages": [
			{"role": "user", "content": {"type": "text", "text": "Review this code"}},
			{"role": "assistant", "content": {"type": "text", "text": "Looks good"}}
		]
	}`
	var r prompt.GetResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(r.Messages) != 2 || r.Description != "A code review prompt" {
		t.Fatalf("result mismatch: %+v", r)
	}
	if r.Messages[0].Role != "user" {
		t.Fatalf("role lost: %q", r.Messages[0].Role)
	}
	tc, ok := r.Messages[0].Content.(*content.TextContent)
	if !ok || tc.Text != "Review this code" {
		t.Fatalf("message content lost: %#v", r.Messages[0].Content)
	}
}
