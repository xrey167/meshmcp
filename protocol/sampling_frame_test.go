package protocol_test

import (
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/protocol/content"
	"github.com/xrey167/meshmcp/protocol/messages"
	"github.com/xrey167/meshmcp/protocol/sampling"
)

// TestSamplingFrameRoutes decodes a full sampling/createMessage frame (a
// server-initiated request) and its polymorphic message content.
func TestSamplingFrameRoutes(t *testing.T) {
	frame := `{
		"method": "sampling/createMessage",
		"params": {
			"messages": [
				{"role": "user", "content": {"type": "text", "text": "What is the capital of France?"}}
			],
			"modelPreferences": {
				"hints": [{"name": "claude-3-sonnet"}],
				"intelligencePriority": 0.8,
				"speedPriority": 0.5
			},
			"systemPrompt": "You are a helpful assistant.",
			"maxTokens": 100
		}
	}`
	req, err := messages.DecodeServerRequest([]byte(frame))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	cm, ok := req.(*sampling.CreateMessageRequest)
	if !ok {
		t.Fatalf("want *sampling.CreateMessageRequest, got %T", req)
	}
	assertSamplingParams(t, cm.Params)
}

// TestSamplingParams decodes the params object on its own.
func TestSamplingParams(t *testing.T) {
	params := `{
		"messages": [
			{"role": "user", "content": {"type": "text", "text": "What is the capital of France?"}}
		],
		"modelPreferences": {
			"hints": [{"name": "claude-3-sonnet"}],
			"intelligencePriority": 0.8,
			"speedPriority": 0.5
		},
		"systemPrompt": "You are a helpful assistant.",
		"maxTokens": 100
	}`
	var p sampling.CreateMessageRequestParams
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	assertSamplingParams(t, p)
}

func assertSamplingParams(t *testing.T, p sampling.CreateMessageRequestParams) {
	t.Helper()
	if p.MaxTokens != 100 || p.SystemPrompt != "You are a helpful assistant." {
		t.Fatalf("scalar params mismatch: %+v", p)
	}
	if len(p.Messages) != 1 {
		t.Fatalf("want 1 message, got %d", len(p.Messages))
	}
	txt, ok := p.Messages[0].Content.(*content.TextContent)
	if !ok || txt.Text != "What is the capital of France?" {
		t.Fatalf("message content mismatch: %#v", p.Messages[0].Content)
	}
	if p.ModelPreferences == nil || len(p.ModelPreferences.Hints) != 1 ||
		p.ModelPreferences.Hints[0].Name != "claude-3-sonnet" {
		t.Fatalf("model preferences mismatch: %+v", p.ModelPreferences)
	}
	if p.ModelPreferences.IntelligencePriority == nil || *p.ModelPreferences.IntelligencePriority != 0.8 {
		t.Fatalf("intelligencePriority mismatch: %+v", p.ModelPreferences)
	}
}
