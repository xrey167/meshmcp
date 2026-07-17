package samplingtools_test

import (
	"encoding/json"
	"testing"

	"meshmcp/protocol/content"
	"meshmcp/protocol/samplingtools"
)

// TestToolUseConversation decodes a multi-turn sampling request whose messages
// carry text, an array of tool_use blocks, and an array of tool_result blocks.
func TestToolUseConversation(t *testing.T) {
	params := `{
		"messages": [
			{"role": "user", "content": {"type": "text", "text": "Weather in Paris and London?"}},
			{"role": "assistant", "content": [
				{"type": "tool_use", "id": "call_abc123", "name": "get_weather", "input": {"city": "Paris"}},
				{"type": "tool_use", "id": "call_def456", "name": "get_weather", "input": {"city": "London"}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "toolUseId": "call_abc123", "content": [{"type": "text", "text": "Paris: 18C"}]},
				{"type": "tool_result", "toolUseId": "call_def456", "content": [{"type": "text", "text": "London: 15C"}]}
			]}
		],
		"tools": [{"name": "get_weather", "description": "Get weather", "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}],
		"maxTokens": 1000
	}`
	var p samplingtools.CreateMessageRequestParams
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.Messages) != 3 || p.MaxTokens != 1000 || len(p.Tools) != 1 {
		t.Fatalf("params mismatch: msgs=%d tools=%d", len(p.Messages), len(p.Tools))
	}

	// Message 1: single text block, normalized to a 1-element slice.
	if len(p.Messages[0].Content) != 1 {
		t.Fatalf("msg0 content = %d blocks", len(p.Messages[0].Content))
	}
	if _, ok := p.Messages[0].Content[0].(*content.TextContent); !ok {
		t.Fatalf("msg0 not text: %#v", p.Messages[0].Content[0])
	}

	// Message 2: two tool_use blocks.
	tu, ok := p.Messages[1].Content[0].(*samplingtools.ToolUseContent)
	if !ok || tu.Name != "get_weather" || tu.Input["city"] != "Paris" {
		t.Fatalf("msg1 block0 not tool_use: %#v", p.Messages[1].Content[0])
	}

	// Message 3: tool_result blocks with nested content.
	tr, ok := p.Messages[2].Content[0].(*samplingtools.ToolResultContent)
	if !ok || tr.ToolUseID != "call_abc123" || len(tr.Content) != 1 {
		t.Fatalf("msg2 block0 not tool_result: %#v", p.Messages[2].Content[0])
	}
	if _, ok := tr.Content[0].(*content.TextContent); !ok {
		t.Fatalf("tool_result nested content not text: %#v", tr.Content[0])
	}
}

// TestToolChoice decodes a request carrying a toolChoice.
func TestToolChoice(t *testing.T) {
	params := `{
		"messages": [{"role": "user", "content": {"type": "text", "text": "weather?"}}],
		"tools": [{"name": "get_weather", "inputSchema": {"type": "object"}}],
		"toolChoice": {"mode": "auto"},
		"maxTokens": 1000
	}`
	var p samplingtools.CreateMessageRequestParams
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.ToolChoice == nil || p.ToolChoice.Mode != samplingtools.ToolChoiceAuto {
		t.Fatalf("toolChoice mismatch: %+v", p.ToolChoice)
	}
}

// TestToolUseResult decodes an assistant result whose content is an array of
// tool_use blocks with stopReason "toolUse".
func TestToolUseResult(t *testing.T) {
	raw := `{
		"role": "assistant",
		"content": [
			{"type": "tool_use", "id": "call_abc123", "name": "get_weather", "input": {"city": "Paris"}},
			{"type": "tool_use", "id": "call_def456", "name": "get_weather", "input": {"city": "London"}}
		],
		"model": "claude-3-sonnet-20240307",
		"stopReason": "toolUse"
	}`
	var r samplingtools.CreateMessageResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Model != "claude-3-sonnet-20240307" || r.StopReason != samplingtools.StopToolUse {
		t.Fatalf("result scalar mismatch: %+v", r)
	}
	if len(r.Content) != 2 {
		t.Fatalf("want 2 tool_use blocks, got %d", len(r.Content))
	}
	if _, ok := r.Content[1].(*samplingtools.ToolUseContent); !ok {
		t.Fatalf("block1 not tool_use: %#v", r.Content[1])
	}
}

// TestTextResult decodes a plain text assistant result (single content block).
func TestTextResult(t *testing.T) {
	raw := `{
		"role": "assistant",
		"content": {"type": "text", "text": "The capital of France is Paris."},
		"model": "claude-3-sonnet-20240307",
		"stopReason": "endTurn"
	}`
	var r samplingtools.CreateMessageResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(r.Content) != 1 || r.StopReason != samplingtools.StopEndTurn {
		t.Fatalf("text result mismatch: %+v", r)
	}
	if _, ok := r.Content[0].(*content.TextContent); !ok {
		t.Fatalf("block not text: %#v", r.Content[0])
	}
}
