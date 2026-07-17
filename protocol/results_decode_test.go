package protocol_test

import (
	"encoding/json"
	"testing"

	"meshmcp/protocol/cancellation"
	"meshmcp/protocol/content"
	"meshmcp/protocol/messages"
	"meshmcp/protocol/tool"
)

// firstText returns the text of the first content block, requiring it to be a
// TextContent.
func firstText(t *testing.T, r *tool.CallResult) string {
	t.Helper()
	if len(r.Content) == 0 {
		t.Fatal("no content blocks")
	}
	tc, ok := r.Content[0].(*content.TextContent)
	if !ok {
		t.Fatalf("first block not TextContent: %#v", r.Content[0])
	}
	return tc.Text
}

// TestToolResultError decodes an error result (resultType is a draft-only field
// and is ignored by the 2025-06-18 model without failing).
func TestToolResultError(t *testing.T) {
	raw := `{
		"resultType": "complete",
		"content": [{"type": "text", "text": "Invalid departure date: must be in the future."}],
		"isError": true
	}`
	var r tool.CallResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !r.IsError {
		t.Fatal("isError should be true")
	}
	if firstText(t, &r) == "" {
		t.Fatal("text content lost")
	}
	if r.StructuredContent != nil {
		t.Fatalf("structuredContent should be absent: %s", r.StructuredContent)
	}
}

// TestToolResultStructuredArray decodes structuredContent shaped as a JSON
// array — valid under the draft (structuredContent: unknown), which the earlier
// map[string]any typing could not decode.
func TestToolResultStructuredArray(t *testing.T) {
	raw := `{
		"resultType": "complete",
		"content": [{"type": "text", "text": "Found 2 users."}],
		"structuredContent": [
			{"id": "1", "name": "Alice", "email": "alice@example.com"},
			{"id": "2", "name": "Bob", "email": "bob@example.com"}
		]
	}`
	var r tool.CallResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("unmarshal (array structuredContent): %v", err)
	}
	var users []map[string]any
	if err := json.Unmarshal(r.StructuredContent, &users); err != nil {
		t.Fatalf("decode structuredContent array: %v", err)
	}
	if len(users) != 2 || users[0]["name"] != "Alice" {
		t.Fatalf("users = %v", users)
	}
}

// TestToolResultStructuredObject decodes structuredContent shaped as a JSON
// object.
func TestToolResultStructuredObject(t *testing.T) {
	raw := `{
		"resultType": "complete",
		"content": [{"type": "text", "text": "{\"temperature\": 22.5}"}],
		"structuredContent": {"temperature": 22.5, "conditions": "Partly cloudy", "humidity": 65}
	}`
	var r tool.CallResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("unmarshal (object structuredContent): %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(r.StructuredContent, &obj); err != nil {
		t.Fatalf("decode structuredContent object: %v", err)
	}
	if obj["conditions"] != "Partly cloudy" {
		t.Fatalf("obj = %v", obj)
	}
}

// TestToolResultEnvelope decodes a full JSON-RPC result envelope and then its
// result payload as a tool.CallResult.
func TestToolResultEnvelope(t *testing.T) {
	raw := `{
		"jsonrpc": "2.0",
		"id": "call-tool-example",
		"result": {
			"resultType": "complete",
			"content": [{"type": "text", "text": "Current weather in New York: 72F"}],
			"isError": false
		}
	}`
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	var r tool.CallResult
	if err := json.Unmarshal(env.Result, &r); err != nil {
		t.Fatalf("result payload: %v", err)
	}
	if r.IsError {
		t.Fatal("isError should be false")
	}
	if firstText(t, &r) == "" {
		t.Fatal("text content lost")
	}
}

// TestCancelledNotification decodes the cancelled notification, both as a full
// frame via the dispatcher and as a bare params object.
func TestCancelledNotification(t *testing.T) {
	frame := `{
		"jsonrpc": "2.0",
		"method": "notifications/cancelled",
		"params": {"requestId": "123", "reason": "User requested cancellation"}
	}`
	n, err := messages.DecodeClientNotification([]byte(frame))
	if err != nil {
		t.Fatalf("decode notification: %v", err)
	}
	cn, ok := n.(*cancellation.CancelledNotification)
	if !ok {
		t.Fatalf("want *cancellation.CancelledNotification, got %T", n)
	}
	if cn.Params.RequestId != "123" || cn.Params.Reason != "User requested cancellation" {
		t.Fatalf("params = %+v", cn.Params)
	}

	var p cancellation.CancelledNotificationParams
	if err := json.Unmarshal([]byte(`{"requestId": "123", "reason": "User requested cancellation"}`), &p); err != nil {
		t.Fatalf("params unmarshal: %v", err)
	}
	if p.RequestId != "123" {
		t.Fatalf("requestId = %v", p.RequestId)
	}
}
