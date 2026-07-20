package sampling_test

import (
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/protocol/content"
	"github.com/xrey167/meshmcp/protocol/sampling"
)

// TestCreateMessageResultDecode covers the tricky decoder: CreateMessageResult
// embeds Message (which has its own UnmarshalJSON) and overrides it to also
// pull model/stopReason and the embedded Result's _meta.
func TestCreateMessageResultDecode(t *testing.T) {
	raw := `{
		"_meta": {"io.modelcontextprotocol/serverInfo": {"name": "S", "version": "1"}},
		"role": "assistant",
		"content": {"type": "text", "text": "The capital of France is Paris."},
		"model": "claude-3-sonnet-20240307",
		"stopReason": "endTurn"
	}`
	var r sampling.CreateMessageResult
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Model != "claude-3-sonnet-20240307" || r.StopReason != "endTurn" {
		t.Fatalf("model/stopReason lost: %+v", r)
	}
	if r.Role != "assistant" {
		t.Fatalf("role lost: %q", r.Role)
	}
	tc, ok := r.Content.(*content.TextContent)
	if !ok || tc.Text != "The capital of France is Paris." {
		t.Fatalf("content lost: %#v", r.Content)
	}
	if r.Meta["io.modelcontextprotocol/serverInfo"] == nil {
		t.Fatalf("_meta lost: %+v", r.Meta)
	}
}
