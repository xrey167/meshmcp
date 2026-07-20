package protocol_test

import (
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/protocol/completion"
	"github.com/xrey167/meshmcp/protocol/messages"
	"github.com/xrey167/meshmcp/protocol/transport"
)

// TestCompletionFrameRoutes decodes a full completion/complete frame through the
// dispatcher, verifying the polymorphic ref decodes to a prompt reference.
func TestCompletionFrameRoutes(t *testing.T) {
	frame := `{
		"jsonrpc": "2.0",
		"id": "completion-example",
		"method": "completion/complete",
		"params": {
			"_meta": {
				"io.modelcontextprotocol/protocolVersion": "2026-07-28",
				"io.modelcontextprotocol/clientInfo": {"name": "ExampleClient", "version": "1.0.0"},
				"io.modelcontextprotocol/clientCapabilities": {}
			},
			"ref": {"type": "ref/prompt", "name": "code_review"},
			"argument": {"name": "language", "value": "py"}
		}
	}`
	req, err := messages.DecodeClientRequest([]byte(frame))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	c, ok := req.(*completion.CompleteRequest)
	if !ok {
		t.Fatalf("want *completion.CompleteRequest, got %T", req)
	}
	ref, ok := c.Params.Ref.(*completion.PromptReference)
	if !ok {
		t.Fatalf("ref not a PromptReference: %#v", c.Params.Ref)
	}
	if ref.Name != "code_review" || ref.Type != completion.TypePromptRef {
		t.Fatalf("ref mismatch: %+v", ref)
	}
	if c.Params.Argument.Name != "language" || c.Params.Argument.Value != "py" {
		t.Fatalf("argument mismatch: %+v", c.Params.Argument)
	}
}

// TestCompletionParamsWithContext decodes a completion params object carrying a
// context.arguments map, and shows the typed request _meta decodes separately.
func TestCompletionParamsWithContext(t *testing.T) {
	params := `{
		"_meta": {
			"io.modelcontextprotocol/protocolVersion": "2026-07-28",
			"io.modelcontextprotocol/clientInfo": {"name": "ExampleClient", "version": "1.0.0"},
			"io.modelcontextprotocol/clientCapabilities": {}
		},
		"ref": {"type": "ref/prompt", "name": "code_review"},
		"argument": {"name": "framework", "value": "fla"},
		"context": {"arguments": {"language": "python"}}
	}`
	var p completion.CompleteRequestParams
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		t.Fatalf("params unmarshal: %v", err)
	}
	if _, ok := p.Ref.(*completion.PromptReference); !ok {
		t.Fatalf("ref not a PromptReference: %#v", p.Ref)
	}
	if p.Context == nil || p.Context.Arguments["language"] != "python" {
		t.Fatalf("context lost: %+v", p.Context)
	}

	// The well-known request _meta decodes into the typed helper.
	var meta struct {
		Meta transport.RequestMeta `json:"_meta"`
	}
	if err := json.Unmarshal([]byte(params), &meta); err != nil {
		t.Fatalf("meta unmarshal: %v", err)
	}
	if meta.Meta.ProtocolVersion != "2026-07-28" || meta.Meta.ClientInfo.Name != "ExampleClient" {
		t.Fatalf("typed _meta mismatch: %+v", meta.Meta)
	}
}

// TestCompletionResult decodes a completion result (bare and enveloped). The
// draft-only resultType field is ignored by the 2025-06-18 model.
func TestCompletionResult(t *testing.T) {
	bare := `{
		"resultType": "complete",
		"completion": {"values": ["python", "pytorch", "pyside"], "total": 10, "hasMore": true}
	}`
	var r completion.CompleteResult
	if err := json.Unmarshal([]byte(bare), &r); err != nil {
		t.Fatalf("bare result: %v", err)
	}
	if len(r.Completion.Values) != 3 || r.Completion.Total == nil || *r.Completion.Total != 10 || !r.Completion.HasMore {
		t.Fatalf("completion mismatch: %+v", r.Completion)
	}

	enveloped := `{
		"jsonrpc": "2.0",
		"id": "completion-example",
		"result": {"resultType": "complete", "completion": {"values": ["flask"], "total": 1, "hasMore": false}}
	}`
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(enveloped), &env); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	var r2 completion.CompleteResult
	if err := json.Unmarshal(env.Result, &r2); err != nil {
		t.Fatalf("enveloped result: %v", err)
	}
	if len(r2.Completion.Values) != 1 || r2.Completion.Values[0] != "flask" || r2.Completion.HasMore {
		t.Fatalf("enveloped completion mismatch: %+v", r2.Completion)
	}
}
