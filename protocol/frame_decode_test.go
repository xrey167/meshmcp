package protocol_test

import (
	"encoding/json"
	"testing"

	"meshmcp/protocol/messages"
	"meshmcp/protocol/tool"
	"meshmcp/protocol/transport"
)

// The tools/call frame supplied in the draft 2026-07-28 shape.
const callToolFrame = `{
  "jsonrpc": "2.0",
  "id": "call-tool-example",
  "method": "tools/call",
  "params": {
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": { "name": "ExampleClient", "version": "1.0.0" },
      "io.modelcontextprotocol/clientCapabilities": {}
    },
    "name": "get_weather",
    "arguments": { "location": "New York" }
  }
}`

// TestCallToolFrameRoutes decodes the full frame through the method dispatcher
// into the concrete *tool.CallRequest.
func TestCallToolFrameRoutes(t *testing.T) {
	req, err := messages.DecodeClientRequest([]byte(callToolFrame))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	call, ok := req.(*tool.CallRequest)
	if !ok {
		t.Fatalf("want *tool.CallRequest, got %T", req)
	}
	if call.Params.Name != "get_weather" {
		t.Fatalf("name = %q", call.Params.Name)
	}
	if call.Params.Arguments["location"] != "New York" {
		t.Fatalf("arguments = %v", call.Params.Arguments)
	}
}

// TestCallToolParamsTypedMeta decodes the params object (as supplied on its
// own) and verifies the typed request `_meta` fields.
func TestCallToolParamsTypedMeta(t *testing.T) {
	params := `{
      "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": { "name": "ExampleClient", "version": "1.0.0" },
        "io.modelcontextprotocol/clientCapabilities": {}
      },
      "name": "get_weather",
      "arguments": { "location": "New York" }
    }`

	var p struct {
		Meta      transport.RequestMeta `json:"_meta"`
		Name      string                `json:"name"`
		Arguments map[string]any        `json:"arguments"`
	}
	if err := json.Unmarshal([]byte(params), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Meta.ProtocolVersion != "2026-07-28" {
		t.Fatalf("protocolVersion = %q", p.Meta.ProtocolVersion)
	}
	if p.Meta.ClientInfo == nil || p.Meta.ClientInfo.Name != "ExampleClient" ||
		p.Meta.ClientInfo.Version != "1.0.0" {
		t.Fatalf("clientInfo = %+v", p.Meta.ClientInfo)
	}
	if p.Meta.ClientCapabilities == nil {
		t.Fatalf("clientCapabilities should decode to an empty (non-nil) object")
	}
	if p.Name != "get_weather" || p.Arguments["location"] != "New York" {
		t.Fatalf("name/args mismatch: %q %v", p.Name, p.Arguments)
	}

	// Re-marshal and confirm the well-known keys survive verbatim.
	out, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var probe map[string]any
	_ = json.Unmarshal(out, &probe)
	meta, _ := probe["_meta"].(map[string]any)
	if meta["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" {
		t.Fatalf("meta key not preserved on marshal: %v", meta)
	}
}
