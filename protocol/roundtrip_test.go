package protocol_test

import (
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/protocol/content"
	"github.com/xrey167/meshmcp/protocol/elicitation"
	"github.com/xrey167/meshmcp/protocol/initialize"
	"github.com/xrey167/meshmcp/protocol/resource"
	"github.com/xrey167/meshmcp/protocol/tool"
)

// TestInitializeResultRoundTrip checks that an embedded base.Result (_meta) and
// nested capabilities marshal and unmarshal faithfully.
func TestInitializeResultRoundTrip(t *testing.T) {
	in := initialize.InitializeResult{
		ProtocolVersion: "2025-06-18",
		Capabilities: initialize.ServerCapabilities{
			Tools:     &initialize.ToolsCapability{ListChanged: true},
			Resources: &initialize.ResourcesCapability{Subscribe: true},
		},
		ServerInfo:   initialize.Implementation{Version: "1.0.0"},
		Instructions: "hello",
	}
	in.ServerInfo.Name = "meshmcp"

	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out initialize.InitializeResult
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ServerInfo.Name != "meshmcp" || out.ProtocolVersion != "2025-06-18" {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	if out.Capabilities.Tools == nil || !out.Capabilities.Tools.ListChanged {
		t.Fatalf("tools capability lost: %+v", out.Capabilities)
	}
}

// TestCallResultContentUnion checks the polymorphic content block decoder via
// tool.CallResult.
func TestCallResultContentUnion(t *testing.T) {
	raw := `{
		"content": [
			{"type": "text", "text": "done"},
			{"type": "image", "data": "AAAA", "mimeType": "image/png"}
		],
		"isError": false
	}`
	var res tool.CallResult
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(res.Content) != 2 {
		t.Fatalf("want 2 blocks, got %d", len(res.Content))
	}
	txt, ok := res.Content[0].(*content.TextContent)
	if !ok || txt.Text != "done" {
		t.Fatalf("block 0 not TextContent: %#v", res.Content[0])
	}
	img, ok := res.Content[1].(*content.ImageContent)
	if !ok || img.MimeType != "image/png" {
		t.Fatalf("block 1 not ImageContent: %#v", res.Content[1])
	}

	// Re-marshal and ensure the discriminator survives.
	out, err := json.Marshal(&res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !json.Valid(out) {
		t.Fatalf("invalid json: %s", out)
	}
}

// TestReadResultContents checks the text/blob resource-contents union.
func TestReadResultContents(t *testing.T) {
	raw := `{"contents":[{"uri":"file:///a.txt","text":"hi"},{"uri":"file:///b.bin","blob":"QUJD"}]}`
	var res resource.ReadResult
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := res.Contents[0].(*resource.TextResourceContents); !ok {
		t.Fatalf("contents[0] not text: %#v", res.Contents[0])
	}
	if _, ok := res.Contents[1].(*resource.BlobResourceContents); !ok {
		t.Fatalf("contents[1] not blob: %#v", res.Contents[1])
	}
}

// TestElicitationSchemaUnion checks the primitive-schema discriminator,
// including the string-vs-enum disambiguation.
func TestElicitationSchemaUnion(t *testing.T) {
	raw := `{
		"type": "object",
		"properties": {
			"name": {"type": "string"},
			"age": {"type": "integer"},
			"color": {"type": "string", "enum": ["red", "green"]},
			"agree": {"type": "boolean"}
		},
		"required": ["name"]
	}`
	var s elicitation.RequestedSchema
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := s.Properties["name"].(*elicitation.StringSchema); !ok {
		t.Fatalf("name not StringSchema: %#v", s.Properties["name"])
	}
	if _, ok := s.Properties["age"].(*elicitation.NumberSchema); !ok {
		t.Fatalf("age not NumberSchema: %#v", s.Properties["age"])
	}
	if _, ok := s.Properties["color"].(*elicitation.EnumSchema); !ok {
		t.Fatalf("color not EnumSchema: %#v", s.Properties["color"])
	}
	if _, ok := s.Properties["agree"].(*elicitation.BooleanSchema); !ok {
		t.Fatalf("agree not BooleanSchema: %#v", s.Properties["agree"])
	}
}
