package tool_test

import (
	"encoding/json"
	"testing"

	"meshmcp/protocol/tool"
)

// toolExamples are the official draft schema/draft/examples/Tool fixtures. Each
// must decode into tool.Tool without error, preserving the (arbitrary) JSON
// Schema of inputSchema/outputSchema verbatim.
var toolExamples = map[string]string{
	"array-output": `{
		"name": "list_users", "title": "User List", "description": "Returns users",
		"inputSchema": {"type": "object", "properties": {}},
		"outputSchema": {"type": "array", "items": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}}
	}`,
	"composition-input": `{
		"name": "find_resource", "title": "Resource Finder", "description": "Find by id or name",
		"inputSchema": {"type": "object", "oneOf": [
			{"properties": {"id": {"type": "string"}}, "required": ["id"]},
			{"properties": {"name": {"type": "string"}}, "required": ["name"]}
		]}
	}`,
	"no-parameters": `{
		"name": "ping", "description": "No params",
		"inputSchema": {"type": "object", "properties": {}}
	}`,
	"explicit-draft07": `{
		"name": "legacy", "description": "draft-07 input",
		"inputSchema": {"$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "properties": {"q": {"type": "string"}}}
	}`,
}

func TestToolConformance(t *testing.T) {
	for name, raw := range toolExamples {
		t.Run(name, func(t *testing.T) {
			var tl tool.Tool
			if err := json.Unmarshal([]byte(raw), &tl); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if tl.Name == "" {
				t.Fatal("name lost")
			}
			// inputSchema must survive verbatim (oneOf / $schema / items preserved).
			if len(tl.InputSchema) == 0 {
				t.Fatal("inputSchema lost")
			}
			var in map[string]any
			if err := json.Unmarshal(tl.InputSchema, &in); err != nil {
				t.Fatalf("inputSchema not valid JSON: %v", err)
			}
			if in["type"] != "object" {
				t.Fatalf("inputSchema type = %v", in["type"])
			}
		})
	}

	// The composition example must keep its oneOf intact.
	var comp tool.Tool
	_ = json.Unmarshal([]byte(toolExamples["composition-input"]), &comp)
	var in map[string]any
	_ = json.Unmarshal(comp.InputSchema, &in)
	if _, ok := in["oneOf"]; !ok {
		t.Fatalf("oneOf dropped from inputSchema: %v", in)
	}

	// The array-output example must keep outputSchema type "array".
	var arr tool.Tool
	_ = json.Unmarshal([]byte(toolExamples["array-output"]), &arr)
	var out map[string]any
	_ = json.Unmarshal(arr.OutputSchema, &out)
	if out["type"] != "array" {
		t.Fatalf("outputSchema type = %v (array dropped)", out["type"])
	}
}
