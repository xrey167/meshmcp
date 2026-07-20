package elicitationdraft_test

import (
	"encoding/json"
	"testing"

	ed "github.com/xrey167/meshmcp/protocol/elicitationdraft"
)

func TestFormModeRequest(t *testing.T) {
	frame := `{
		"method": "elicitation/create",
		"params": {
			"mode": "form",
			"message": "Please provide your contact information",
			"requestedSchema": {
				"type": "object",
				"properties": {
					"name": {"type": "string", "description": "Your full name"},
					"email": {"type": "string", "format": "email"},
					"age": {"type": "number", "minimum": 18},
					"subscribe": {"type": "boolean", "default": true}
				},
				"required": ["name", "email"]
			}
		}
	}`
	var r ed.ElicitRequest
	if err := json.Unmarshal([]byte(frame), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	fp, ok := r.Params.(*ed.FormParams)
	if !ok || fp.Mode() != ed.ModeForm {
		t.Fatalf("params not form: %#v", r.Params)
	}
	props := fp.RequestedSchema.Properties
	if _, ok := props["name"].(*ed.StringSchema); !ok {
		t.Fatalf("name not StringSchema: %#v", props["name"])
	}
	if _, ok := props["email"].(*ed.StringSchema); !ok {
		t.Fatalf("email not StringSchema: %#v", props["email"])
	}
	if _, ok := props["age"].(*ed.NumberSchema); !ok {
		t.Fatalf("age not NumberSchema: %#v", props["age"])
	}
	if _, ok := props["subscribe"].(*ed.BooleanSchema); !ok {
		t.Fatalf("subscribe not BooleanSchema: %#v", props["subscribe"])
	}
}

func TestURLModeRequest(t *testing.T) {
	frame := `{
		"method": "elicitation/create",
		"params": {"mode": "url", "url": "https://mcp.example.com/ui/set_api_key", "message": "Provide your API key."}
	}`
	var r ed.ElicitRequest
	if err := json.Unmarshal([]byte(frame), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	up, ok := r.Params.(*ed.URLParams)
	if !ok || up.Mode() != ed.ModeURL {
		t.Fatalf("params not url: %#v", r.Params)
	}
	if up.URL != "https://mcp.example.com/ui/set_api_key" {
		t.Fatalf("url = %q", up.URL)
	}
}

func TestEnumSchemaVariants(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want any
	}{
		{"untitled-single", `{"type":"string","enum":["Red","Green","Blue"]}`, &ed.UntitledSingleSelectEnumSchema{}},
		{"titled-single", `{"type":"string","oneOf":[{"const":"#FF0000","title":"Red"}]}`, &ed.TitledSingleSelectEnumSchema{}},
		{"legacy", `{"type":"string","enum":["a","b"],"enumNames":["A","B"]}`, &ed.LegacyTitledEnumSchema{}},
		{"untitled-multi", `{"type":"array","minItems":1,"maxItems":2,"items":{"type":"string","enum":["Red","Green","Blue"]},"default":["Red","Green"]}`, &ed.UntitledMultiSelectEnumSchema{}},
		{"titled-multi", `{"type":"array","minItems":1,"maxItems":2,"items":{"anyOf":[{"const":"#FF0000","title":"Red"},{"const":"#00FF00","title":"Green"}]},"default":["#FF0000"]}`, &ed.TitledMultiSelectEnumSchema{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := ed.DecodePrimitiveSchema([]byte(c.raw))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got, want := typeName(s), typeName(c.want); got != want {
				t.Fatalf("decoded %s, want %s", got, want)
			}
		})
	}

	// Spot-check field decoding on the two array variants.
	um, _ := ed.DecodePrimitiveSchema([]byte(`{"type":"array","items":{"type":"string","enum":["Red","Green"]},"maxItems":2}`))
	if u := um.(*ed.UntitledMultiSelectEnumSchema); len(u.Items.Enum) != 2 || u.MaxItems == nil || *u.MaxItems != 2 {
		t.Fatalf("untitled-multi fields: %+v", u)
	}
	tm, _ := ed.DecodePrimitiveSchema([]byte(`{"type":"array","items":{"anyOf":[{"const":"x","title":"X"}]}}`))
	if tt := tm.(*ed.TitledMultiSelectEnumSchema); len(tt.Items.AnyOf) != 1 || tt.Items.AnyOf[0].Title != "X" {
		t.Fatalf("titled-multi fields: %+v", tt)
	}
}

func typeName(v any) string {
	switch v.(type) {
	case *ed.UntitledSingleSelectEnumSchema:
		return "untitled-single"
	case *ed.TitledSingleSelectEnumSchema:
		return "titled-single"
	case *ed.LegacyTitledEnumSchema:
		return "legacy"
	case *ed.UntitledMultiSelectEnumSchema:
		return "untitled-multi"
	case *ed.TitledMultiSelectEnumSchema:
		return "titled-multi"
	case *ed.StringSchema:
		return "string"
	default:
		return "unknown"
	}
}

func TestElicitResult(t *testing.T) {
	// URL-mode accept: no content.
	var r1 ed.ElicitResult
	if err := json.Unmarshal([]byte(`{"action":"accept"}`), &r1); err != nil {
		t.Fatalf("r1: %v", err)
	}
	if r1.Action != ed.ActionAccept || r1.Content != nil {
		t.Fatalf("r1 mismatch: %+v", r1)
	}

	// Form accept with content (incl. a number and a string).
	var r2 ed.ElicitResult
	if err := json.Unmarshal([]byte(`{"action":"accept","content":{"name":"Monalisa Octocat","email":"octocat@github.com","age":30}}`), &r2); err != nil {
		t.Fatalf("r2: %v", err)
	}
	if r2.Content["name"] != "Monalisa Octocat" || r2.Content["age"].(float64) != 30 {
		t.Fatalf("r2 content: %+v", r2.Content)
	}
}

func TestErrorPaths(t *testing.T) {
	if _, err := ed.DecodePrimitiveSchema([]byte(`{"type":"bogus"}`)); err == nil {
		t.Fatal("expected error for unknown primitive schema type")
	}
	if _, err := ed.DecodeParams([]byte(`{"mode":"telepathy"}`)); err == nil {
		t.Fatal("expected error for unknown elicitation mode")
	}
}
