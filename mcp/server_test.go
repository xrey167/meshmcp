package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testServer() *Server {
	s := New("test", "1.0")
	s.AddTool(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}},
		Handler: func(_ context.Context, args json.RawMessage) (ToolResult, error) {
			var a struct{ Text string `json:"text"` }
			_ = json.Unmarshal(args, &a)
			return ToolResult{Content: []Content{Text(a.Text)}}, nil
		},
	})
	s.AddTool(Tool{
		Name: "boom",
		Handler: func(_ context.Context, _ json.RawMessage) (ToolResult, error) {
			return ToolResult{}, errors.New("kaboom")
		},
	})
	s.AddResource(Resource{
		URI: "info://x", Name: "x", MimeType: "text/plain",
		Read: func(_ context.Context) (ResourceContents, error) {
			return ResourceContents{Text: "hello"}, nil
		},
	})
	s.AddPrompt(Prompt{
		Name:      "greet",
		Arguments: []PromptArg{{Name: "who", Required: true}},
		Get: func(_ context.Context, args map[string]string) (PromptResult, error) {
			return PromptResult{Messages: []PromptMessage{{Role: "user", Content: Text("hi " + args["who"])}}}, nil
		},
	})
	return s
}

func call(t *testing.T, s *Server, method, params string) response {
	t.Helper()
	var p json.RawMessage
	if params != "" {
		p = json.RawMessage(params)
	}
	return s.dispatch(context.Background(), request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: method, Params: p}, &Session{})
}

func mustResult(t *testing.T, r response) map[string]any {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("unexpected error: %+v", r.Error)
	}
	b, _ := json.Marshal(r.Result)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("result not an object: %v", err)
	}
	return m
}

func TestInitializeAdvertisesRegisteredCapabilities(t *testing.T) {
	m := mustResult(t, call(t, testServer(), "initialize", "{}"))
	if m["protocolVersion"] != ProtocolVersion {
		t.Fatalf("protocolVersion = %v", m["protocolVersion"])
	}
	caps := m["capabilities"].(map[string]any)
	for _, want := range []string{"tools", "resources", "prompts"} {
		if _, ok := caps[want]; !ok {
			t.Fatalf("capabilities missing %q: %v", want, caps)
		}
	}
}

func TestInitializeOmitsUnusedCapabilities(t *testing.T) {
	s := New("bare", "1.0")
	s.AddTool(Tool{Name: "t", Handler: func(_ context.Context, _ json.RawMessage) (ToolResult, error) { return ToolResult{}, nil }})
	m := mustResult(t, call(t, s, "initialize", "{}"))
	caps := m["capabilities"].(map[string]any)
	if _, ok := caps["resources"]; ok {
		t.Fatalf("should not advertise resources: %v", caps)
	}
	if _, ok := caps["prompts"]; ok {
		t.Fatalf("should not advertise prompts: %v", caps)
	}
}

func TestToolsCall(t *testing.T) {
	s := testServer()
	m := mustResult(t, call(t, s, "tools/call", `{"name":"echo","arguments":{"text":"hi"}}`))
	content := m["content"].([]any)
	first := content[0].(map[string]any)
	if first["text"] != "hi" || first["type"] != "text" {
		t.Fatalf("bad content: %v", content)
	}

	// Handler error -> isError result, not a protocol error.
	m = mustResult(t, call(t, s, "tools/call", `{"name":"boom"}`))
	if m["isError"] != true {
		t.Fatalf("expected isError, got %v", m)
	}

	// Unknown tool -> protocol error.
	r := call(t, s, "tools/call", `{"name":"nope"}`)
	if r.Error == nil || r.Error.Code != codeInvalidParams {
		t.Fatalf("expected invalid params for unknown tool, got %+v", r)
	}
}

func TestResources(t *testing.T) {
	s := testServer()
	m := mustResult(t, call(t, s, "resources/list", "{}"))
	if len(m["resources"].([]any)) != 1 {
		t.Fatalf("expected 1 resource: %v", m)
	}
	m = mustResult(t, call(t, s, "resources/read", `{"uri":"info://x"}`))
	contents := m["contents"].([]any)
	first := contents[0].(map[string]any)
	if first["text"] != "hello" || first["uri"] != "info://x" || first["mimeType"] != "text/plain" {
		t.Fatalf("bad contents: %v", contents)
	}
	if r := call(t, s, "resources/read", `{"uri":"nope://y"}`); r.Error == nil {
		t.Fatalf("expected error for unknown resource")
	}
}

func TestPrompts(t *testing.T) {
	s := testServer()
	m := mustResult(t, call(t, s, "prompts/list", "{}"))
	if len(m["prompts"].([]any)) != 1 {
		t.Fatalf("expected 1 prompt: %v", m)
	}
	m = mustResult(t, call(t, s, "prompts/get", `{"name":"greet","arguments":{"who":"mesh"}}`))
	msgs := m["messages"].([]any)
	c := msgs[0].(map[string]any)["content"].(map[string]any)
	if !strings.Contains(c["text"].(string), "hi mesh") {
		t.Fatalf("bad prompt render: %v", msgs)
	}
	// Missing required argument -> error.
	if r := call(t, s, "prompts/get", `{"name":"greet","arguments":{}}`); r.Error == nil {
		t.Fatalf("expected error for missing required arg")
	}
}

func TestUnknownMethod(t *testing.T) {
	if r := call(t, testServer(), "does/notExist", "{}"); r.Error == nil || r.Error.Code != codeMethodNotFound {
		t.Fatalf("expected method not found, got %+v", r)
	}
}
