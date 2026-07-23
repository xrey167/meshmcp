package provider

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/mcp"
)

// serveMockModel starts an in-process MCP server exposing a "complete" tool that
// echoes the prompt, and returns a dial that connects a fresh client each call.
func serveMockModel(t *testing.T) func(ctx context.Context) (net.Conn, error) {
	t.Helper()
	return func(ctx context.Context) (net.Conn, error) {
		c1, c2 := net.Pipe()
		s := mcp.New("mock-model", "0.1.0")
		s.AddTool(mcp.Tool{
			Name:        "complete",
			InputSchema: map[string]any{"type": "object"},
			Handler: func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
				var p struct{ System, Prompt string }
				_ = json.Unmarshal(args, &p)
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("model says: " + p.Prompt)}}, nil
			},
		})
		go func() { _ = s.Serve(context.Background(), c1, c1) }()
		return c2, nil
	}
}

func TestMCPProviderInvoke(t *testing.T) {
	p := NewMCPProvider(MCPConfig{Name: "remote", Class: "gpt-medium", Dial: serveMockModel(t)})
	if !p.Available(context.Background()) {
		t.Fatal("provider with a dial should be available")
	}
	c, err := p.Invoke(context.Background(), Prompt{User: "hello"})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !strings.Contains(c.Text, "model says: hello") {
		t.Fatalf("unexpected completion: %q", c.Text)
	}
	if c.Provider != "remote" || c.TokensOut == 0 {
		t.Fatalf("usage/provider not populated: %+v", c)
	}
}

func TestMCPProviderInRegistryFallback(t *testing.T) {
	reg := NewRegistry()
	// An unavailable primary, then the remote MCP provider.
	reg.Register(stubbedUnavailable{NewMock("down", "gpt-medium")})
	reg.Register(NewMCPProvider(MCPConfig{Name: "remote", Class: "gpt-medium", Dial: serveMockModel(t)}))
	p, err := reg.Resolve(context.Background(), "gpt-medium")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if p.Name() != "remote" {
		t.Fatalf("expected fallback to the remote provider, got %q", p.Name())
	}
}

func TestMCPProviderNoDial(t *testing.T) {
	p := NewMCPProvider(MCPConfig{Name: "x", Class: "c"})
	if p.Available(context.Background()) {
		t.Fatal("a provider with no dial must not be available")
	}
	if _, err := p.Invoke(context.Background(), Prompt{User: "hi"}); err == nil {
		t.Fatal("invoke with no dial must error")
	}
}
