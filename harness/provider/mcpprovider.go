package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/xrey167/meshmcp/mcpclient"
)

// MCPProvider reaches a model that is exposed as an MCP tool over a connection.
// In production the Dial reaches the remote MCP server over the mesh, so a
// remote or cross-org provider is reached with transport-bound identity and is
// audited on both sides (federation) — the tri-model synthesize across orgs
// inherits governance automatically. It adapts a remote completion tool to the
// uniform Provider interface.
type MCPProvider struct {
	name  string
	class string
	tool  string // the completion tool name on the remote server
	dial  func(ctx context.Context) (net.Conn, error)
	caps  ModelCaps
}

// MCPConfig configures an MCP-backed provider.
type MCPConfig struct {
	Name  string
	Class string
	// Tool is the remote tool that performs a completion. It is called with
	// {"system":..., "prompt":...} and must return a text content block.
	Tool string
	// Dial opens a connection to the remote MCP server (a mesh dial in prod).
	Dial func(ctx context.Context) (net.Conn, error)
	Caps ModelCaps
}

// NewMCPProvider builds an MCP-backed provider.
func NewMCPProvider(cfg MCPConfig) *MCPProvider {
	caps := cfg.Caps
	if caps.Name == "" {
		caps.Name = cfg.Name
	}
	if caps.Class == "" {
		caps.Class = cfg.Class
	}
	tool := cfg.Tool
	if tool == "" {
		tool = "complete"
	}
	return &MCPProvider{name: cfg.Name, class: cfg.Class, tool: tool, dial: cfg.Dial, caps: caps}
}

func (p *MCPProvider) Name() string            { return p.name }
func (p *MCPProvider) Class() string           { return p.class }
func (p *MCPProvider) Capabilities() ModelCaps { return p.caps }

// Available reports whether a dial is configured. A dial that then fails is an
// explicit, audited error at Invoke rather than a silent skip.
func (p *MCPProvider) Available(ctx context.Context) bool { return p.dial != nil }

// Invoke dials the remote server, calls its completion tool, and adapts the
// result. The connection is per-call (one completion per dial); the remote
// server holds its own credentials, so no key crosses in the prompt.
func (p *MCPProvider) Invoke(ctx context.Context, in Prompt) (Completion, error) {
	if p.dial == nil {
		return Completion{}, fmt.Errorf("provider %s: no dial configured", p.name)
	}
	conn, err := p.dial(ctx)
	if err != nil {
		return Completion{}, fmt.Errorf("provider %s: dial: %w", p.name, err)
	}
	// A dial that returns (nil, nil) is a misbehaving dialer; guard it so we
	// surface a clear error instead of panicking on a nil connection downstream.
	if conn == nil {
		return Completion{}, fmt.Errorf("provider %s: dial returned a nil connection", p.name)
	}
	c := mcpclient.New(conn, nil)
	defer c.Close()
	if _, err := c.Initialize(ctx, "harness-provider"); err != nil {
		return Completion{}, fmt.Errorf("provider %s: initialize: %w", p.name, err)
	}
	raw, err := c.CallTool(ctx, p.tool, map[string]any{"system": in.System, "prompt": in.User}, false)
	if err != nil {
		return Completion{}, fmt.Errorf("provider %s: call %q: %w", p.name, p.tool, err)
	}
	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return Completion{}, fmt.Errorf("provider %s: decode result: %w", p.name, err)
	}
	text := ""
	if len(res.Content) > 0 {
		text = res.Content[0].Text
	}
	if res.IsError {
		return Completion{}, fmt.Errorf("provider %s: remote error: %s", p.name, text)
	}
	return Completion{
		Text:      text,
		TokensIn:  estimateTokens(in.System) + estimateTokens(in.User),
		TokensOut: estimateTokens(text),
		Provider:  p.name,
	}, nil
}

// Stream delivers Invoke's completion as a single delta (the remote tool call is
// unary; per-token streaming would require the remote server's stream protocol).
func (p *MCPProvider) Stream(ctx context.Context, in Prompt) (<-chan Delta, error) {
	comp, err := p.Invoke(ctx, in)
	if err != nil {
		return nil, err
	}
	ch := make(chan Delta, 2)
	ch <- Delta{Text: comp.Text}
	ch <- Delta{Done: true}
	close(ch)
	return ch, nil
}
