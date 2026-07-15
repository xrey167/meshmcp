package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"meshmcp/mcp"
	"meshmcp/mcpclient"
)

// TestRouterRelaysServerRequest verifies full bidirectional MCP through the
// aggregator: an upstream tool issues a server->client sampling request; the
// router relays it down to the end client and the client's answer back up.
func TestRouterRelaysServerRequest(t *testing.T) {
	addr, stop := startLoopbackServer(t, func(s *mcp.Server) {
		s.AddTool(mcp.Tool{
			Name: "ask",
			Handler: func(ctx context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
				// Reverse request: ask the client to "sample".
				res, err := s.Request(ctx, "sampling/createMessage", map[string]any{"prompt": "hi"})
				if err != nil {
					return mcp.ToolResult{}, err
				}
				var r struct {
					Text string `json:"text"`
				}
				_ = json.Unmarshal(res, &r)
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("sampled: " + r.Text)}}, nil
			},
		})
	})
	defer stop()

	agg, cleanup := buildAggregate(context.Background(), loopbackDial,
		map[string][]string{"up": {addr}}, nil)
	defer cleanup()

	mc := clientTo(agg)
	defer mc.Close()

	// The downstream client answers server-initiated sampling requests.
	mc.SetOnRequest(func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, *mcpclient.RPCError) {
		if method != "sampling/createMessage" {
			return nil, &mcpclient.RPCError{Code: -32601, Message: "unexpected method: " + method}
		}
		return json.RawMessage(`{"text":"world"}`), nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := mc.Initialize(ctx, "test"); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	res, err := mc.CallTool(ctx, "up.ask", map[string]any{}, false)
	if err != nil {
		t.Fatalf("up.ask: %v", err)
	}
	if got := firstText(res); got != "sampled: world" {
		t.Fatalf("bidirectional relay failed: got %q, want %q", got, "sampled: world")
	}
}
