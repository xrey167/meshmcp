package main

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/mcp"
)

func TestRouterAggregatesAndRoutes(t *testing.T) {
	addrA, stopA := startLoopbackServer(t, func(s *mcp.Server) {
		s.AddTool(addTool())
		s.AddResource(mcp.Resource{URI: "info://a", Name: "a-info",
			Read: func(_ context.Context) (mcp.ResourceContents, error) {
				return mcp.ResourceContents{Text: "from-a"}, nil
			}})
	})
	defer stopA()
	addrB, stopB := startLoopbackServer(t, func(s *mcp.Server) {
		s.AddTool(echoTool())
	})
	defer stopB()

	agg, cleanup := buildAggregate(context.Background(), loopbackDial,
		map[string][]string{"svca": {addrA}, "svcb": {addrB}}, nil)
	defer cleanup()

	mc := clientTo(agg)
	defer mc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := mc.Initialize(ctx, "test"); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	// tools/list is the namespaced union.
	tools, err := mc.ListTools(ctx)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	names := map[string]bool{}
	for _, tl := range tools {
		names[tl.Name] = true
	}
	if !names["svca.add"] || !names["svcb.echo"] {
		t.Fatalf("expected namespaced union svca.add + svcb.echo, got %v", names)
	}

	// A routed tool call reaches the right upstream.
	res, err := mc.CallTool(ctx, "svca.add", map[string]any{"a": 2, "b": 40}, false)
	if err != nil {
		t.Fatalf("call svca.add: %v", err)
	}
	if got := firstText(res); got != "42" {
		t.Fatalf("svca.add = %q, want 42", got)
	}
	res, err = mc.CallTool(ctx, "svcb.echo", map[string]any{"text": "hi"}, false)
	if err != nil {
		t.Fatalf("call svcb.echo: %v", err)
	}
	if got := firstText(res); got != "hi" {
		t.Fatalf("svcb.echo = %q, want hi", got)
	}

	// A routed resource read reaches its owner.
	rr, err := mc.ReadResource(ctx, "info://a")
	if err != nil {
		t.Fatalf("read info://a: %v", err)
	}
	if !strings.Contains(string(rr), "from-a") {
		t.Fatalf("resource read = %s, want from-a", rr)
	}
}

// TestRouterFailsOverToHealthyReplica verifies the router discovers and
// routes through a healthy replica when another replica of the same upstream
// is dead (connection refused).
func TestRouterFailsOverToHealthyReplica(t *testing.T) {
	addrGood, stop := startLoopbackServer(t, func(s *mcp.Server) {
		s.AddTool(addTool())
	})
	defer stop()

	// A dead address: bind then release a port so connections are refused.
	dl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dl.Addr().String()
	dl.Close()

	agg, cleanup := buildAggregate(context.Background(), loopbackDial,
		map[string][]string{"svc": {deadAddr, addrGood}}, nil)
	defer cleanup()

	mc := clientTo(agg)
	defer mc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := mc.Initialize(ctx, "test"); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	// Discovery must have failed over past the dead replica.
	tools, err := mc.ListTools(ctx)
	if err != nil || len(tools) == 0 {
		t.Fatalf("no tools discovered (failover during discovery failed): %v", err)
	}
	// A routed call must succeed via the healthy replica.
	res, err := mc.CallTool(ctx, "svc.add", map[string]any{"a": 2, "b": 40}, false)
	if err != nil {
		t.Fatalf("call failed despite a healthy replica: %v", err)
	}
	if got := firstText(res); got != "42" {
		t.Fatalf("svc.add = %q, want 42 (via failover)", got)
	}
}

// TestPoolHealthCheckRecoversReplica verifies the proactive health check
// re-dials a down replica so it is ready before the next call.
func TestPoolHealthCheckRecoversReplica(t *testing.T) {
	addr, stop := startLoopbackServer(t, func(s *mcp.Server) {
		s.AddTool(addTool())
	})
	defer stop()

	pool := newUpstreamPool("svc", []string{addr}, loopbackDial, nil,
		func(string, json.RawMessage) {}, nil)
	defer pool.closeAll()

	// Mark the replica down, past its cooldown.
	pool.mu.Lock()
	pool.replicas[0].failedAt = time.Now().Add(-time.Hour)
	pool.mu.Unlock()

	pool.healthCheck(context.Background())

	pool.mu.Lock()
	recovered := pool.replicas[0].client != nil
	pool.mu.Unlock()
	if !recovered {
		t.Fatal("health check did not recover the down replica")
	}
}
