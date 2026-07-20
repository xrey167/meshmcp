package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/mcp"
)

func TestOrchestratorCallsUpstream(t *testing.T) {
	addr, stop := startLoopbackServer(t, func(s *mcp.Server) {
		s.AddTool(addTool())
		s.AddTool(echoTool())
	})
	defer stop()

	orch := mcp.New("orchestrator", "1.0")
	registerResearch(orch, loopbackDial, addr)

	mc := clientTo(orch)
	defer mc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := mc.Initialize(ctx, "test"); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	res, err := mc.CallTool(ctx, "research",
		map[string]any{"topic": "hello", "a": 2, "b": 40}, false)
	if err != nil {
		t.Fatalf("call research: %v", err)
	}
	got := firstText(res)
	// research must have called add + echo on the upstream and combined them.
	if !strings.Contains(got, "= 42") {
		t.Fatalf("research result missing add(2,40)=42: %q", got)
	}
	if !strings.Contains(got, `echo("hello") = hello`) {
		t.Fatalf("research result missing echo: %q", got)
	}
}
