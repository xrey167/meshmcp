package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMiddlewareOrderAndSnapshot(t *testing.T) {
	var order []string
	mw := func(tag string) ToolMiddleware {
		return func(next ToolHandler) ToolHandler {
			return func(ctx context.Context, args json.RawMessage) (ToolResult, error) {
				order = append(order, tag)
				return next(ctx, args)
			}
		}
	}
	s := New("t", "1")
	s.Use(mw("global-1"), mw("global-2"))
	s.AddTool(Tool{Name: "x", Handler: func(ctx context.Context, _ json.RawMessage) (ToolResult, error) {
		info, ok := ToolCallFrom(ctx)
		if !ok || info.Tool != "x" {
			t.Errorf("ToolCallFrom missing/wrong: %+v ok=%v", info, ok)
		}
		order = append(order, "handler")
		return ToolResult{Content: []Content{Text("ok")}}, nil
	}})
	s.UseTool("x", mw("tool-1"))

	h := s.effectiveHandler(s.tools["x"])
	ctx := withToolCall(context.Background(), ToolCallInfo{Tool: "x"})
	if _, err := h(ctx, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	// global (first = outermost) → per-tool → handler.
	want := "global-1,global-2,tool-1,handler"
	if got := strings.Join(order, ","); got != want {
		t.Fatalf("order: got %q want %q", got, want)
	}
}

func TestRecoverPanicsRedacts(t *testing.T) {
	h := RecoverPanics()(func(context.Context, json.RawMessage) (ToolResult, error) {
		panic("secret internal detail")
	})
	_, err := h(context.Background(), nil)
	if err == nil || strings.Contains(err.Error(), "secret internal detail") {
		t.Fatalf("panic must be recovered and redacted, got %v", err)
	}
}

func TestLimitConcurrency(t *testing.T) {
	var cur, max int32
	var mu sync.Mutex
	release := make(chan struct{})
	h := LimitConcurrency(2)(func(context.Context, json.RawMessage) (ToolResult, error) {
		mu.Lock()
		cur++
		if cur > max {
			max = cur
		}
		mu.Unlock()
		<-release
		mu.Lock()
		cur--
		mu.Unlock()
		return ToolResult{}, nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = h(context.Background(), nil) }()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if max > 2 {
		t.Fatalf("concurrency exceeded limit: peak %d", max)
	}
}

func TestTimeoutPropagates(t *testing.T) {
	h := Timeout(10*time.Millisecond)(func(ctx context.Context, _ json.RawMessage) (ToolResult, error) {
		<-ctx.Done()
		return ToolResult{}, ctx.Err()
	})
	_, err := h(context.Background(), nil)
	if err == nil {
		t.Fatal("timeout should propagate a deadline error")
	}
}
