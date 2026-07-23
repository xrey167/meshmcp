package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestApplyLimitsValidation(t *testing.T) {
	s := New("t", "1")
	if err := ApplyLimits(s, LimitsConfig{Global: ToolLimits{Timeout: -time.Second}}); err == nil {
		t.Fatal("negative global timeout must fail validation")
	}
	if err := ApplyLimits(s, LimitsConfig{PerTool: map[string]ToolLimits{"x": {MaxConcurrent: -1}}}); err == nil {
		t.Fatal("negative per-tool max_concurrent must fail validation")
	}
	if err := ApplyLimits(s, LimitsConfig{PerTool: map[string]ToolLimits{"": {Timeout: time.Second}}}); err == nil {
		t.Fatal("empty tool name must fail validation")
	}
	if err := ApplyLimits(s, LimitsConfig{}); err != nil {
		t.Fatalf("empty config must be valid: %v", err)
	}
}

func TestApplyLimitsPerToolTimeout(t *testing.T) {
	s := New("t", "1")
	s.AddTool(Tool{Name: "slow", Handler: func(ctx context.Context, _ json.RawMessage) (ToolResult, error) {
		<-ctx.Done()
		return ToolResult{}, ctx.Err()
	}})
	s.AddTool(Tool{Name: "fast", Handler: func(ctx context.Context, _ json.RawMessage) (ToolResult, error) {
		if _, hasDeadline := ctx.Deadline(); hasDeadline {
			return ToolResult{}, errors.New("fast must not inherit slow's per-tool timeout")
		}
		return ToolResult{}, nil
	}})
	if err := ApplyLimits(s, LimitsConfig{PerTool: map[string]ToolLimits{
		"slow": {Timeout: 10 * time.Millisecond},
	}}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.effectiveHandler(s.tools["slow"])(context.Background(), nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("slow: want deadline exceeded, got %v", err)
	}
	if _, err := s.effectiveHandler(s.tools["fast"])(context.Background(), nil); err != nil {
		t.Fatalf("fast: %v", err)
	}
}

func TestApplyLimitsConcurrency(t *testing.T) {
	s := New("t", "1")
	var cur, peak int64
	release := make(chan struct{})
	s.AddTool(Tool{Name: "busy", Handler: func(context.Context, json.RawMessage) (ToolResult, error) {
		c := atomic.AddInt64(&cur, 1)
		for {
			p := atomic.LoadInt64(&peak)
			if c <= p || atomic.CompareAndSwapInt64(&peak, p, c) {
				break
			}
		}
		<-release
		atomic.AddInt64(&cur, -1)
		return ToolResult{}, nil
	}})
	if err := ApplyLimits(s, LimitsConfig{
		Global:  ToolLimits{Timeout: time.Minute},
		PerTool: map[string]ToolLimits{"busy": {MaxConcurrent: 2}},
	}); err != nil {
		t.Fatal(err)
	}

	h := s.effectiveHandler(s.tools["busy"])
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = h(context.Background(), nil) }()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if p := atomic.LoadInt64(&peak); p > 2 {
		t.Fatalf("concurrency peak %d exceeds limit 2", p)
	}
}
