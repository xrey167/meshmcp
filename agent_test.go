package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"meshmcp/mcp"
)

// TestRunAgentLoopDrivesRoleCalls proves an agent role issues exactly its
// scripted tool sequence against a backend, driven over an in-process client.
func TestRunAgentLoopDrivesRoleCalls(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := mcp.New("demo", "1.0")
	record := func(name string) mcp.Tool {
		return mcp.Tool{Name: name, Handler: func(_ context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
			mu.Lock()
			got = append(got, name)
			mu.Unlock()
			return mcp.ToolResult{Content: []mcp.Content{mcp.Text("ok")}}, nil
		}}
	}
	// Register the tools the "reader" role calls.
	for _, n := range []string{"read_file", "list_dir", "write_file"} {
		srv.AddTool(record(n))
	}

	mc := clientTo(srv)
	ctx := context.Background()
	if _, err := mc.Initialize(ctx, "test"); err != nil {
		t.Fatal(err)
	}

	// Run exactly 3 calls of the reader role, no delay.
	err := runAgentLoop(ctx, mc, roleScripts["reader"], 3, 0, nil, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"read_file", "list_dir", "write_file"}
	if len(got) != 3 {
		t.Fatalf("expected 3 calls, got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call %d: want %s, got %s (all: %v)", i, want[i], got[i], got)
		}
	}
}

func TestRunAgentLoopStopsAtCount(t *testing.T) {
	srv := mcp.New("demo", "1.0")
	srv.AddTool(mcp.Tool{Name: "read_file", Handler: func(_ context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
		return mcp.ToolResult{}, nil
	}})
	// billing role has 2 steps; ask for 5 calls → it should cycle and stop at 5.
	calls := 0
	counter := &countingCaller{onCall: func() { calls++ }}
	if err := runAgentLoop(context.Background(), counter, roleScripts["billing"], 5, 0, nil, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if calls != 5 {
		t.Fatalf("expected exactly 5 calls, got %d", calls)
	}
}

// TestRunAgentLoopSteerTask proves a "task" steer injects an extra call, and a
// "cancel" steer stops the loop.
func TestRunAgentLoopSteerTask(t *testing.T) {
	var mu sync.Mutex
	var got []string
	counter := &recordingCaller{onCall: func(name string) { mu.Lock(); got = append(got, name); mu.Unlock() }}

	steer := make(chan steerEnvelope, 4)
	// A long interval means only steers (not the timer) advance the loop.
	steps := []agentStep{{tool: "noop"}}
	done := make(chan error, 1)
	go func() {
		done <- runAgentLoop(context.Background(), counter, steps, 0, time.Hour, steer, func(string, ...any) {})
	}()

	steer <- steerEnvelope{Type: "task", Tool: "read_customer", Args: json.RawMessage(`{"id":42}`)}
	steer <- steerEnvelope{Type: "nudge", Text: "focus"}
	steer <- steerEnvelope{Type: "cancel"}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loop returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel steer did not stop the loop")
	}

	mu.Lock()
	defer mu.Unlock()
	// First scripted step ("noop") plus the steered "read_customer".
	if len(got) < 2 || got[0] != "noop" {
		t.Fatalf("expected noop then read_customer, got %v", got)
	}
	sawSteered := false
	for _, c := range got {
		if c == "read_customer" {
			sawSteered = true
		}
	}
	if !sawSteered {
		t.Fatalf("steered task call never happened: %v", got)
	}
}

// TestRecvEnvelopes checks newline-delimited envelope parsing.
func TestRecvEnvelopes(t *testing.T) {
	in := strings.NewReader(`{"type":"task","tool":"read_file","args":{"path":"x"}}` + "\n" +
		"\n" + // blank line skipped
		`{"type":"cancel"}` + "\n")
	var got []steerEnvelope
	if err := recvEnvelopes(in, func(e steerEnvelope) { got = append(got, e) }); err != nil {
		t.Fatalf("recvEnvelopes: %v", err)
	}
	if len(got) != 2 || got[0].Type != "task" || got[0].Tool != "read_file" || got[1].Type != "cancel" {
		t.Fatalf("unexpected envelopes: %+v", got)
	}
	// A malformed line is an error.
	if err := recvEnvelopes(strings.NewReader("not json\n"), func(steerEnvelope) {}); err == nil {
		t.Fatal("expected error on malformed envelope")
	}
}

func TestAllRolesHaveScripts(t *testing.T) {
	for _, r := range []string{"reader", "fetcher", "billing", "analyst"} {
		if len(roleScripts[r]) == 0 {
			t.Fatalf("role %q has no script", r)
		}
	}
}

// recordingCaller is a toolCaller that records each call's tool name.
type recordingCaller struct{ onCall func(name string) }

func (c *recordingCaller) CallTool(_ context.Context, name string, _ any, _ bool) (json.RawMessage, error) {
	c.onCall(name)
	return json.RawMessage(`{}`), nil
}

// countingCaller is a toolCaller that just counts calls.
type countingCaller struct{ onCall func() }

func (c *countingCaller) CallTool(_ context.Context, _ string, _ any, _ bool) (json.RawMessage, error) {
	c.onCall()
	return json.RawMessage(`{}`), nil
}
