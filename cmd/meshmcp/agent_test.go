package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/mcp"
	"github.com/xrey167/meshmcp/mcpclient"
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
		`{"type":"nudge","text":"focus","target":"task:9f2a","id":"corr-7"}` + "\n" +
		`{"type":"cancel"}` + "\n")
	var got []steerEnvelope
	if err := recvEnvelopes(in, func(e steerEnvelope) { got = append(got, e) }); err != nil {
		t.Fatalf("recvEnvelopes: %v", err)
	}
	if len(got) != 3 || got[0].Type != "task" || got[0].Tool != "read_file" || got[2].Type != "cancel" {
		t.Fatalf("unexpected envelopes: %+v", got)
	}
	if got[1].Target != "task:9f2a" || got[1].ID != "corr-7" {
		t.Fatalf("target/id not parsed: %+v", got[1])
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

// argsCaller is a toolCaller that records each call's tool name and args map.
type argsCaller struct {
	mu    sync.Mutex
	names []string
	args  []map[string]any
}

func (c *argsCaller) CallTool(_ context.Context, name string, args any, _ bool) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.names = append(c.names, name)
	m, _ := args.(map[string]any)
	c.args = append(c.args, m)
	return json.RawMessage(`{}`), nil
}

// TestRunAgentLoopNudgeGuidance proves a nudge's text is carried as a
// "guidance" argument on the following scripted steps — and that the shared
// role script's own args map is never mutated.
func TestRunAgentLoopNudgeGuidance(t *testing.T) {
	caller := &argsCaller{}
	steps := []agentStep{{tool: "noop", args: map[string]any{"path": "x"}}}
	steer := make(chan steerEnvelope, 2)
	done := make(chan error, 1)
	go func() {
		done <- runAgentLoop(context.Background(), caller, steps, 0, time.Hour, steer, func(string, ...any) {})
	}()

	steer <- steerEnvelope{Type: "nudge", Text: "focus on the API"}
	steer <- steerEnvelope{Type: "cancel"}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel steer did not stop the loop")
	}

	caller.mu.Lock()
	defer caller.mu.Unlock()
	// Call 1 runs before the nudge (no guidance); call 2 runs after it.
	if len(caller.args) < 2 {
		t.Fatalf("expected at least 2 calls, got %d", len(caller.args))
	}
	if _, has := caller.args[0]["guidance"]; has {
		t.Fatalf("first call should carry no guidance: %v", caller.args[0])
	}
	if g := caller.args[1]["guidance"]; g != "focus on the API" {
		t.Fatalf("second call guidance = %v, want the nudge text (args: %v)", g, caller.args[1])
	}
	if caller.args[1]["path"] != "x" {
		t.Fatalf("original args must be preserved alongside guidance: %v", caller.args[1])
	}
	if _, has := steps[0].args["guidance"]; has {
		t.Fatal("the shared step args map was mutated")
	}
}

// steeringCaller is a toolCaller that also implements taskSteerer, recording
// task-target routing.
type steeringCaller struct {
	mu        sync.Mutex
	called    []string
	steered   []string
	cancelled []string
	payloads  []json.RawMessage
}

func (s *steeringCaller) CallTool(_ context.Context, name string, _ any, _ bool) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.called = append(s.called, name)
	return json.RawMessage(`{}`), nil
}

func (s *steeringCaller) SteerTask(_ context.Context, id string, payload json.RawMessage) (mcpclient.Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steered = append(s.steered, id)
	s.payloads = append(s.payloads, payload)
	return mcpclient.Task{TaskID: id, Status: "working"}, nil
}

func (s *steeringCaller) CancelTask(_ context.Context, id string) (mcpclient.Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancelled = append(s.cancelled, id)
	return mcpclient.Task{TaskID: id, Status: "cancelled"}, nil
}

// TestApplySteerTaskTarget proves a steer addressed "task:<id>" is routed to
// that task on the backend (tasks/steer / tasks/cancel) instead of acting on
// the agent loop, and that unsupported targets are refused without action.
func TestApplySteerTaskTarget(t *testing.T) {
	sc := &steeringCaller{}
	var guidance string
	logf := func(string, ...any) {}

	// cancel with a task target routes to CancelTask — it must NOT stop the loop.
	if stop := applySteer(context.Background(), sc, steerEnvelope{Type: "cancel", Target: "task:9f2a"}, &guidance, logf); stop {
		t.Fatal("a task-targeted cancel must not stop the agent loop")
	}
	// nudge with a task target routes to SteerTask.
	applySteer(context.Background(), sc, steerEnvelope{Type: "nudge", Text: "focus", Target: "task:7b1c"}, &guidance, logf)
	// task with a task target routes to SteerTask, not a direct CallTool.
	applySteer(context.Background(), sc, steerEnvelope{Type: "task", Tool: "read_customer", Target: "task:7b1c"}, &guidance, logf)
	// An unsupported target is ignored: no call, no routing.
	applySteer(context.Background(), sc, steerEnvelope{Type: "task", Tool: "read_customer", Target: "session:abc"}, &guidance, logf)

	sc.mu.Lock()
	defer sc.mu.Unlock()
	if len(sc.cancelled) != 1 || sc.cancelled[0] != "9f2a" {
		t.Fatalf("cancelled = %v, want [9f2a]", sc.cancelled)
	}
	if len(sc.steered) != 2 || sc.steered[0] != "7b1c" {
		t.Fatalf("steered = %v, want two 7b1c routings", sc.steered)
	}
	if len(sc.called) != 0 {
		t.Fatalf("no direct CallTool should happen for targeted steers, got %v", sc.called)
	}
	if guidance != "" {
		t.Fatalf("a targeted nudge must not change the agent's own guidance, got %q", guidance)
	}
	// A client without task support ignores the target gracefully.
	rec := &recordingCaller{onCall: func(string) { t.Fatal("no call expected") }}
	applySteer(context.Background(), rec, steerEnvelope{Type: "cancel", Target: "task:9f2a"}, &guidance, logf)
}

// TestAgentSteerPortRequiresAllow proves the steer inbox is deny-by-default: a
// --steer-port without any --steer-allow identity is a startup error, since a
// steer runs tool calls under the agent's own identity (borrowed authority).
func TestAgentSteerPortRequiresAllow(t *testing.T) {
	err := cmdAgent([]string{"--role", "reader", "--steer-port", "9120", "1.2.3.4:9101"})
	if err == nil || !strings.Contains(err.Error(), "--steer-allow") {
		t.Fatalf("agent --steer-port without --steer-allow must fail closed, got: %v", err)
	}
}
