package mcpclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"meshmcp/mcp"
)

// newTestClient wires an mcp.Server (configured by fn) to a Client over pipes.
func newTestClient(t *testing.T, fn func(*mcp.Server)) *Client {
	t.Helper()
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	s := mcp.New("test", "1.0")
	fn(s)
	go func() { _ = s.Serve(context.Background(), c2sR, s2cW); s2cW.Close() }()
	c := New(rwPipe{r: s2cR, w: c2sW}, nil)
	t.Cleanup(func() { c.Close() })
	if _, err := c.Initialize(context.Background(), "tester"); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	return c
}

func TestInvokeToolAndExecutionError(t *testing.T) {
	c := newTestClient(t, func(s *mcp.Server) {
		s.AddTool(mcp.Tool{Name: "add", InputSchema: map[string]any{"type": "object"},
			Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
				var a struct{ A, B float64 }
				_ = json.Unmarshal(args, &a)
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("42")}}, nil
			}})
		s.AddTool(mcp.Tool{Name: "boom",
			Handler: func(context.Context, json.RawMessage) (mcp.ToolResult, error) {
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("kaboom")}, IsError: true}, nil
			}})
	})
	ctx := context.Background()

	// A normal call returns a result, no error.
	res, err := c.InvokeTool(ctx, "add", map[string]any{"a": 2, "b": 40})
	if err != nil || res.Text() != "42" {
		t.Fatalf("add: res=%q err=%v", res.Text(), err)
	}
	// isError:true surfaces as a ToolExecutionError, distinct from transport error.
	res2, err := c.InvokeTool(ctx, "boom", map[string]any{})
	var toolErr *ToolExecutionError
	if !errors.As(err, &toolErr) {
		t.Fatalf("expected ToolExecutionError, got %v", err)
	}
	if toolErr.Tool != "boom" || res2.Text() != "kaboom" {
		t.Fatalf("execution error wrong: %+v", toolErr)
	}
}

func TestListFunctionsAndArgValidation(t *testing.T) {
	c := newTestClient(t, func(s *mcp.Server) {
		s.AddTool(mcp.Tool{Name: "math.add", Description: "add", InputSchema: map[string]any{"type": "object"},
			Handler: func(context.Context, json.RawMessage) (mcp.ToolResult, error) {
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("ok")}}, nil
			}})
	})
	ctx := context.Background()
	fns, err := c.ListFunctions(ctx)
	if err != nil || len(fns) != 1 || fns[0].Name != "math.add" {
		t.Fatalf("list functions wrong: %+v err=%v", fns, err)
	}
	// Valid single object.
	if _, err := c.InvokeFunction(ctx, ModelFunctionCall{Name: "math.add", Arguments: `{"a":2}`}); err != nil {
		t.Fatalf("valid function call failed: %v", err)
	}
	// Rejected shapes: array, null, scalar, trailing data.
	for _, bad := range []string{`[1,2]`, `null`, `42`, `"s"`, `{"a":1} {"b":2}`, ``} {
		if _, err := c.InvokeFunction(ctx, ModelFunctionCall{Name: "math.add", Arguments: bad}); err == nil {
			t.Fatalf("arguments %q should be rejected", bad)
		}
	}
}

func TestTaskClientLifecycle(t *testing.T) {
	c := newTestClient(t, func(s *mcp.Server) {
		s.AddTool(mcp.Tool{Name: "slow",
			Handler: func(ctx context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
				select {
				case <-time.After(80 * time.Millisecond):
				case <-ctx.Done():
					return mcp.ToolResult{}, ctx.Err()
				}
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("done")}}, nil
			}})
	})
	ctx := context.Background()

	task, err := c.StartTool(ctx, "slow", map[string]any{})
	if err != nil || task.TaskID == "" {
		t.Fatalf("start: %+v err=%v", task, err)
	}
	if task.Status != "working" {
		t.Fatalf("new task should be working, got %q", task.Status)
	}
	res, err := c.WaitTask(ctx, task.TaskID, WaitTaskOptions{PollInterval: 20 * time.Millisecond, MaxPolls: 100})
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if res.Text() != "done" {
		t.Fatalf("task result wrong: %q", res.Text())
	}
	// It should now be listed as terminal.
	tasks, err := c.ListTasks(ctx)
	if err != nil || len(tasks) == 0 || !tasks[0].Terminal() {
		t.Fatalf("list tasks wrong: %+v err=%v", tasks, err)
	}
}
