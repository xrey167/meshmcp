package mcpclient

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Task is an asynchronous tool invocation's handle/state.
type Task struct {
	TaskID string `json:"taskId"`
	Status string `json:"status"` // working | completed | failed | cancelled
	Error  string `json:"error,omitempty"`
}

// Terminal reports whether the task will not change further.
func (t Task) Terminal() bool {
	return t.Status == "completed" || t.Status == "failed" || t.Status == "cancelled"
}

// WaitTaskOptions bounds WaitTask.
type WaitTaskOptions struct {
	PollInterval time.Duration // default 100ms
	MaxPolls     int           // default 300; total wait is also bounded by ctx
}

// StartTool starts a tool as an asynchronous task and returns its handle.
func (c *Client) StartTool(ctx context.Context, name string, args any) (Task, error) {
	raw, err := c.CallTool(ctx, name, args, true)
	if err != nil {
		return Task{}, err
	}
	var h struct {
		Task Task `json:"task"`
	}
	if err := json.Unmarshal(raw, &h); err != nil || h.Task.TaskID == "" {
		return Task{}, fmt.Errorf("unexpected task handle: %s", string(raw))
	}
	return h.Task, nil
}

// ListTasks lists the server's tasks.
func (c *Client) ListTasks(ctx context.Context) ([]Task, error) {
	raw, err := c.Call(ctx, "tasks/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	// The server returns either a bare array or {"tasks":[...]}.
	var arr []Task
	if json.Unmarshal(raw, &arr) == nil && arr != nil {
		return arr, nil
	}
	var wrap struct {
		Tasks []Task `json:"tasks"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, err
	}
	return wrap.Tasks, nil
}

// GetTask fetches one task's current state.
func (c *Client) GetTask(ctx context.Context, taskID string) (Task, error) {
	raw, err := c.Call(ctx, "tasks/get", map[string]any{"taskId": taskID})
	if err != nil {
		return Task{}, err
	}
	var t Task
	return t, json.Unmarshal(raw, &t)
}

// CancelTask cancels a task.
func (c *Client) CancelTask(ctx context.Context, taskID string) (Task, error) {
	raw, err := c.Call(ctx, "tasks/cancel", map[string]any{"taskId": taskID})
	if err != nil {
		return Task{}, err
	}
	var t Task
	return t, json.Unmarshal(raw, &t)
}

// SteerTask delivers mid-flight guidance to a working task (Air · Steer, P3) —
// the augment counterpart to CancelTask's interrupt. The payload is arbitrary
// JSON the task's handler interprets; only a handler cooperating with steers
// reacts. Returns the task's post-steer handle.
func (c *Client) SteerTask(ctx context.Context, taskID string, payload json.RawMessage) (Task, error) {
	raw, err := c.Call(ctx, "tasks/steer", map[string]any{"taskId": taskID, "payload": payload})
	if err != nil {
		return Task{}, err
	}
	var t Task
	return t, json.Unmarshal(raw, &t)
}

// TaskResult fetches a completed task's result. A tool that reported
// isError:true comes back as a *ToolExecutionError.
func (c *Client) TaskResult(ctx context.Context, taskID string) (ToolCallResult, error) {
	raw, err := c.Call(ctx, "tasks/result", map[string]any{"taskId": taskID})
	if err != nil {
		return ToolCallResult{}, err
	}
	res := decodeToolResult(raw)
	if res.IsError {
		return res, &ToolExecutionError{Tool: taskID, Result: res}
	}
	return res, nil
}

// WaitTask polls a task to a terminal state and returns its result. Waiting is
// bounded by both ctx and MaxPolls. If ctx is cancelled it sends a best-effort
// notifications/cancelled carrying the task ID so the server doesn't run on.
func (c *Client) WaitTask(ctx context.Context, taskID string, opts WaitTaskOptions) (ToolCallResult, error) {
	if opts.PollInterval <= 0 {
		opts.PollInterval = 100 * time.Millisecond
	}
	if opts.MaxPolls <= 0 {
		opts.MaxPolls = 300
	}
	for i := 0; i < opts.MaxPolls; i++ {
		t, err := c.GetTask(ctx, taskID)
		if err != nil {
			return ToolCallResult{}, err
		}
		switch t.Status {
		case "completed", "failed":
			return c.TaskResult(ctx, taskID)
		case "cancelled":
			return ToolCallResult{}, fmt.Errorf("task %s was cancelled", taskID)
		}
		select {
		case <-ctx.Done():
			_ = c.Notify("notifications/cancelled", map[string]any{"taskId": taskID})
			return ToolCallResult{}, ctx.Err()
		case <-time.After(opts.PollInterval):
		}
	}
	return ToolCallResult{}, fmt.Errorf("task %s did not finish within %d polls", taskID, opts.MaxPolls)
}
