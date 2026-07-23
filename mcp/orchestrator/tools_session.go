package orchestrator

import (
	"context"
	"encoding/json"

	"github.com/xrey167/meshmcp/harness"
	"github.com/xrey167/meshmcp/mcp"
)

func (s *Server) registerSessionAndTasks() {
	// Session tools are identity-scoped by session/; the live session backend is
	// Phase-2 wiring. They are registered and governed here.
	for _, t := range []string{"session_list", "session_read", "session_search", "session_info", "sessions_send"} {
		name := t
		s.mcp.AddTool(mcp.Tool{
			Name:        name,
			Description: "Session tool (identity-scoped; live session backend wired in Phase 2)",
			InputSchema: obj(map[string]any{
				"session_id": str("session id"),
				"query":      str("search query (session_search)"),
				"text":       str("message text (sessions_send)"),
			}),
			Handler: s.pendingBackend(name),
		})
	}

	// Task-store tools are backed by the in-process store (air-backed in
	// production so tasks survive handoff/resume).
	s.mcp.AddTool(mcp.Tool{
		Name:        "task_create",
		Description: "Create a task in the run task store.",
		InputSchema: obj(map[string]any{"title": str("task title"), "body": str("optional body"), "parent": str("optional parent task id")}, "title"),
		Handler:     s.toolTaskCreate,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "task_get",
		Description: "Get a task by id.",
		InputSchema: obj(map[string]any{"task_id": str("task id")}, "task_id"),
		Handler:     s.toolTaskGet,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "task_list",
		Description: "List tasks, optionally filtered by status (open|in_progress|done|failed).",
		InputSchema: obj(map[string]any{"filter": str("optional status filter")}),
		Handler:     s.toolTaskList,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "task_update",
		Description: "Update a task's status/title/body.",
		InputSchema: obj(map[string]any{
			"task_id": str("task id"),
			"status":  str("new status: open|in_progress|done|failed"),
			"title":   str("new title"),
			"body":    str("new body"),
		}, "task_id"),
		Handler: s.toolTaskUpdate,
	})
}

func (s *Server) toolTaskCreate(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Title, Body, Parent string
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Title == "" {
		return errText("title is required"), nil
	}
	t := s.tasks.create(p.Title, p.Body, p.Parent)
	return jsonText(map[string]any{"task_id": t.ID}), nil
}

func (s *Server) toolTaskGet(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.TaskID == "" {
		return errText("task_id is required"), nil
	}
	t, ok := s.tasks.get(p.TaskID)
	if !ok {
		return errText("no such task %q", p.TaskID), nil
	}
	return jsonText(t), nil
}

func (s *Server) toolTaskList(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Filter string `json:"filter"`
	}
	_ = json.Unmarshal(args, &p)
	return jsonText(map[string]any{"tasks": s.tasks.list(harness.TaskStatus(p.Filter))}), nil
}

func (s *Server) toolTaskUpdate(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
		Title  string `json:"title"`
		Body   string `json:"body"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.TaskID == "" {
		return errText("task_id is required"), nil
	}
	t, ok := s.tasks.update(p.TaskID, harness.TaskStatus(p.Status), p.Title, p.Body)
	if !ok {
		return errText("no such task %q", p.TaskID), nil
	}
	return jsonText(t), nil
}
