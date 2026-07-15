package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Task status values (MCP task lifecycle).
const (
	StatusWorking   = "working"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// task is one async tool invocation.
type task struct {
	id   string
	tool string

	mu     sync.Mutex
	status string
	result ToolResult
	errMsg string
	cancel context.CancelFunc
}

func (t *task) snapshot() (status, errMsg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status, t.errMsg
}

type taskManager struct {
	mu    sync.Mutex
	seq   int
	tasks map[string]*task
	order []string
}

func newTaskManager() *taskManager {
	return &taskManager{tasks: map[string]*task{}}
}

// start launches tool.Handler as a task: it registers the task, sends the
// working handle (as the reply to reqID) *before* spawning the handler — so
// the task's progress notifications can never precede its handle — then runs
// the handler in a goroutine that records the outcome and emits a
// notifications/tasks/status.
func (m *taskManager) start(sess *Session, reqID json.RawMessage, tool Tool, args json.RawMessage) {
	m.mu.Lock()
	m.seq++
	id := fmt.Sprintf("task-%d", m.seq)
	ctx, cancel := context.WithCancel(context.Background())
	t := &task{id: id, tool: tool.Name, status: StatusWorking, cancel: cancel}
	m.tasks[id] = t
	m.order = append(m.order, id)
	m.mu.Unlock()

	// Send the working handle first.
	_ = sess.conn.send(response{
		JSONRPC: "2.0",
		ID:      reqID,
		Result:  map[string]any{"task": map[string]any{"taskId": id, "status": StatusWorking}},
	})

	go func() {
		res, err := tool.Handler(WithSession(ctx, sess), args)
		t.mu.Lock()
		switch {
		case ctx.Err() != nil:
			t.status = StatusCancelled
		case err != nil:
			t.status = StatusFailed
			t.errMsg = err.Error()
		default:
			t.status = StatusCompleted
			t.result = res
		}
		status := t.status
		t.mu.Unlock()
		cancel() // release the context
		sess.Notify("notifications/tasks/status", map[string]any{"taskId": id, "status": status})
	}()
}

func (m *taskManager) get(id string) (*task, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	return t, ok
}

func (m *taskManager) list() []map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]map[string]any, 0, len(m.order))
	for _, id := range m.order {
		t := m.tasks[id]
		status, _ := t.snapshot()
		out = append(out, map[string]any{"taskId": id, "status": status})
	}
	return out
}
