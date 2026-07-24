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
	steer  chan json.RawMessage // buffered; mid-flight guidance for a cooperative handler
}

func (t *task) snapshot() (status, errMsg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status, t.errMsg
}

// isTerminal reports whether the task has finished (completed/failed/cancelled)
// and so is eligible for eviction when the retained-task cap is hit.
func (t *task) isTerminal() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status != StatusWorking
}

// maxTasks bounds the retained task records per server. Task records are
// client-driven allocations (each tools/call with task:true adds one) and were
// previously never reaped, so a peer could grow the map without bound until the
// backend OOMs. This mirrors the bounds every other client-controlled
// allocation carries (subscriptions maxSubscriptions, idempotency memClaimCap).
// At the cap the manager first evicts the oldest FINISHED task; if none can be
// reclaimed (all in flight) it fails closed and refuses the new task.
const maxTasks = 4096

// steerBuffer bounds a task's pending steer payloads. A non-blocking send drops
// (and taskManager.steer reports "busy") once this many are unconsumed, so a
// steer call can never block on a handler that isn't reading.
const steerBuffer = 8

type steerKey struct{}

func withSteer(ctx context.Context, ch <-chan json.RawMessage) context.Context {
	return context.WithValue(ctx, steerKey{}, ch)
}

// SteerChan returns the channel of steer payloads delivered to the current task
// via tasks/steer, or nil for a synchronous (non-task) call. A cooperative
// handler selects on it to receive mid-flight guidance; a receive on the nil
// channel blocks forever, so a handler that never expects a steer is unaffected.
func SteerChan(ctx context.Context) <-chan json.RawMessage {
	ch, _ := ctx.Value(steerKey{}).(<-chan json.RawMessage)
	return ch
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
func (m *taskManager) start(sess *Session, reqID json.RawMessage, toolName string, handler ToolHandler, meta, args json.RawMessage) bool {
	m.mu.Lock()
	if len(m.tasks) >= maxTasks && !m.evictOldestTerminalLocked() {
		// At the cap with every retained task still in flight: refuse rather than
		// grow the map without bound (fail closed).
		m.mu.Unlock()
		return false
	}
	m.seq++
	id := fmt.Sprintf("task-%d", m.seq)
	ctx, cancel := context.WithCancel(context.Background())
	steer := make(chan json.RawMessage, steerBuffer)
	t := &task{id: id, tool: toolName, status: StatusWorking, cancel: cancel, steer: steer}
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
		tctx := withSteer(withToolCall(WithSession(ctx, sess), ToolCallInfo{Tool: toolName, RequestID: reqID, Meta: meta}), steer)
		res, err := handler(tctx, args)
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
	return true
}

// evictOldestTerminalLocked removes the oldest FINISHED task from the manager,
// reclaiming its map and order-slice entry. It returns false when no retained
// task has finished (every one is still working), in which case the caller must
// fail closed rather than exceed the cap. Caller holds m.mu.
func (m *taskManager) evictOldestTerminalLocked() bool {
	for i, id := range m.order {
		t := m.tasks[id]
		if t == nil {
			continue // stale order entry; skip
		}
		if t.isTerminal() {
			delete(m.tasks, id)
			m.order = append(m.order[:i], m.order[i+1:]...)
			return true
		}
	}
	return false
}

func (m *taskManager) get(id string) (*task, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	return t, ok
}

// steerResult reports how a tasks/steer delivery landed.
type steerResult int

const (
	steerUnknown   steerResult = iota // no such task
	steerNotReady                     // task exists but is not in the working state
	steerBusy                         // working, but its steer buffer is full
	steerDelivered                    // guidance queued for the handler
)

// steer queues one guidance payload for a working task, non-blocking. Only a
// task that is still working and whose buffer has room accepts it, so a steer
// call never blocks on (or wakes) a handler that isn't reading.
func (m *taskManager) steer(id string, payload json.RawMessage) steerResult {
	t, ok := m.get(id)
	if !ok {
		return steerUnknown
	}
	t.mu.Lock()
	working, ch := t.status == StatusWorking, t.steer
	t.mu.Unlock()
	if !working || ch == nil {
		return steerNotReady
	}
	select {
	case ch <- payload:
		return steerDelivered
	default:
		return steerBusy
	}
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
