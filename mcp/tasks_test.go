package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"
)

// msg is a decoded line from the server: a response (has ID) or a
// notification (has Method, no ID).
type msg struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
	Params json.RawMessage `json:"params"`
}

// serverHarness drives a Server over pipes and collects its output.
type serverHarness struct {
	in      *io.PipeWriter
	msgs    chan msg
	pending []msg // messages a wait passed over, kept for a later wait
}

func startHarness(t *testing.T, s *Server) *serverHarness {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() { _ = s.Serve(context.Background(), inR, outW); outW.Close() }()

	h := &serverHarness{in: inW, msgs: make(chan msg, 64)}
	go func() {
		dec := json.NewDecoder(outR)
		for {
			var m msg
			if err := dec.Decode(&m); err != nil {
				close(h.msgs)
				return
			}
			h.msgs <- m
		}
	}()
	return h
}

func (h *serverHarness) send(t *testing.T, s string) {
	t.Helper()
	if _, err := io.WriteString(h.in, s+"\n"); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// match returns the first message (from the buffer, then the live stream)
// satisfying pred, retaining every message it passes over so a later wait can
// still find it. A response and a notification can be written in either order
// (the server serializes writes but does not order them across goroutines), so
// a waiter must not discard the message another waiter is about to ask for.
func (h *serverHarness) match(t *testing.T, what string, pred func(msg) bool) msg {
	t.Helper()
	for i, m := range h.pending {
		if pred(m) {
			h.pending = append(h.pending[:i], h.pending[i+1:]...)
			return m
		}
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m, ok := <-h.msgs:
			if !ok {
				t.Fatalf("stream closed waiting for %s", what)
			}
			if pred(m) {
				return m
			}
			h.pending = append(h.pending, m) // keep it for a later wait
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// waitResponse returns the response whose id equals the given number.
func (h *serverHarness) waitResponse(t *testing.T, id int) msg {
	t.Helper()
	want := fmt.Sprintf("%d", id)
	return h.match(t, "response "+want, func(m msg) bool {
		return len(m.ID) > 0 && string(m.ID) == want
	})
}

// waitNotification returns the next notification with the given method.
func (h *serverHarness) waitNotification(t *testing.T, method string) msg {
	t.Helper()
	return h.match(t, "notification "+method, func(m msg) bool {
		return len(m.ID) == 0 && m.Method == method
	})
}

func taskServer() *Server {
	s := New("tasks", "1.0")
	s.AddTool(Tool{
		Name: "count",
		Handler: func(ctx context.Context, args json.RawMessage) (ToolResult, error) {
			var a struct {
				N int `json:"n"`
			}
			_ = json.Unmarshal(args, &a)
			sess := SessionFrom(ctx)
			for i := 1; i <= a.N; i++ {
				if ctx.Err() != nil {
					return ToolResult{}, ctx.Err()
				}
				sess.Progress("count", float64(i), float64(a.N), "")
			}
			return ToolResult{Content: []Content{Text(fmt.Sprintf("counted to %d", a.N))}}, nil
		},
	})
	s.AddTool(Tool{
		Name: "block",
		Handler: func(ctx context.Context, _ json.RawMessage) (ToolResult, error) {
			<-ctx.Done()
			return ToolResult{}, ctx.Err()
		},
	})
	// steerable blocks until a tasks/steer payload arrives (or cancel/timeout),
	// then returns it — so a test can prove mid-flight guidance is delivered.
	s.AddTool(Tool{
		Name: "steerable",
		Handler: func(ctx context.Context, _ json.RawMessage) (ToolResult, error) {
			select {
			case p := <-SteerChan(ctx):
				return ToolResult{Content: []Content{Text("steered: " + string(p))}}, nil
			case <-ctx.Done():
				return ToolResult{}, ctx.Err()
			case <-time.After(5 * time.Second):
				return ToolResult{}, fmt.Errorf("no steer arrived")
			}
		},
	})
	return s
}

func TestTaskRunsWithProgressAndResult(t *testing.T) {
	h := startHarness(t, taskServer())

	h.send(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"count","arguments":{"n":3},"task":true}}`)
	resp := h.waitResponse(t, 1)
	var handle struct {
		Task struct {
			TaskID string `json:"taskId"`
			Status string `json:"status"`
		} `json:"task"`
	}
	if err := json.Unmarshal(resp.Result, &handle); err != nil {
		t.Fatalf("bad task handle: %s", resp.Result)
	}
	if handle.Task.TaskID == "" || handle.Task.Status != StatusWorking {
		t.Fatalf("expected working task handle, got %s", resp.Result)
	}

	// Progress notifications and a terminal status notification arrive.
	h.waitNotification(t, "notifications/progress")
	st := h.waitNotification(t, "notifications/tasks/status")
	var stp struct {
		TaskID string `json:"taskId"`
		Status string `json:"status"`
	}
	_ = json.Unmarshal(st.Params, &stp)
	if stp.Status != StatusCompleted {
		t.Fatalf("expected completed status, got %s", st.Params)
	}

	// tasks/result returns the tool's output.
	h.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tasks/result","params":{"taskId":%q}}`, handle.Task.TaskID))
	res := h.waitResponse(t, 2)
	if res.Error != nil {
		t.Fatalf("tasks/result error: %s", res.Error)
	}
	var tr ToolResult
	_ = json.Unmarshal(res.Result, &tr)
	if len(tr.Content) == 0 || tr.Content[0].Text != "counted to 3" {
		t.Fatalf("bad task result: %s", res.Result)
	}
}

func TestTaskSteer(t *testing.T) {
	h := startHarness(t, taskServer())

	// Start a task that waits for mid-flight guidance.
	h.send(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"steerable","task":true}}`)
	resp := h.waitResponse(t, 1)
	var handle struct {
		Task struct {
			TaskID string `json:"taskId"`
		} `json:"task"`
	}
	_ = json.Unmarshal(resp.Result, &handle)
	id := handle.Task.TaskID
	if id == "" {
		t.Fatalf("no task id: %s", resp.Result)
	}

	// Steer it — governed exactly like tasks/cancel, since it's a real method.
	h.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tasks/steer","params":{"taskId":%q,"payload":{"focus":"api"}}}`, id))
	sres := h.waitResponse(t, 2)
	if sres.Error != nil {
		t.Fatalf("tasks/steer error: %s", sres.Error)
	}
	var sh struct {
		Steered bool   `json:"steered"`
		Status  string `json:"status"`
	}
	_ = json.Unmarshal(sres.Result, &sh)
	if !sh.Steered || sh.Status != StatusWorking {
		t.Fatalf("expected steered working handle, got %s", sres.Result)
	}

	// The handler received the guidance and completed with it.
	st := h.waitNotification(t, "notifications/tasks/status")
	var stp struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(st.Params, &stp)
	if stp.Status != StatusCompleted {
		t.Fatalf("expected completed after steer, got %s", st.Params)
	}
	h.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tasks/result","params":{"taskId":%q}}`, id))
	res := h.waitResponse(t, 3)
	var tr ToolResult
	_ = json.Unmarshal(res.Result, &tr)
	if len(tr.Content) == 0 || tr.Content[0].Text != `steered: {"focus":"api"}` {
		t.Fatalf("handler did not receive the steer payload: %s", res.Result)
	}

	// Steering an unknown task is an error, not a silent no-op.
	h.send(t, `{"jsonrpc":"2.0","id":4,"method":"tasks/steer","params":{"taskId":"task-999"}}`)
	un := h.waitResponse(t, 4)
	if un.Error == nil {
		t.Fatalf("expected error steering unknown task, got %s", un.Result)
	}
}

// TestTaskManagerBoundedEviction proves the retained-task map is bounded: at the
// cap the oldest FINISHED task is reclaimed, and when every retained task is
// still in flight the manager reports it cannot reclaim (so start fails closed
// rather than growing the map without bound).
func TestTaskManagerBoundedEviction(t *testing.T) {
	// A manager full of terminal tasks reclaims the oldest on demand.
	full := newTaskManager()
	for i := 0; i < maxTasks; i++ {
		id := fmt.Sprintf("task-%d", i)
		full.tasks[id] = &task{id: id, status: StatusCompleted}
		full.order = append(full.order, id)
	}
	if !full.evictOldestTerminalLocked() {
		t.Fatal("a manager full of finished tasks must be able to reclaim one")
	}
	if len(full.tasks) != maxTasks-1 || len(full.order) != maxTasks-1 {
		t.Fatalf("eviction did not shrink: tasks=%d order=%d", len(full.tasks), len(full.order))
	}
	if _, ok := full.tasks["task-0"]; ok {
		t.Fatal("eviction must reclaim the OLDEST task first")
	}

	// A manager whose every retained task is still working cannot reclaim any —
	// this is the signal start() uses to fail closed at the cap.
	busy := newTaskManager()
	for i := 0; i < maxTasks; i++ {
		id := fmt.Sprintf("w-%d", i)
		busy.tasks[id] = &task{id: id, status: StatusWorking}
		busy.order = append(busy.order, id)
	}
	if busy.evictOldestTerminalLocked() {
		t.Fatal("a working task must never be evicted")
	}
}

func TestTaskCancellation(t *testing.T) {
	h := startHarness(t, taskServer())

	h.send(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"block","task":true}}`)
	resp := h.waitResponse(t, 1)
	var handle struct {
		Task struct {
			TaskID string `json:"taskId"`
		} `json:"task"`
	}
	_ = json.Unmarshal(resp.Result, &handle)
	id := handle.Task.TaskID
	if id == "" {
		t.Fatalf("no task id: %s", resp.Result)
	}

	// Cancel via the standard cancelled notification (maps to the task).
	h.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"taskId":%q}}`, id))
	st := h.waitNotification(t, "notifications/tasks/status")
	var stp struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(st.Params, &stp)
	if stp.Status != StatusCancelled {
		t.Fatalf("expected cancelled, got %s", st.Params)
	}

	h.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"taskId":%q}}`, id))
	got := h.waitResponse(t, 2)
	if got.Error != nil {
		t.Fatalf("tasks/get error: %s", got.Error)
	}
	var gs struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(got.Result, &gs)
	if gs.Status != StatusCancelled {
		t.Fatalf("expected cancelled status, got %s", got.Result)
	}
}
