package orchestrator

import (
	"fmt"
	"sync"

	"github.com/xrey167/meshmcp/harness"
)

// taskStore is the in-process backing for the task_* tools. In production these
// are backed by the air task store so tasks survive handoff/resume; here they
// live for the server's lifetime. Safe for concurrent use.
type taskStore struct {
	mu    sync.Mutex
	seq   int
	tasks map[string]harness.Task
	order []string
}

func newTaskStore() *taskStore {
	return &taskStore{tasks: map[string]harness.Task{}}
}

func (s *taskStore) create(title, body, parent string) harness.Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	id := fmt.Sprintf("task-%d", s.seq)
	t := harness.Task{ID: id, Parent: parent, Title: title, Body: body, Status: harness.TaskOpen}
	s.tasks[id] = t
	s.order = append(s.order, id)
	return t
}

func (s *taskStore) get(id string) (harness.Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	return t, ok
}

func (s *taskStore) list(filter harness.TaskStatus) []harness.Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]harness.Task, 0, len(s.order))
	for _, id := range s.order {
		t := s.tasks[id]
		if filter != "" && t.Status != filter {
			continue
		}
		out = append(out, t)
	}
	return out
}

func (s *taskStore) update(id string, status harness.TaskStatus, title, body string) (harness.Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return harness.Task{}, false
	}
	if status != "" {
		t.Status = status
	}
	if title != "" {
		t.Title = title
	}
	if body != "" {
		t.Body = body
	}
	s.tasks[id] = t
	return t, true
}
