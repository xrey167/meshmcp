package main

import (
	"encoding/json"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSchedulerDueOneShotAndRecurring(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sched.jsonl")

	var nowUnix atomic.Int64
	nowUnix.Store(1000)
	clock := func() time.Time { return time.Unix(nowUnix.Load(), 0) }

	st, err := openScheduleStore(path, clock)
	if err != nil {
		t.Fatal(err)
	}

	// A one-shot at t=1000 and a recurring every 60s starting at t=1000.
	one, _ := st.schedule("deploy", json.RawMessage(`{}`), 1000, 0, "alice")
	_, _ = st.schedule("healthcheck", nil, 1000, 60, "alice")

	// At t=1000 both are due.
	due, _ := st.due()
	if len(due) != 2 {
		t.Fatalf("expected 2 due at t=1000, got %d", len(due))
	}

	// At t=1001 nothing is due (one-shot done, recurring advanced to 1060).
	nowUnix.Store(1001)
	if d, _ := st.due(); len(d) != 0 {
		t.Fatalf("expected 0 due at t=1001, got %d", len(d))
	}

	// At t=1060 the recurring job fires again; the one-shot stays done.
	nowUnix.Store(1060)
	d, _ := st.due()
	if len(d) != 1 || d[0].Tool != "healthcheck" {
		t.Fatalf("expected the recurring job at t=1060, got %+v", d)
	}

	// Cancel + persistence: cancelling the one-shot leaves one job; reload sees it.
	if ok, _ := st.cancel(one.ID); !ok {
		t.Fatal("cancel should report true for an existing job")
	}
	st2, err := openScheduleStore(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	if len(st2.list()) != 1 {
		t.Fatalf("after cancel+reload expected 1 job, got %d", len(st2.list()))
	}
}
