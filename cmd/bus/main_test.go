package main

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestBusPublishPollAndPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bus.jsonl")
	st, err := openBusStore(path)
	if err != nil {
		t.Fatal(err)
	}

	// Publish three events across two topics.
	if _, err := st.publish("orders", json.RawMessage(`{"id":1}`), "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.publish("orders", json.RawMessage(`{"id":2}`), "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.publish("alerts", json.RawMessage(`{"level":"warn"}`), "bob"); err != nil {
		t.Fatal(err)
	}

	// Poll orders from the beginning: two events, cursor at the second's seq.
	evs, cursor := st.poll("orders", 0, 100)
	if len(evs) != 2 || evs[0].Seq >= evs[1].Seq {
		t.Fatalf("poll orders: got %d events, order wrong: %+v", len(evs), evs)
	}
	if evs[0].Peer != "alice" {
		t.Fatalf("event not stamped with publisher identity: %+v", evs[0])
	}

	// Polling again from the cursor yields nothing.
	if more, _ := st.poll("orders", cursor, 100); len(more) != 0 {
		t.Fatalf("expected no new events after cursor, got %d", len(more))
	}

	// A fresh store reloads from disk (persistence + seq continuity).
	st2, err := openBusStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := st2.topics(); got["orders"] != 2 || got["alerts"] != 1 {
		t.Fatalf("reloaded topics wrong: %v", got)
	}
	e, err := st2.publish("orders", json.RawMessage(`{"id":3}`), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if e.Seq != 4 {
		t.Fatalf("global seq not continued after reload: got %d, want 4", e.Seq)
	}
}
