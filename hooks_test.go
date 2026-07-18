package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"meshmcp/policy"
)

// TestGatewayHooksWebhook verifies the hook sink POSTs selected decisions to a
// webhook, filters out unselected outcomes, and carries the right metadata.
func TestGatewayHooksWebhook(t *testing.T) {
	got := make(chan []byte, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("X-Meshmcp-Topic") == "" {
			t.Errorf("missing topic header")
		}
		got <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h, err := newGatewayHooks(&HooksConfig{
		Events:  []string{"deny"},
		Webhook: &HookWebhookConfig{URL: srv.URL},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	h.Emit(policy.AuditRecord{Decision: "deny", Backend: "kg", Tool: "delete_all", Reason: "blocked", Rule: 2, Seq: 7})
	h.Emit(policy.AuditRecord{Decision: "allow", Tool: "read_x"}) // filtered out

	select {
	case body := <-got:
		var p hookPayload
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		if p.Event != "deny" || p.Tool != "delete_all" || p.AuditSeq != 7 || p.Rule != 2 {
			t.Fatalf("unexpected webhook payload: %+v", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was not called for the deny")
	}
	// The filtered allow must not have been delivered.
	select {
	case <-got:
		t.Fatal("allow decision should have been filtered out")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestGatewayHooksNonBlocking verifies Emit never blocks the caller: with a
// stalled sink and a tiny queue, excess events are dropped (counted) rather
// than blocking the enforcement path.
func TestGatewayHooksNonBlocking(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // stall the worker on the first POST
	}))
	defer srv.Close()

	h, err := newGatewayHooks(&HooksConfig{
		Events:    []string{"deny"},
		QueueSize: 2,
		Webhook:   &HookWebhookConfig{URL: srv.URL, TimeoutSeconds: 30},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			h.Emit(policy.AuditRecord{Decision: "deny", Seq: i})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked the caller — hooks must never block enforcement")
	}
	if h.Dropped() == 0 {
		t.Fatal("expected dropped events with a stalled sink and tiny queue")
	}
	close(block)
	h.Close()
}
