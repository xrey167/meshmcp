package mcp

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// TestSubscriptionsListen drives the draft subscriptions/listen pattern
// end-to-end: open a stream, receive the acknowledgment, receive only the
// requested notification types (each tagged with the subscription id), and end
// the stream with a cancel that yields the terminal `complete` result.
func TestSubscriptionsListen(t *testing.T) {
	s := New("test", "1.0")
	h := startHarness(t, s)

	h.send(t, `{"jsonrpc":"2.0","id":7,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true,"resourceSubscriptions":["file:///a"]}}}`)

	// The acknowledgment is first and carries the subscription id in _meta.
	ack := h.waitNotification(t, "notifications/subscriptions/acknowledged")
	var ackP struct {
		Meta struct {
			ID string `json:"io.modelcontextprotocol/subscriptionId"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal(ack.Params, &ackP); err != nil {
		t.Fatal(err)
	}
	if ackP.Meta.ID != "7" {
		t.Fatalf("ack subscription id = %q, want 7", ackP.Meta.ID)
	}

	// A requested list-changed notification is delivered, tagged with the id.
	s.NotifyToolsChanged()
	tn := h.waitNotification(t, "notifications/tools/list_changed")
	if !hasSubID(tn.Params, "7") {
		t.Fatalf("tools/list_changed missing subscription id: %s", tn.Params)
	}

	// A tracked resource update is delivered with its uri.
	s.NotifyResourceUpdated("file:///a")
	ru := h.waitNotification(t, "notifications/resources/updated")
	var ruP struct {
		URI string `json:"uri"`
	}
	json.Unmarshal(ru.Params, &ruP)
	if ruP.URI != "file:///a" {
		t.Fatalf("resource update uri = %q", ruP.URI)
	}

	// An UNREQUESTED type is never delivered (server MUST NOT send it).
	s.NotifyPromptsChanged()
	s.NotifyResourceUpdated("file:///other") // untracked uri
	select {
	case m, ok := <-h.msgs:
		if ok {
			t.Fatalf("unexpected notification for unrequested type: %s %s", m.Method, m.Params)
		}
	case <-time.After(200 * time.Millisecond):
	}

	// Cancelling the listen request ends the stream with `complete`.
	h.send(t, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}`)
	comp := h.waitResponse(t, 7)
	var res struct {
		ResultType string `json:"resultType"`
	}
	if err := json.Unmarshal(comp.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.ResultType != "complete" {
		t.Fatalf("terminal result = %q, want complete", res.ResultType)
	}
}

// TestSubscriptionsCloseOnDisconnect verifies open streams are terminated with
// `complete` when the connection ends.
func TestSubscriptionsCloseOnDisconnect(t *testing.T) {
	s := New("test", "1.0")
	h := startHarness(t, s)
	h.send(t, `{"jsonrpc":"2.0","id":3,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}`)
	h.waitNotification(t, "notifications/subscriptions/acknowledged")

	// Client disconnects: closing the input ends Serve, which must complete the
	// open subscription.
	h.in.Close()
	comp := h.waitResponse(t, 3)
	var res struct {
		ResultType string `json:"resultType"`
	}
	json.Unmarshal(comp.Result, &res)
	if res.ResultType != "complete" {
		t.Fatalf("disconnect terminal result = %q, want complete", res.ResultType)
	}
}

// TestSubscriptionsCap verifies the per-connection subscription count is
// bounded: past the cap, further listen requests are rejected (not registered),
// so a client cannot exhaust server memory.
func TestSubscriptionsCap(t *testing.T) {
	s := New("test", "1.0")
	h := startHarness(t, s)
	total := maxSubscriptions + 1
	for i := 1; i <= total; i++ {
		h.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}`, i))
	}
	acks, errs := 0, 0
	deadline := time.After(5 * time.Second)
	for acks+errs < total {
		select {
		case m, ok := <-h.msgs:
			if !ok {
				t.Fatalf("stream closed: acks=%d errs=%d", acks, errs)
			}
			switch {
			case len(m.ID) == 0 && m.Method == methodSubscriptionsAck:
				acks++
			case len(m.ID) > 0 && len(m.Error) > 0:
				errs++
			}
		case <-deadline:
			t.Fatalf("timeout: acks=%d errs=%d", acks, errs)
		}
	}
	if acks != maxSubscriptions || errs != 1 {
		t.Fatalf("acks=%d errs=%d, want %d/1", acks, errs, maxSubscriptions)
	}
}

// TestSubscriptionsRejectsAbuse verifies duplicate ids and oversized resource
// subscription lists are refused.
func TestSubscriptionsRejectsAbuse(t *testing.T) {
	s := New("test", "1.0")
	h := startHarness(t, s)

	h.send(t, `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}`)
	h.waitNotification(t, methodSubscriptionsAck)
	// Re-using id 1 is rejected.
	h.send(t, `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}`)
	if dup := h.waitResponse(t, 1); len(dup.Error) == 0 {
		t.Fatal("duplicate subscription id should be rejected")
	}

	// An oversized resourceSubscriptions list is rejected.
	big := make([]string, maxResourceSubsPerListen+1)
	for i := range big {
		big[i] = fmt.Sprintf("file:///%d", i)
	}
	params, _ := json.Marshal(map[string]any{"notifications": map[string]any{"resourceSubscriptions": big}})
	h.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"subscriptions/listen","params":%s}`, params))
	if over := h.waitResponse(t, 2); len(over.Error) == 0 {
		t.Fatal("oversized resourceSubscriptions should be rejected")
	}
}

func hasSubID(params json.RawMessage, id string) bool {
	var p struct {
		Meta struct {
			ID string `json:"io.modelcontextprotocol/subscriptionId"`
		} `json:"_meta"`
	}
	json.Unmarshal(params, &p)
	return p.Meta.ID == id
}
