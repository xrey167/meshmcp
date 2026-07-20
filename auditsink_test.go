package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// TestWebhookSinkForwardsAndFilters proves the webhook AuditSink POSTs a deny
// record and, in deny-only mode, drops an allow record (S42 / F15).
func TestWebhookSinkForwardsAndFilters(t *testing.T) {
	got := make(chan policy.AuditRecord, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var rec policy.AuditRecord
		_ = json.Unmarshal(body, &rec)
		got <- rec
	}))
	defer srv.Close()

	sink := newWebhookSink(srv.URL, true /* denyOnly */)
	_ = sink.Append(policy.AuditRecord{Tool: "read", Decision: "allow"}) // filtered out
	_ = sink.Append(policy.AuditRecord{Tool: "deploy", Decision: "deny"})

	select {
	case rec := <-got:
		if rec.Decision != "deny" || rec.Tool != "deploy" {
			t.Fatalf("expected the deny record, got %+v", rec)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the webhook POST")
	}

	// The allow record must NOT arrive.
	select {
	case rec := <-got:
		t.Fatalf("allow record should have been filtered, got %+v", rec)
	case <-time.After(200 * time.Millisecond):
	}
}
