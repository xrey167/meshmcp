package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"meshmcp/policy"
)

// TestApprovalsFlow drives the full approver API: a pending request appears,
// an identified approver approves it (which writes a grant and clears the
// pending), and a second request is denied (cleared, no grant). This is the
// server side of "approve from your phone".
func TestApprovalsFlow(t *testing.T) {
	dir := t.TempDir()
	ps := &policy.FilePending{Dir: dir}
	// Two held requests, as the filter would have recorded them.
	_ = ps.Record(policy.Pending{Peer: "billing.mesh", Backend: "pay", Tool: "transfer_funds", RPCID: "1"})
	_ = ps.Record(policy.Pending{Peer: "bot.mesh", Backend: "pay", Tool: "wire", RPCID: "2"})

	fixedNow := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	h := approvalsHandler(ps, func(*http.Request) string { return "alice-phone.netbird.cloud" }, func() time.Time { return fixedNow })
	ts := httptest.NewServer(h)
	defer ts.Close()

	// 1) list — both pending, with the approver identity echoed.
	resp, _ := http.Get(ts.URL + "/v1/pending")
	var listed struct {
		Pending []policy.Pending `json:"pending"`
		You     string           `json:"you"`
	}
	json.NewDecoder(resp.Body).Decode(&listed)
	if len(listed.Pending) != 2 {
		t.Fatalf("expected 2 pending, got %d", len(listed.Pending))
	}
	if listed.You != "alice-phone.netbird.cloud" {
		t.Fatalf("approver identity not echoed: %q", listed.You)
	}

	// 2) approve transfer_funds → a grant is written, pending cleared.
	post(t, ts.URL+"/v1/approve", `{"peer":"billing.mesh","tool":"transfer_funds"}`)
	cos := &policy.FileCosign{Dir: dir}
	if !cos.Approved(policy.CosignKey("billing.mesh", "transfer_funds")) {
		t.Fatalf("approve should have written a co-sign grant")
	}

	// 3) deny wire → cleared, but NO grant written.
	post(t, ts.URL+"/v1/deny", `{"peer":"bot.mesh","tool":"wire"}`)
	if cos.Approved(policy.CosignKey("bot.mesh", "wire")) {
		t.Fatalf("deny must NOT write a grant")
	}

	// 4) list — both resolved now.
	resp2, _ := http.Get(ts.URL + "/v1/pending")
	var after struct {
		Pending []policy.Pending `json:"pending"`
	}
	json.NewDecoder(resp2.Body).Decode(&after)
	if len(after.Pending) != 0 {
		t.Fatalf("both requests should be resolved, got %+v", after.Pending)
	}
}

func TestApprovalsServesMobileUI(t *testing.T) {
	ps := &policy.FilePending{Dir: t.TempDir()}
	h := approvalsHandler(ps, func(*http.Request) string { return "x" }, time.Now)
	ts := httptest.NewServer(h)
	defer ts.Close()
	resp, _ := http.Get(ts.URL + "/")
	b := make([]byte, 4096)
	n, _ := resp.Body.Read(b)
	body := string(b[:n])
	if !strings.Contains(body, "width=device-width") || !strings.Contains(body, "Pending approvals") {
		t.Fatalf("expected a phone-first approver page")
	}
}

// TestApproverNoInjectableHandlers guards against the XSS class where an
// attacker-controlled tool/peer name is concatenated into an inline handler.
// The approver renders all dynamic values via textContent + addEventListener,
// so the page must contain no inline onclick= and must use addEventListener.
func TestApproverNoInjectableHandlers(t *testing.T) {
	if strings.Contains(approvalsHTML, "onclick=") {
		t.Fatalf("approver must not use inline onclick handlers (XSS via interpolated tool/peer names)")
	}
	if !strings.Contains(approvalsHTML, "addEventListener") {
		t.Fatalf("approver should attach handlers via addEventListener")
	}
	if !strings.Contains(approvalsHTML, "textContent") {
		t.Fatalf("approver should render dynamic values via textContent")
	}
}

func post(t *testing.T, url, body string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("POST %s → %d", url, resp.StatusCode)
	}
}
