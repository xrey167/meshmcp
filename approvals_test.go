package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
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
	h := approvalsHandler(ps, func(*http.Request) string { return "alice-phone.netbird.cloud" }, nil, func() time.Time { return fixedNow })
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

func TestApprovalsOperatorAllowlist(t *testing.T) {
	dir := t.TempDir()
	ps := &policy.FilePending{Dir: dir}
	_ = ps.Record(policy.Pending{Peer: "bot.mesh", Backend: "pay", Tool: "wire", RPCID: "1"})

	// authorized=false → approve must be rejected and no grant written.
	h := approvalsHandler(ps, func(*http.Request) string { return "bot.mesh" },
		func(*http.Request) bool { return false }, time.Now)
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/approve", "application/json",
		strings.NewReader(`{"peer":"bot.mesh","tool":"wire"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized approver got %d, want 403", resp.StatusCode)
	}
	if (&policy.FileCosign{Dir: dir}).Approved(policy.CosignKey("bot.mesh", "wire")) {
		t.Fatal("a forbidden approve wrote a grant")
	}
}

func TestApprovalsServesMobileUI(t *testing.T) {
	ps := &policy.FilePending{Dir: t.TempDir()}
	h := approvalsHandler(ps, func(*http.Request) string { return "x" }, nil, time.Now)
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
// TestApproverExternalRequestFlow exercises the general HITL bridge: an external
// tool registers a request, polls pending, and the two decisions yield distinct
// approved / denied states — the substrate for the OpenAI Agents SDK
// ShellTool.on_approval bridge.
func TestApproverExternalRequestFlow(t *testing.T) {
	dir := t.TempDir()
	ps := &policy.FilePending{Dir: dir}
	h := approvalsHandler(ps, func(*http.Request) string { return "phone" }, nil, time.Now)
	ts := httptest.NewServer(h)
	defer ts.Close()

	status := func(peer, tool string) string {
		resp, _ := http.Get(ts.URL + "/v1/status?peer=" + peer + "&tool=" + tool)
		var s struct{ State string }
		json.NewDecoder(resp.Body).Decode(&s)
		return s.State
	}

	// Unknown before any request.
	if got := status("agentA", "shell"); got != "unknown" {
		t.Fatalf("pre-request state should be unknown, got %q", got)
	}
	// Register two requests.
	post(t, ts.URL+"/v1/request", `{"peer":"agentA","tool":"shell","backend":"agent-shell"}`)
	post(t, ts.URL+"/v1/request", `{"peer":"agentB","tool":"shell","backend":"agent-shell"}`)
	if got := status("agentA", "shell"); got != "pending" {
		t.Fatalf("after request, state should be pending, got %q", got)
	}
	// Approve A, deny B.
	post(t, ts.URL+"/v1/approve", `{"peer":"agentA","tool":"shell"}`)
	post(t, ts.URL+"/v1/deny", `{"peer":"agentB","tool":"shell"}`)
	if got := status("agentA", "shell"); got != "approved" {
		t.Fatalf("agentA should be approved, got %q", got)
	}
	if got := status("agentB", "shell"); got != "denied" {
		t.Fatalf("agentB should be denied, got %q", got)
	}
	// A grant was actually written for A (so a gateway would let the call through).
	if !(&policy.FileCosign{Dir: dir}).Approved(policy.CosignKey("agentA", "shell")) {
		t.Fatalf("approve should write a usable grant")
	}
	// A re-request clears the prior decision back to pending.
	post(t, ts.URL+"/v1/request", `{"peer":"agentA","tool":"shell"}`)
	if got := status("agentA", "shell"); got != "pending" {
		t.Fatalf("re-request should reset to pending, got %q", got)
	}
}

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

// TestApprovalsRequiresApproverACLInMeshMode is the Phase-2.2 regression: a
// mesh-served approver must not start without a mandatory approver ACL, because
// an empty ACL would let any mesh peer approve (self-authorize) its own held
// call. The guard returns before any mesh is started, so this is a fast,
// network-free check. (Local --addr dev mode is exempt but blocks on
// ListenAndServe, so it is not exercised here.)
func TestApprovalsRequiresApproverACLInMeshMode(t *testing.T) {
	err := cmdApprovals([]string{"--store", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "approver") {
		t.Fatalf("expected a fail-closed startup error requiring --approver, got %v", err)
	}
}
