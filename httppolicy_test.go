package main

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

func newTestEnforcer(pol *policy.Policy) *httpEnforcer {
	audit := policy.NewAuditLog(io.Discard, func() string { return "" })
	return &httpEnforcer{eng: policy.NewEngine(pol, nil, nil), audit: audit, backend: "b"}
}

func TestHTTPEnforcerDeniesAndAllows(t *testing.T) {
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"read_*"}, Allow: true},
	}}
	e := newTestEnforcer(pol)

	// Denied tool (no matching allow rule; default deny).
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_all"}}`))
	ok, _, denial := e.decide("alice", "k", r)
	if ok || !strings.Contains(string(denial), "blocked") {
		t.Fatalf("expected deny, got ok=%v denial=%s", ok, denial)
	}

	// Allowed tool; body must be restored for the proxy.
	r = httptest.NewRequest("POST", "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file"}}`))
	ok, _, _ = e.decide("alice", "k", r)
	if !ok {
		t.Fatal("expected allow for read_file")
	}
	got, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(got), "read_file") {
		t.Fatalf("body not restored for proxy: %s", got)
	}
}

func TestHTTPEnforcerRefusesBatchAndPassesOtherMethods(t *testing.T) {
	e := newTestEnforcer(&policy.Policy{DefaultAllow: false})

	// Batch is refused.
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`[{"jsonrpc":"2.0"}]`))
	if ok, _, denial := e.decide("a", "k", r); ok || !bytes.Contains(denial, []byte("batches")) {
		t.Fatalf("batch should be refused, got ok=%v", ok)
	}

	// A non-tools/call method passes through even under deny-by-default.
	r = httptest.NewRequest("POST", "/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if ok, _, _ := e.decide("a", "k", r); !ok {
		t.Fatal("tools/list should pass through (ungoverned method)")
	}
}
