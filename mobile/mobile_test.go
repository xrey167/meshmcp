package mobile

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestJoinRequiresSetupKey exercises input validation without a network.
func TestJoinRequiresSetupKey(t *testing.T) {
	if _, err := Join("", "", "", ""); err == nil {
		t.Fatal("expected an error joining without a setup key")
	}
}

// TestApprovalsClient drives the Approvals methods against a stub server,
// proving the request shapes without a mesh (the transport is swapped).
func TestApprovalsClient(t *testing.T) {
	var gotApprove string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/pending":
			_, _ = w.Write([]byte(`{"pending":[]}`))
		case "/v1/approve":
			b := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(b)
			gotApprove = string(b)
			_, _ = w.Write([]byte(`{"status":"approved"}`))
		case "/v1/deny":
			_, _ = w.Write([]byte(`{"status":"denied"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := &Approvals{hc: srv.Client(), base: srv.URL}

	got, err := a.Pending()
	if err != nil || !strings.Contains(got, "pending") {
		t.Fatalf("pending: %v %q", err, got)
	}
	if err := a.Approve("billing.mesh", "transfer_funds"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !strings.Contains(gotApprove, "transfer_funds") {
		t.Fatalf("approve body missing tool: %q", gotApprove)
	}
	if err := a.Deny("billing.mesh", "transfer_funds"); err != nil {
		t.Fatalf("deny: %v", err)
	}
}

// TestReadBodyError maps a non-2xx upstream to an error.
func TestReadBodyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	a := &Approvals{hc: srv.Client(), base: srv.URL}
	if err := a.Approve("p", "t"); err == nil {
		t.Fatal("expected error on 403")
	}
}
