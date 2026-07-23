package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

// TestNetBirdIssuerDeregisterLooksUpAndDeletes proves the deregistration path:
// it resolves a peer id from the node name (GET /api/peers), issues a
// DELETE /api/peers/{id} with the PAT, and audits the removal in the
// tamper-evident chain.
func TestNetBirdIssuerDeregisterLooksUpAndDeletes(t *testing.T) {
	var listAuth, delAuth, delPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/peers":
			listAuth = r.Header.Get("Authorization")
			json.NewEncoder(w).Encode([]map[string]any{
				{"id": "peer-1", "name": "other", "hostname": "other.netbird.cloud"},
				{"id": "peer-2", "name": "gw", "hostname": "gw.netbird.cloud"},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/peers/"):
			delAuth = r.Header.Get("Authorization")
			delPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer ts.Close()

	var auditBuf bytes.Buffer
	audit := policy.NewAuditLog(&auditBuf, func() string { return "T" })
	iss := &NetBirdIssuer{APIURL: ts.URL, Token: "PAT-123", Client: ts.Client(), Audit: audit}

	if err := iss.Deregister("gw"); err != nil {
		t.Fatalf("deregister: %v", err)
	}
	if delPath != "/api/peers/peer-2" {
		t.Errorf("deleted the wrong peer: %q (want /api/peers/peer-2)", delPath)
	}
	if listAuth != "Token PAT-123" || delAuth != "Token PAT-123" {
		t.Errorf("PAT not sent: list=%q del=%q", listAuth, delAuth)
	}
	audit.Flush()
	as := auditBuf.String()
	if !strings.Contains(as, `"method":"deregister"`) || !strings.Contains(as, `"decision":"allow"`) {
		t.Fatalf("deregistration not audited as allow: %s", as)
	}
	if res, _ := policy.VerifyChain(strings.NewReader(as)); !res.OK {
		t.Fatalf("deregistration audit chain should verify: %+v", res)
	}
}

// TestNetBirdIssuerDeregisterUnknownPeer proves an unknown node name errors
// (and is audited as a deny) rather than deleting the wrong peer.
func TestNetBirdIssuerDeregisterUnknownPeer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			t.Errorf("must not DELETE when the peer name was not found")
		}
		json.NewEncoder(w).Encode([]map[string]any{{"id": "peer-1", "name": "someone-else"}})
	}))
	defer ts.Close()

	var auditBuf bytes.Buffer
	iss := &NetBirdIssuer{APIURL: ts.URL, Token: "PAT", Client: ts.Client(),
		Audit: policy.NewAuditLog(&auditBuf, func() string { return "T" })}

	if err := iss.Deregister("ghost"); err == nil {
		t.Fatal("expected an error for an unknown peer name")
	}
	if !strings.Contains(auditBuf.String(), `"decision":"deny"`) {
		t.Errorf("a failed deregistration should be audited as deny: %s", auditBuf.String())
	}
}

// TestNetBirdIssuerDeletePeerAPIError proves a management API failure surfaces
// as an error and a deny audit.
func TestNetBirdIssuerDeletePeerAPIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"forbidden"}`, http.StatusForbidden)
	}))
	defer ts.Close()

	var auditBuf bytes.Buffer
	iss := &NetBirdIssuer{APIURL: ts.URL, Token: "PAT", Client: ts.Client(),
		Audit: policy.NewAuditLog(&auditBuf, func() string { return "T" })}

	if err := iss.DeletePeer("peer-9"); err == nil {
		t.Fatal("expected an error on API 403")
	}
	if !strings.Contains(auditBuf.String(), `"decision":"deny"`) {
		t.Errorf("failed delete should be audited as deny: %s", auditBuf.String())
	}
}
