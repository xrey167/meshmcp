package control

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"meshmcp/policy"
)

func TestNetBirdIssuerMintsKeyAndAudits(t *testing.T) {
	var gotAuth, gotBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/setup-keys" || r.Method != http.MethodPost {
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"id": "key-abc", "key": "AAAA-BBBB-CCCC-DDDD", "name": "meshmcp-enroll-node1", "expires": "2026-07-16T10:00:00Z",
		})
	}))
	defer ts.Close()

	var auditBuf bytes.Buffer
	audit := policy.NewAuditLog(&auditBuf, func() string { return "T" })
	iss := &NetBirdIssuer{
		APIURL:        ts.URL,
		ManagementURL: "https://mgmt.example",
		Token:         "PAT-123",
		Groups:        []string{"agents"},
		Client:        ts.Client(),
		Audit:         audit,
	}

	resp, err := iss.Enroll(EnrollRequest{Node: "node1"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.SetupKey != "AAAA-BBBB-CCCC-DDDD" {
		t.Fatalf("expected minted key, got %q", resp.SetupKey)
	}
	if resp.ManagementURL != "https://mgmt.example" {
		t.Fatalf("management url wrong: %q", resp.ManagementURL)
	}
	if gotAuth != "Token PAT-123" {
		t.Fatalf("expected NetBird Token auth header, got %q", gotAuth)
	}
	// Request should ask for a one-off, ephemeral, single-use key in the group.
	for _, want := range []string{`"type":"one-off"`, `"ephemeral":true`, `"usage_limit":1`, `"agents"`} {
		if !strings.Contains(gotBody, want) {
			t.Fatalf("setup-key request missing %s: %s", want, gotBody)
		}
	}
	// The enrollment must be recorded in the tamper-evident audit trail.
	audit.Flush()
	as := auditBuf.String()
	if !strings.Contains(as, `"method":"enroll"`) || !strings.Contains(as, "key-abc") {
		t.Fatalf("enrollment not audited: %s", as)
	}
	if res, _ := policy.VerifyChain(strings.NewReader(as)); !res.OK {
		t.Fatalf("enrollment audit chain should verify: %+v", res)
	}
}

func TestNetBirdIssuerHandlesAPIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
	}))
	defer ts.Close()

	var auditBuf bytes.Buffer
	iss := &NetBirdIssuer{
		APIURL: ts.URL,
		Token:  "bad",
		Client: ts.Client(),
		Audit:  policy.NewAuditLog(&auditBuf, func() string { return "T" }),
	}
	if _, err := iss.Enroll(EnrollRequest{Node: "node2"}); err == nil {
		t.Fatal("expected an error on API 401")
	}
	// A denied enrollment is still audited.
	if !strings.Contains(auditBuf.String(), `"decision":"deny"`) {
		t.Fatalf("failed enrollment should be audited as deny: %s", auditBuf.String())
	}
}
