package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/registry"
)

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	reg, err := registry.NewFileRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ps, err := NewFilePolicyStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Reg:      reg,
		Policies: ps,
		Enroll:   StaticEnroll("https://mgmt.example", "SETUP-KEY-123", "/shared/registry", "control-1"),
	}
	return s, httptest.NewServer(s.Handler())
}

func TestEnroll(t *testing.T) {
	_, ts := newTestServer(t)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/enroll", "application/json", strings.NewReader(`{"node":"laptop-7"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("enroll status %d", resp.StatusCode)
	}
	var er EnrollResponse
	if json.NewDecoder(resp.Body).Decode(&er) != nil {
		t.Fatal("decode")
	}
	if er.SetupKey != "SETUP-KEY-123" || er.ManagementURL != "https://mgmt.example" {
		t.Fatalf("unexpected enroll response: %+v", er)
	}

	// A node with no name is rejected.
	bad, _ := http.Post(ts.URL+"/v1/enroll", "application/json", strings.NewReader(`{}`))
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty node should be 400, got %d", bad.StatusCode)
	}
}

func TestRegistryRoundTrip(t *testing.T) {
	_, ts := newTestServer(t)
	defer ts.Close()

	// Register a service.
	post, err := http.Post(ts.URL+"/v1/registry", "application/json",
		strings.NewReader(`{"name":"fs","addr":"100.64.0.2:9101"}`))
	if err != nil {
		t.Fatal(err)
	}
	if post.StatusCode != 200 {
		t.Fatalf("register status %d", post.StatusCode)
	}

	// It should appear in the listing.
	get, _ := http.Get(ts.URL + "/v1/registry")
	var m map[string][]string
	json.NewDecoder(get.Body).Decode(&m)
	if len(m["fs"]) != 1 || m["fs"][0] != "100.64.0.2:9101" {
		t.Fatalf("registry lookup wrong: %+v", m)
	}
}

func TestPolicyDistribution(t *testing.T) {
	_, ts := newTestServer(t)
	defer ts.Close()

	good := `default_allow: false
rules:
  - peers: ["*"]
    tools: ["read_*"]
    allow: true`
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/policy/team", strings.NewReader(good))
	put, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if put.StatusCode != 200 {
		t.Fatalf("put policy status %d", put.StatusCode)
	}

	// Fetch it back.
	get, _ := http.Get(ts.URL + "/v1/policy/team")
	if get.StatusCode != 200 {
		t.Fatalf("get policy status %d", get.StatusCode)
	}
	body := make([]byte, 4096)
	n, _ := get.Body.Read(body)
	if !strings.Contains(string(body[:n]), "read_*") {
		t.Fatalf("policy body wrong: %s", body[:n])
	}

	// It should be listed.
	list, _ := http.Get(ts.URL + "/v1/policies")
	var names []string
	json.NewDecoder(list.Body).Decode(&names)
	found := false
	for _, nm := range names {
		if nm == "team" {
			found = true
		}
	}
	if !found {
		t.Fatalf("policy 'team' not listed: %v", names)
	}
}

func TestPolicyValidationRejectsGarbage(t *testing.T) {
	_, ts := newTestServer(t)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/policy/bad",
		strings.NewReader("this: : : not valid yaml : ["))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid policy should be rejected with 400, got %d", resp.StatusCode)
	}
}
