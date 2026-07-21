package control

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// identifyByHeader is a test stand-in for mesh transport identity: the caller's
// pubkey rides in a header. Real deployments resolve it from the WireGuard peer.
func identifyByHeader(r *http.Request) (string, string) {
	return r.Header.Get("X-Peer-Key"), r.Header.Get("X-Peer-FQDN")
}

// TestTenantIsolation proves multi-tenant isolation (F25): a policy written by
// tenant A is invisible to tenant B, and an unmapped identity is refused.
func TestTenantIsolation(t *testing.T) {
	// Two identities, mapped to two tenants; a third identity maps to nothing.
	resolve := func(pub, fqdn string) string {
		switch pub {
		case "keyA":
			return "acme"
		case "keyB":
			return "globex"
		}
		return ""
	}
	ts := NewFileTenantServer(t.TempDir(), identifyByHeader, resolve, nil)
	srv := httptest.NewServer(ts.Handler())
	defer srv.Close()

	policy := "default_allow: false\nrules: []\n"

	put := func(key, name, body string) int {
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/policy/"+name, strings.NewReader(body))
		req.Header.Set("X-Peer-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	get := func(key, name string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/policy/"+name, nil)
		req.Header.Set("X-Peer-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// Tenant A stores a policy named "prod".
	if code := put("keyA", "prod", policy); code != http.StatusOK {
		t.Fatalf("tenant A put: want 200, got %d", code)
	}
	// Tenant A can read it back.
	if code, body := get("keyA", "prod"); code != http.StatusOK || !strings.Contains(body, "default_allow") {
		t.Fatalf("tenant A get: code=%d body=%q", code, body)
	}
	// Tenant B must NOT see tenant A's "prod" policy — isolated store.
	if code, _ := get("keyB", "prod"); code != http.StatusNotFound {
		t.Fatalf("tenant B must not read tenant A's policy: want 404, got %d", code)
	}
	// Tenant B may use the same name for its own, independent policy.
	if code := put("keyB", "prod", policy); code != http.StatusOK {
		t.Fatalf("tenant B put its own prod: want 200, got %d", code)
	}
	// An identity mapped to no tenant is refused entirely.
	if code, _ := get("stranger", "prod"); code != http.StatusForbidden {
		t.Fatalf("unmapped identity: want 403, got %d", code)
	}
	if code := put("stranger", "prod", policy); code != http.StatusForbidden {
		t.Fatalf("unmapped identity put: want 403, got %d", code)
	}
}

// TestTenantRegistryIsolation proves the service registry is tenant-scoped too.
func TestTenantRegistryIsolation(t *testing.T) {
	resolve := func(pub, fqdn string) string {
		if pub == "keyA" {
			return "acme"
		}
		if pub == "keyB" {
			return "globex"
		}
		return ""
	}
	ts := NewFileTenantServer(t.TempDir(), identifyByHeader, resolve, nil)
	srv := httptest.NewServer(ts.Handler())
	defer srv.Close()

	reg := func(key string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/registry", nil)
		req.Header.Set("X-Peer-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	// Register a backend in tenant A.
	body := `{"name":"fs","addr":"10.0.0.1:9101"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/registry", strings.NewReader(body))
	req.Header.Set("X-Peer-Key", "keyA")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if _, a := reg("keyA"); !strings.Contains(a, "10.0.0.1:9101") {
		t.Fatalf("tenant A should see its registration: %s", a)
	}
	if _, b := reg("keyB"); strings.Contains(b, "10.0.0.1:9101") {
		t.Fatalf("tenant B must not see tenant A's registry: %s", b)
	}
}
