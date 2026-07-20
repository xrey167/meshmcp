package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/registry"
)

// do issues a request against ts and returns the status code and body.
func do(t *testing.T, ts *httptest.Server, method, path, body string) int {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestControlOrdinaryPeerCannotMutate is the core Phase-2 regression: an
// ordinary mesh peer (identified, but holding no roles) cannot mint setup keys,
// mutate the registry, replace policies, or list administrative state. Every
// privileged route must return 403 and leave state untouched.
func TestControlOrdinaryPeerCannotMutate(t *testing.T) {
	// caller "PEER-KEY" is a real mesh peer but has NO grants.
	s, aud, ts := newTestServerWith(t, "PEER-KEY", map[string][]Role{"ADMIN-KEY": {RoleAdmin}})
	defer ts.Close()

	cases := []struct {
		name, method, path, body string
	}{
		{"mint setup key", http.MethodPost, "/v1/enroll", `{"node":"attacker"}`},
		{"register service", http.MethodPost, "/v1/registry", `{"name":"evil","addr":"100.64.0.9:1"}`},
		{"deregister service", http.MethodDelete, "/v1/registry", `{"name":"fs","addr":"100.64.0.2:9101"}`},
		{"list registry", http.MethodGet, "/v1/registry", ""},
		{"replace policy", http.MethodPut, "/v1/policy/team", "default_allow: true"},
		{"read policy", http.MethodGet, "/v1/policy/team", ""},
		{"list policies", http.MethodGet, "/v1/policies", ""},
	}
	for _, c := range cases {
		if code := do(t, ts, c.method, c.path, c.body); code != http.StatusForbidden {
			t.Fatalf("%s: ordinary peer should get 403, got %d", c.name, code)
		}
	}

	// State must be untouched: nothing registered, no policy stored.
	if m, _ := s.Reg.Lookup(); len(m) != 0 {
		t.Fatalf("registry should be empty after denied writes, got %+v", m)
	}
	if names, _ := s.Policies.List(); len(names) != 0 {
		t.Fatalf("no policy should be stored after a denied PUT, got %v", names)
	}

	// Every denial must be audited with the actor key.
	var denials int
	for _, r := range aud.snapshot() {
		if r.Result == "deny" {
			denials++
			if r.Actor != "PEER-KEY" {
				t.Fatalf("deny audit should record the actor key, got %q", r.Actor)
			}
			if r.Corr == "" {
				t.Fatalf("deny audit should carry a correlation id")
			}
		}
	}
	if denials != len(cases) {
		t.Fatalf("expected %d deny audits, got %d", len(cases), denials)
	}
}

// TestControlFailsClosedWithoutAuth: a server with no authorizer/identity
// resolver denies every privileged route (WireGuard membership is not
// authorization).
func TestControlFailsClosedWithoutAuth(t *testing.T) {
	reg, _ := registry.NewFileRegistry(t.TempDir())
	ps, _ := NewFilePolicyStore(t.TempDir())
	s := &Server{Reg: reg, Policies: ps, Enroll: StaticEnroll("m", "k", "", "c")} // no Auth, no Identify
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	for _, p := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/enroll", `{"node":"x"}`},
		{http.MethodPost, "/v1/registry", `{"name":"n","addr":"a"}`},
		{http.MethodGet, "/v1/registry", ""},
		{http.MethodPut, "/v1/policy/p", "default_allow: false"},
		{http.MethodGet, "/v1/policies", ""},
	} {
		if code := do(t, ts, p.method, p.path, p.body); code != http.StatusForbidden {
			t.Fatalf("%s %s with no auth configured should be 403, got %d", p.method, p.path, code)
		}
	}
	// healthz stays open.
	if code := do(t, ts, http.MethodGet, "/healthz", ""); code != http.StatusOK {
		t.Fatalf("healthz should be open, got %d", code)
	}
}

// TestControlRoleGranularity: roles are distinct. A caller with only
// registry.write cannot read the registry, and vice versa.
func TestControlRoleGranularity(t *testing.T) {
	s, _, ts := newTestServerWith(t, "WRITER", map[string][]Role{"WRITER": {RoleRegistryWrite}})
	defer ts.Close()
	_ = s
	// Writer can register...
	if code := do(t, ts, http.MethodPost, "/v1/registry", `{"name":"fs","addr":"100.64.0.2:9101"}`); code != http.StatusOK {
		t.Fatalf("registry.write should allow POST, got %d", code)
	}
	// ...but cannot read (needs registry.read).
	if code := do(t, ts, http.MethodGet, "/v1/registry", ""); code != http.StatusForbidden {
		t.Fatalf("registry.write must NOT grant read, got %d", code)
	}
}

// TestControlIgnoresBodyIdentity: identity comes from the transport, not the
// body. The same registry write is denied for an unprivileged caller even
// though nothing in the body could elevate them — proving the body is not an
// identity source.
func TestControlIgnoresBodyIdentity(t *testing.T) {
	_, _, ts := newTestServerWith(t, "NOBODY", map[string][]Role{"ADMIN-KEY": {RoleAdmin}})
	defer ts.Close()
	// A body that (uselessly) tries to name an admin actor is still denied, and
	// because unknown fields are rejected it never even elevates.
	if code := do(t, ts, http.MethodPost, "/v1/registry", `{"name":"n","addr":"a","actor":"ADMIN-KEY"}`); code == http.StatusOK {
		t.Fatalf("caller-supplied identity in the body must not authorize; got 200")
	}
}

// TestControlUnattributableCallerDenied: a caller the transport cannot map to a
// mesh peer is denied even if some key is granted admin.
func TestControlUnattributableCallerDenied(t *testing.T) {
	_, _, ts := newTestServerWith(t, "", map[string][]Role{"ADMIN-KEY": {RoleAdmin}}) // blank caller => unattributable
	defer ts.Close()
	if code := do(t, ts, http.MethodPost, "/v1/enroll", `{"node":"x"}`); code != http.StatusForbidden {
		t.Fatalf("unattributable caller should be 403, got %d", code)
	}
}

func TestValidPolicyName(t *testing.T) {
	bad := []string{"", ".", "..", "../etc", "a/b", "a\\b", ".hidden", "a..b", "name\x00", "team!", strings.Repeat("x", 200)}
	for _, n := range bad {
		if err := validPolicyName(n); err == nil {
			t.Fatalf("policy name %q should be rejected", n)
		}
	}
	for _, n := range []string{"team", "prod_v2", "a-b.c", "Team1"} {
		if err := validPolicyName(n); err != nil {
			t.Fatalf("policy name %q should be allowed: %v", n, err)
		}
	}
}

// TestLoadAuthorizerStrict: the ACL loader rejects unknown fields and unknown
// roles so a typo fails startup instead of silently mis-granting.
func TestLoadAuthorizerStrict(t *testing.T) {
	if _, err := LoadAuthorizer([]byte("grants:\n  KEY: [control.admin]\n")); err != nil {
		t.Fatalf("valid ACL should load: %v", err)
	}
	if _, err := LoadAuthorizer([]byte("grants:\n  KEY: [not.a.role]\n")); err == nil {
		t.Fatal("unknown role should fail to load")
	}
	if _, err := LoadAuthorizer([]byte("grantz:\n  KEY: [control.admin]\n")); err == nil {
		t.Fatal("unknown top-level field should fail strict decode")
	}
	if _, err := LoadAuthorizer([]byte("grants: {}\n")); err == nil {
		t.Fatal("empty grants should fail (default-deny with no admins is a config error)")
	}
}
