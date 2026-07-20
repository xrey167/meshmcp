package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/session"
)

// fakeAirControl is an in-memory airController for handler tests.
type fakeAirControl struct {
	list       []AirSession
	steers     []string // "backend/id/method" of accepted steers
	callers    []string // "pubKey/fqdn" seen by steer
	err        error    // returned by steer
	denyOnFqdn string   // if set, steer/sessions deny this caller fqdn on backend "fs"
}

func (f *fakeAirControl) sessions(pubKey, fqdn string) []AirSession {
	if f.denyOnFqdn != "" && fqdn == f.denyOnFqdn {
		var out []AirSession
		for _, s := range f.list {
			if s.Backend != "fs" {
				out = append(out, s)
			}
		}
		return out
	}
	return f.list
}
func (f *fakeAirControl) steer(pubKey, fqdn, backend, id, method string, _ any) error {
	if f.denyOnFqdn != "" && fqdn == f.denyOnFqdn && backend == "fs" {
		return errBackendForbidden
	}
	if f.err != nil {
		return f.err
	}
	f.callers = append(f.callers, pubKey+"/"+fqdn)
	f.steers = append(f.steers, backend+"/"+id+"/"+method)
	return nil
}

func newTestHandler(c airController, allowCaller bool) http.Handler {
	id := func(*http.Request) (string, string) { return "key1", "caller.mesh" }
	// The Air endpoint is default-deny: allowing the caller requires an explicit
	// ACL entry for its key; the deny case uses an ACL that does not list it.
	allow := newACL([]string{"pubkey:someone-else"})
	if allowCaller {
		allow = newACL([]string{"pubkey:key1"})
	}
	return airControlHandler(c, id, allow, nil)
}

func TestAirControlSessions(t *testing.T) {
	c := &fakeAirControl{list: []AirSession{{Backend: "fs", ID: "9f2a", Peer: "agent.mesh", AgeSec: 4}}}
	rr := httptest.NewRecorder()
	newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/sessions", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	var out struct {
		Sessions []AirSession `json:"sessions"`
		You      string       `json:"you"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(out.Sessions) != 1 || out.Sessions[0].Backend != "fs" || out.Sessions[0].ID != "9f2a" {
		t.Fatalf("unexpected sessions: %+v", out.Sessions)
	}
	if out.You != "caller.mesh" {
		t.Fatalf("you = %q, want caller.mesh", out.You)
	}
}

func TestAirControlSteerRoutes(t *testing.T) {
	c := &fakeAirControl{}
	rr := httptest.NewRecorder()
	body := `{"backend":"fs","id":"9f2a","method":"notifications/air/steer","params":{"text":"focus"}}`
	newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	if len(c.steers) != 1 || c.steers[0] != "fs/9f2a/notifications/air/steer" {
		t.Fatalf("steer not routed: %v", c.steers)
	}
}

func TestAirControlSteerUnknownSession(t *testing.T) {
	c := &fakeAirControl{err: session.ErrNoSession}
	rr := httptest.NewRecorder()
	body := `{"backend":"fs","id":"nope","method":"notifications/air/steer"}`
	newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(body)))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestAirControlSteerUnknownBackend(t *testing.T) {
	c := &fakeAirControl{err: errNoBackend}
	rr := httptest.NewRecorder()
	body := `{"backend":"ghost","id":"9f2a","method":"notifications/air/steer"}`
	newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(body)))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestAirControlACLDeny(t *testing.T) {
	c := &fakeAirControl{}
	for _, path := range []string{"/v1/sessions", "/v1/steer"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"backend":"fs","id":"9f2a","method":"m"}`))
		newTestHandler(c, false).ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s: status = %d, want 403", path, rr.Code)
		}
	}
	if len(c.steers) != 0 {
		t.Fatalf("denied caller still steered: %v", c.steers)
	}
}

// handlerWithIdentity builds a control handler with a chosen caller identity and
// an audit collector, so per-backend ACL and on-behalf attribution are testable.
func handlerWithIdentity(c airController, pubKey, fqdn string, audit func(airSteerAudit)) http.Handler {
	id := func(*http.Request) (string, string) { return pubKey, fqdn }
	return airControlHandler(c, id, newACL(nil), audit)
}

func TestAirControlPerBackendACL(t *testing.T) {
	// Caller reaches the endpoint (global Allow open) but is denied on backend fs.
	c := &fakeAirControl{
		list:       []AirSession{{Backend: "fs", ID: "9f2a"}, {Backend: "kg", ID: "1a2b"}},
		denyOnFqdn: "outsider.mesh",
	}
	h := handlerWithIdentity(c, "keyX", "outsider.mesh", nil)

	// sessions: fs rows filtered out, kg remains.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/sessions", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("sessions status = %d, want 200", rr.Code)
	}
	var out struct {
		Sessions []AirSession `json:"sessions"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Sessions) != 1 || out.Sessions[0].Backend != "kg" {
		t.Fatalf("fs sessions not filtered for denied caller: %+v", out.Sessions)
	}

	// steer fs: 403 forbidden (backend ACL), not routed.
	rr = httptest.NewRecorder()
	body := `{"backend":"fs","id":"9f2a","method":"notifications/air/steer"}`
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(body)))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("steer fs status = %d, want 403", rr.Code)
	}
}

func TestAirControlSteerMethodAllowlist(t *testing.T) {
	c := &fakeAirControl{}
	var recs []airSteerAudit
	h := handlerWithIdentity(c, "key1", "caller.mesh", func(r airSteerAudit) { recs = append(recs, r) })
	rr := httptest.NewRecorder()
	body := `{"backend":"fs","id":"9f2a","method":"notifications/evil"}`
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("off-allowlist method = %d, want 400", rr.Code)
	}
	if len(c.steers) != 0 {
		t.Fatalf("off-allowlist method still steered: %v", c.steers)
	}
	if len(recs) != 1 || recs[0].OK {
		t.Fatalf("off-allowlist method not audited as deny: %+v", recs)
	}
}

func TestAirControlSteerOnBehalf(t *testing.T) {
	c := &fakeAirControl{}
	var recs []airSteerAudit
	// The connecting peer is ACL-allowed (global Allow open), so its attested
	// X-Air-On-Behalf header is honoured.
	h := handlerWithIdentity(c, "relaykey", "air-serve.mesh", func(r airSteerAudit) { recs = append(recs, r) })
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(`{"backend":"fs","id":"9f2a","method":"notifications/air/steer"}`))
	req.Header.Set("X-Air-On-Behalf", "phone.mesh")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
	}
	if len(recs) != 1 || recs[0].OnBehalf != "phone.mesh" {
		t.Fatalf("on-behalf not attributed: %+v", recs)
	}
	if !strings.Contains(rr.Body.String(), "phone.mesh") {
		t.Fatalf("response should attribute the human: %s", rr.Body)
	}
}

func TestAirControlSteerBadRequest(t *testing.T) {
	c := &fakeAirControl{}
	rr := httptest.NewRecorder()
	newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(`{"backend":"fs"}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	rr = httptest.NewRecorder()
	newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/steer", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /v1/steer = %d, want 405", rr.Code)
	}
}

// TestAirControlEmptyACLDeniesAll is the Phase-4/Air regression: an empty ACL is
// DEFAULT-DENY (not "any mesh peer"), so no one can list or steer without an
// explicit allowlist entry.
func TestAirControlEmptyACLDeniesAll(t *testing.T) {
	c := &fakeAirControl{list: []AirSession{{Backend: "fs", ID: "9f2a"}}}
	id := func(*http.Request) (string, string) { return "key1", "caller.mesh" }
	h := airControlHandler(c, id, newACL(nil), nil) // empty ACL
	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/v1/sessions", ""},
		{http.MethodPost, "/v1/steer", `{"backend":"fs","id":"9f2a","method":"notifications/air/steer"}`},
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s with empty ACL should be 403, got %d", tc.method, tc.path, rr.Code)
		}
	}
	if len(c.steers) != 0 {
		t.Fatalf("empty-ACL caller must not steer: %v", c.steers)
	}
}

// TestAirControlSteerMethodAllowlist: only notifications/* may be steered; a
// server->client request (or any other method) is rejected.
func TestAirControlSteerMethodAllowlist(t *testing.T) {
	for _, method := range []string{"sampling/createMessage", "tools/call", "roots/list", "initialize"} {
		c := &fakeAirControl{}
		rr := httptest.NewRecorder()
		body := `{"backend":"fs","id":"9f2a","method":"` + method + `"}`
		newTestHandler(c, true).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/steer", strings.NewReader(body)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("steer method %q should be rejected (400), got %d", method, rr.Code)
		}
		if len(c.steers) != 0 {
			t.Fatalf("off-allowlist method %q was steered: %v", method, c.steers)
		}
	}
}
