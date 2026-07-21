package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"meshmcp/session"
)

// fakeAirControl is an in-memory airController for handler tests.
type fakeAirControl struct {
	list     []AirSession
	steers   []string // "backend/id/method" of accepted steers
	handoffs []string // "backend/id/newkey" of accepted handoffs
	err      error    // returned by steer/handoff
}

func (f *fakeAirControl) sessions() []AirSession { return f.list }
func (f *fakeAirControl) steer(backend, id, method string, _ any) error {
	if f.err != nil {
		return f.err
	}
	f.steers = append(f.steers, backend+"/"+id+"/"+method)
	return nil
}

func (f *fakeAirControl) handoff(backend, id, newKey string) error {
	if f.err != nil {
		return f.err
	}
	f.handoffs = append(f.handoffs, backend+"/"+id+"/"+newKey)
	return nil
}

func newTestHandler(c airController, allowAll bool) http.Handler {
	id := func(*http.Request) (string, string) { return "key1", "caller.mesh" }
	allow := newACL(nil)
	if !allowAll {
		allow = newACL([]string{"pubkey:someone-else"})
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

func TestAirControlHandoffRoutes(t *testing.T) {
	c := &fakeAirControl{}
	h := newTestHandler(c, true)
	body := `{"backend":"fs","id":"9f2a","new_key":"bob-key"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/handoff", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("handoff: want 200, got %d (%s)", rr.Code, rr.Body)
	}
	if len(c.handoffs) != 1 || c.handoffs[0] != "fs/9f2a/bob-key" {
		t.Fatalf("handoff not routed: %v", c.handoffs)
	}
}

func TestAirControlHandoffACLDeny(t *testing.T) {
	c := &fakeAirControl{}
	h := newTestHandler(c, false)
	req := httptest.NewRequest(http.MethodPost, "/v1/handoff", strings.NewReader(`{"backend":"fs","id":"x","new_key":"k"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("unauthorized handoff: want 403, got %d", rr.Code)
	}
	if len(c.handoffs) != 0 {
		t.Fatalf("denied handoff must not route: %v", c.handoffs)
	}
}

func TestAirControlHandoffBadRequest(t *testing.T) {
	c := &fakeAirControl{}
	h := newTestHandler(c, true)
	// missing new_key
	req := httptest.NewRequest(http.MethodPost, "/v1/handoff", strings.NewReader(`{"backend":"fs","id":"x"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing new_key: want 400, got %d", rr.Code)
	}
}
