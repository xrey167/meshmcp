package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoomCapsReflectsFlags(t *testing.T) {
	rs := &roomServer{localShell: true}
	rec := httptest.NewRecorder()
	rs.handleCaps(rec, httptest.NewRequest("GET", "/api/caps", nil))
	var caps map[string]any
	json.Unmarshal(rec.Body.Bytes(), &caps)
	if caps["mesh"] != false || caps["local_shell"] != true {
		t.Fatalf("caps wrong: %+v", caps)
	}
}

func TestRoomShellGatedOff(t *testing.T) {
	rs := &roomServer{localShell: false}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/shell", strings.NewReader(`{"cmd":"echo hi"}`))
	rs.handleShell(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("shell must be forbidden when --local-shell is off, got %d", rec.Code)
	}
}

func TestRoomShellRunsWhenEnabled(t *testing.T) {
	rs := &roomServer{localShell: true}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/shell", strings.NewReader(`{"cmd":"echo meshmcp-shell-ok"}`))
	rs.handleShell(rec, req)
	if rec.Code != 200 {
		t.Fatalf("shell should run, got %d", rec.Code)
	}
	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if out, _ := resp["output"].(string); !strings.Contains(out, "meshmcp-shell-ok") {
		t.Fatalf("shell output wrong: %q", resp["output"])
	}
}

func TestRoomCallWithoutMeshErrors(t *testing.T) {
	rs := &roomServer{} // mesh == nil
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/call", strings.NewReader(`{"target":"100.64.0.1:9101","tool":"add"}`))
	rs.handleCall(rec, req)
	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if e, _ := resp["error"].(string); !strings.Contains(e, "not connected to the mesh") {
		t.Fatalf("expected a not-connected error, got %+v", resp)
	}
}

func TestRoomGuardBlocksRebindingAndCSRF(t *testing.T) {
	addr := "127.0.0.1:9900"
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	g := guardLoopback(inner, addr)

	check := func(host, origin string, want int) {
		t.Helper()
		req := httptest.NewRequest("POST", "http://x/api/shell", strings.NewReader("{}"))
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		g.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("host=%q origin=%q → %d, want %d", host, origin, rec.Code, want)
		}
	}
	// Legit same-origin requests pass.
	check("127.0.0.1:9900", "http://127.0.0.1:9900", 200)
	check("localhost:9900", "", 200)
	// DNS rebinding: attacker domain (rebound to 127.0.0.1) → Host is the domain.
	check("evil.com:9900", "", http.StatusForbidden)
	check("attacker.example:9900", "http://attacker.example:9900", http.StatusForbidden)
	// CSRF: loopback host but a cross-origin page.
	check("127.0.0.1:9900", "https://evil.com", http.StatusForbidden)
	// Wrong port on a loopback host.
	check("127.0.0.1:1234", "", http.StatusForbidden)
}

const roomMoveBody = `{"backend":"fs","id":"9f2a","dest_key":"K","dest_addr":"100.64.0.9:9600"}`

// TestRoomMoveRequiresToken: the browser->room hop is token-gated, so an
// unauthenticated viewer cannot fire a handoff even before the gateway ACL.
func TestRoomMoveRequiresToken(t *testing.T) {
	rs := &roomServer{token: "secret", control: "100.64.0.9:9600"}
	h := rs.requireToken(rs.handleMove)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("POST", "/api/move", strings.NewReader(roomMoveBody))) // no token
	if rec.Code != http.StatusForbidden {
		t.Fatalf("move without token = %d, want 403", rec.Code)
	}
}

// TestRoomMoveWithoutControlWired: with no --control the move endpoint fails
// clearly (409), never a silent success.
func TestRoomMoveWithoutControlWired(t *testing.T) {
	rs := &roomServer{token: "secret"} // control unset
	rec := httptest.NewRecorder()
	rs.handleMove(rec, httptest.NewRequest("POST", "/api/move", strings.NewReader(roomMoveBody)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("move without --control = %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not wired") {
		t.Fatalf("expected a not-wired message: %s", rec.Body)
	}
}

// TestRoomSessionsWithoutControlWired: the live Sessions panel fails clearly when
// the room is not wired to a control gateway.
func TestRoomSessionsWithoutControlWired(t *testing.T) {
	rs := &roomServer{}
	rec := httptest.NewRecorder()
	rs.handleSessions(rec, httptest.NewRequest("GET", "/api/sessions", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("sessions without --control = %d, want 409", rec.Code)
	}
}

// TestRoomMoveBadRequest: an incomplete body is 400 before any proxy.
func TestRoomMoveBadRequest(t *testing.T) {
	rs := &roomServer{control: "100.64.0.9:9600"}
	rec := httptest.NewRecorder()
	rs.handleMove(rec, httptest.NewRequest("POST", "/api/move", strings.NewReader(`{"backend":"fs"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("incomplete move body = %d, want 400", rec.Code)
	}
}

// TestRoomCapsControl: the control capability is false when unwired and true when
// both --control and mesh credentials are present (so the SPA hides/shows the panel).
func TestRoomCapsControl(t *testing.T) {
	unwired := &roomServer{}
	rec := httptest.NewRecorder()
	unwired.handleCaps(rec, httptest.NewRequest("GET", "/api/caps", nil))
	var caps map[string]any
	json.Unmarshal(rec.Body.Bytes(), &caps)
	if caps["control"] != false {
		t.Fatalf("unwired control cap = %v, want false", caps["control"])
	}

	wired := &roomServer{control: "100.64.0.9:9600", controlHC: &http.Client{}}
	rec = httptest.NewRecorder()
	wired.handleCaps(rec, httptest.NewRequest("GET", "/api/caps", nil))
	json.Unmarshal(rec.Body.Bytes(), &caps)
	if caps["control"] != true {
		t.Fatalf("wired control cap = %v, want true", caps["control"])
	}
}

// TestRoomMoveProxiesGatewayVerdict proves the room passes the source gateway's
// status and reason THROUGH unchanged — a 409 refusal reaches the browser as a
// 409 with its reason, so the tile can tell the truth (source still serving).
func TestRoomMoveProxiesGatewayVerdict(t *testing.T) {
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/move" || r.Method != http.MethodPost {
			t.Errorf("unexpected upstream request %s %s", r.Method, r.URL.Path)
		}
		http.Error(w, "destination could not commit move: grant missing", http.StatusConflict)
	}))
	defer gw.Close()
	addr := gw.Listener.Addr().String()
	rs := &roomServer{control: addr, controlHC: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return net.Dial("tcp", addr) },
	}}}
	rec := httptest.NewRecorder()
	rs.handleMove(rec, httptest.NewRequest("POST", "/api/move", strings.NewReader(roomMoveBody)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("proxied move status = %d, want 409 (passed through)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "grant missing") {
		t.Fatalf("refusal reason not passed through: %s", rec.Body)
	}
}

func TestLoopbackAddr(t *testing.T) {
	for _, a := range []string{"127.0.0.1:9900", "localhost:9900", "[::1]:9900"} {
		if !loopbackAddr(a) {
			t.Fatalf("%q should be loopback", a)
		}
	}
	for _, a := range []string{"0.0.0.0:9900", ":9900", "100.64.0.5:9900"} {
		if loopbackAddr(a) {
			t.Fatalf("%q should NOT be loopback", a)
		}
	}
}
