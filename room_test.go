package main

import (
	"encoding/json"
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
