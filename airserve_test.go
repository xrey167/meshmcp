package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAirServePage(t *testing.T) {
	h := airServeHandler(airServeDeps{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "meshmcp") {
		t.Fatalf("page not served: %d", rr.Code)
	}
}

func TestAirServePeers(t *testing.T) {
	h := airServeHandler(airServeDeps{peers: func() ([]airPeerRow, error) {
		return []airPeerRow{{Status: "connected", IP: "100.64.0.2", FQDN: "gw.mesh", PubKey: "Ab…"}}, nil
	}})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/peers", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("peers status %d", rr.Code)
	}
	var out struct {
		Peers []airPeerRow `json:"peers"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Peers) != 1 || out.Peers[0].FQDN != "gw.mesh" {
		t.Fatalf("unexpected peers: %+v", out.Peers)
	}
}

func TestAirServeSessionsProxy(t *testing.T) {
	// A stub gateway control endpoint.
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sessions":
			_, _ = io.WriteString(w, `{"sessions":[{"backend":"fs","id":"9f2a","peer":"a.mesh","age_sec":4}]}`)
		case "/v1/steer":
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), "9f2a") {
				t.Errorf("steer body missing id: %s", b)
			}
			_, _ = io.WriteString(w, `{"status":"steered"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()

	h := airServeHandler(airServeDeps{controlHC: control.Client(), controlBase: control.URL})

	// sessions proxied through
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "9f2a") {
		t.Fatalf("sessions proxy failed: %d %s", rr.Code, rr.Body)
	}
	// steer proxied through
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/steer", strings.NewReader(`{"backend":"fs","id":"9f2a","method":"m"}`)))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "steered") {
		t.Fatalf("steer proxy failed: %d %s", rr.Code, rr.Body)
	}
}

func TestAirServeNoControl(t *testing.T) {
	h := airServeHandler(airServeDeps{}) // no control configured
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without control, got %d", rr.Code)
	}
}
