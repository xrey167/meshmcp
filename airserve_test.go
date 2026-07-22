package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
			if ob := r.Header.Get("X-Air-On-Behalf"); ob != "phone.mesh" {
				t.Errorf("X-Air-On-Behalf = %q, want phone.mesh", ob)
			}
			_, _ = io.WriteString(w, `{"status":"steered"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()

	h := airServeHandler(airServeDeps{
		controlHC:   control.Client(),
		controlBase: control.URL,
		identify:    func(*http.Request) (string, string) { return "browserkey", "phone.mesh" },
	})

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

// TestAirServePushDrop covers the relay push/drop endpoints: JSON text push,
// multipart file drop, disabled state, and input validation.
func TestAirServePushDrop(t *testing.T) {
	type sent struct {
		target, name string
		data         []byte
	}
	var got []sent
	h := airServeHandler(airServeDeps{
		push: func(_ context.Context, target, name string, data []byte) error {
			got = append(got, sent{target, name, data})
			return nil
		},
	})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/push", strings.NewReader(`{"target":"100.64.0.9:9110","text":"meet at 15:00"}`)))
	if rr.Code != http.StatusOK {
		t.Fatalf("push status %d: %s", rr.Code, rr.Body)
	}
	if len(got) != 1 || got[0].name != "clip.txt" || string(got[0].data) != "meet at 15:00" {
		t.Fatalf("push not delivered: %+v", got)
	}

	// Multipart drop.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("target", "100.64.0.9:9110")
	fw, _ := mw.CreateFormFile("file", "report.pdf")
	_, _ = fw.Write([]byte("PDFDATA"))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/drop", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("drop status %d: %s", rr.Code, rr.Body)
	}
	if len(got) != 2 || got[1].name != "report.pdf" || string(got[1].data) != "PDFDATA" {
		t.Fatalf("drop not delivered: %+v", got[1])
	}

	// Missing fields are 400s.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/push", strings.NewReader(`{"text":"x"}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("push without target = %d, want 400", rr.Code)
	}

	// Disabled when no push dep is wired.
	off := airServeHandler(airServeDeps{})
	rr = httptest.NewRecorder()
	off.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/push", strings.NewReader(`{"target":"a:1","text":"x"}`)))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled push = %d, want 503", rr.Code)
	}
}

// TestAirServeReceiptsAndConfig covers the receipts tail endpoint and the
// config endpoint the page uses to toggle views.
func TestAirServeReceiptsAndConfig(t *testing.T) {
	h := airServeHandler(airServeDeps{
		approvals: "100.64.0.2:9310",
		receipts: func(limit int) ([]json.RawMessage, error) {
			return []json.RawMessage{json.RawMessage(`{"decision":"allow","peer":"a.mesh"}`)}, nil
		},
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/receipts", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "a.mesh") {
		t.Fatalf("receipts: %d %s", rr.Code, rr.Body)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "9310") {
		t.Fatalf("config: %d %s", rr.Code, rr.Body)
	}
}

// TestAirServeViewerACL proves a non-empty --allow list gates every route by
// the browser's mesh identity.
func TestAirServeViewerACL(t *testing.T) {
	h := airServeHandler(airServeDeps{
		allow:    newACL([]string{"phone.mesh"}),
		identify: func(r *http.Request) (string, string) { return "k", r.Header.Get("X-Test-FQDN") },
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Test-FQDN", "phone.mesh")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("allowed viewer = %d, want 200", rr.Code)
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Test-FQDN", "stranger.mesh")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("stranger = %d, want 403", rr.Code)
	}
}

// TestTailAuditRecords covers the receipts file tail helper.
func TestTailAuditRecords(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	lines := `{"seq":1,"decision":"allow"}
not json
{"seq":2,"decision":"deny"}
{"seq":3,"decision":"allow"}
`
	if err := os.WriteFile(p, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := tailAuditRecords(p, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || !strings.Contains(string(recs[0]), `"seq":2`) || !strings.Contains(string(recs[1]), `"seq":3`) {
		t.Fatalf("unexpected tail: %v", recs)
	}
}
