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

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
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

// TestAirServeVision covers the Vision gallery endpoints end to end: /api/config
// advertises it, /api/gallery lists the inbox images, /api/image serves one with
// the exact content type, and a traversal name is refused.
func TestAirServeVision(t *testing.T) {
	dir := t.TempDir()
	writeImage(t, dir, "shot.png", 5)
	h := airServeHandler(airServeDeps{
		gallery: func(limit int) ([]galleryImage, error) { return listGalleryImages(dir, limit) },
		image:   func(name string) ([]byte, string, error) { return readGalleryImage(dir, name) },
	})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"vision":true`) {
		t.Fatalf("config: %d %s", rr.Code, rr.Body)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/gallery", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "shot.png") {
		t.Fatalf("gallery: %d %s", rr.Code, rr.Body)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/image?name=shot.png", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("image: %d %s", rr.Code, rr.Body)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "image/png" {
		t.Fatalf("image content-type = %q, want image/png", ct)
	}
	// Served inline (not downloaded) — the whole point of the gallery.
	if cd := rr.Header().Get("Content-Disposition"); cd != "inline" {
		t.Fatalf("image content-disposition = %q, want inline", cd)
	}

	// Missing name is a 400.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/image", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing name = %d, want 400", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/image?name=../secret.png", nil))
	if rr.Code == http.StatusOK {
		t.Fatalf("traversal served: %d %s", rr.Code, rr.Body)
	}

	// Disabled by default.
	off := airServeHandler(airServeDeps{})
	rr = httptest.NewRecorder()
	off.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/gallery", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("gallery off = %d, want 503", rr.Code)
	}
}

// TestAirServeHardening covers the defence-in-depth added to the served API:
// read-only routes reject non-GET, sensitive responses are no-store, and the
// relay's push refuses a malformed target.
func TestAirServeHardening(t *testing.T) {
	h := airServeHandler(airServeDeps{
		peers: func() ([]airPeerRow, error) { return nil, nil },
		push:  func(ctx context.Context, target, name string, data []byte) error { return nil },
	})

	// A read-only route rejects POST with 405.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/peers", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/peers = %d, want 405", rr.Code)
	}

	// Sensitive JSON responses are not cacheable.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/peers", nil))
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}

	// A malformed push target is refused before any dial.
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/push", strings.NewReader(`{"target":"not-a-target","text":"hi"}`))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("push bad target = %d, want 400", rr.Code)
	}
}

func TestValidMeshTarget(t *testing.T) {
	for _, ok := range []string{"100.64.0.9:9110", "peer.mesh:22", "[::1]:80"} {
		if !validMeshTarget(ok) {
			t.Errorf("validMeshTarget(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "no-port", "host:", ":9110", "host:abc", "a:b:c"} {
		if validMeshTarget(bad) {
			t.Errorf("validMeshTarget(%q) = true, want false", bad)
		}
	}
}

// TestAirServeCast covers the Cast "Now Showing" endpoints: /api/config
// advertises it, /api/cast lists the cast inbox, and /api/castimage serves one.
func TestAirServeCast(t *testing.T) {
	dir := t.TempDir()
	writeImage(t, dir, "slide.png", 3)
	h := airServeHandler(airServeDeps{
		cast:      func(limit int) ([]galleryImage, error) { return listGalleryImages(dir, limit) },
		castImage: func(name string) ([]byte, string, error) { return readGalleryImage(dir, name) },
	})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"cast":true`) {
		t.Fatalf("config: %d %s", rr.Code, rr.Body)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/cast?limit=1", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "slide.png") {
		t.Fatalf("cast: %d %s", rr.Code, rr.Body)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/castimage?name=slide.png", nil))
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("castimage: %d ct=%q", rr.Code, rr.Header().Get("Content-Type"))
	}
	// Traversal refused on the cast dir too.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/castimage?name=../secret.png", nil))
	if rr.Code == http.StatusOK {
		t.Fatalf("cast traversal served: %d", rr.Code)
	}
	// Disabled by default.
	off := airServeHandler(airServeDeps{})
	rr = httptest.NewRecorder()
	off.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/cast", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("cast off = %d, want 503", rr.Code)
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

// TestAirServeControlRequiresAllow proves the relay refuses to expose the
// privileged (confused-deputy) endpoints without an --allow list naming who may
// drive them — so no arbitrary mesh peer can steer/push with the relay's key.
func TestAirServeControlRequiresAllow(t *testing.T) {
	err := cmdAirServe([]string{"--control", "100.64.0.2:9600"})
	if err == nil || !strings.Contains(err.Error(), "--allow") {
		t.Fatalf("air serve --control without --allow must fail closed, got: %v", err)
	}
}

// TestAirServeSecurityHeaders proves the hardening headers are set on every
// response (CSP, nosniff, frame-deny, no-referrer).
func TestAirServeSecurityHeaders(t *testing.T) {
	h := airServeHandler(airServeDeps{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	hd := rr.Header()
	if csp := hd.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP missing/weak: %q", csp)
	}
	if hd.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing nosniff: %q", hd.Get("X-Content-Type-Options"))
	}
	if hd.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing frame-deny: %q", hd.Get("X-Frame-Options"))
	}
	if hd.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("missing referrer-policy: %q", hd.Get("Referrer-Policy"))
	}
}

// TestAirServeCrossOriginRefused proves a state-changing POST from a different
// origin is refused (CSRF / DNS-rebinding), while a same-origin POST and an
// Origin-less (non-browser) POST proceed.
func TestAirServeCrossOriginRefused(t *testing.T) {
	var pushed int
	h := airServeHandler(airServeDeps{
		push: func(_ context.Context, _, _ string, _ []byte) error { pushed++; return nil },
	})
	body := `{"target":"100.64.0.9:9110","text":"hi"}`

	// Cross-origin → 403, push not invoked.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/push", strings.NewReader(body))
	req.Host = "100.64.0.2:9800"
	req.Header.Set("Origin", "http://evil.example")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST = %d, want 403", rr.Code)
	}

	// Same-origin → allowed.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/push", strings.NewReader(body))
	req.Host = "100.64.0.2:9800"
	req.Header.Set("Origin", "http://100.64.0.2:9800")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("same-origin POST = %d, want 200: %s", rr.Code, rr.Body)
	}

	// No Origin (non-browser client) → allowed.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/push", strings.NewReader(body))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("origin-less POST = %d, want 200", rr.Code)
	}
	if pushed != 2 {
		t.Fatalf("push should have run twice (same-origin + origin-less), got %d", pushed)
	}
}

// TestAirServeCatalogProxy proves the page proxies /api/catalog to the gateway's
// well-known catalog with browser attestation, and advertises it via /api/config.
func TestAirServeCatalogProxy(t *testing.T) {
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == airCatalogPath {
			if r.Header.Get("X-Air-On-Behalf") != "phone.mesh" {
				t.Errorf("catalog request missing on-behalf attestation")
			}
			_, _ = io.WriteString(w, `{"service":"meshmcp","version":"t","endpoints":[{"name":"fs","address":"100.64.0.2:9101","transport":"stdio","steerable":true}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer control.Close()

	h := airServeHandler(airServeDeps{
		controlHC:   control.Client(),
		controlBase: control.URL,
		identify:    func(*http.Request) (string, string) { return "browserkey", "phone.mesh" },
	})

	// config advertises catalog availability.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if !strings.Contains(rr.Body.String(), `"catalog":true`) {
		t.Fatalf("config should advertise catalog: %s", rr.Body)
	}

	// catalog proxied through.
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/catalog", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"fs"`) {
		t.Fatalf("catalog proxy failed: %d %s", rr.Code, rr.Body)
	}

	// disabled without control.
	off := airServeHandler(airServeDeps{})
	rr = httptest.NewRecorder()
	off.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/catalog", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("catalog without control = %d, want 503", rr.Code)
	}
}

// TestAPIHomeAggregates proves /api/home fuses the wired sources into one
// payload carrying peers + sessions + reachable + receipts + cast + summary.
func TestAPIHomeAggregates(t *testing.T) {
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sessions":
			_, _ = io.WriteString(w, `{"sessions":[{"backend":"fs","id":"9f2a","peer":"gw.mesh","age_sec":4}]}`)
		case airCatalogPath:
			_, _ = io.WriteString(w, `{"service":"meshmcp","version":"t","endpoints":[{"name":"fs","address":"100.64.0.2:9101","transport":"stdio","steerable":true}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer control.Close()

	h := airServeHandler(airServeDeps{
		self:        func() airPeerRow { return airPeerRow{Status: "connected", FQDN: "me.mesh", IP: "100.64.0.1"} },
		peers:       func() ([]airPeerRow, error) { return []airPeerRow{{Status: "connected", FQDN: "gw.mesh", IP: "100.64.0.2"}}, nil },
		controlHC:   control.Client(),
		controlBase: control.URL,
		receipts: func(limit int) ([]json.RawMessage, error) {
			return []json.RawMessage{json.RawMessage(`{"decision":"allow","peer":"gw.mesh","method":"tools/call"}`)}, nil
		},
		cast:     func(limit int) ([]galleryImage, error) { return []galleryImage{{Name: "slide.png", ModUnix: 1700000000}}, nil },
		identify: func(*http.Request) (string, string) { return "K", "me.mesh" },
	})

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/home", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("home status %d: %s", rr.Code, rr.Body)
	}
	var home air.Home
	if err := json.Unmarshal(rr.Body.Bytes(), &home); err != nil {
		t.Fatalf("home payload: %v", err)
	}
	if home.You.FQDN != "me.mesh" {
		t.Errorf("you = %+v, want me.mesh", home.You)
	}
	if len(home.Peers) != 1 || len(home.Sessions) != 1 || len(home.Reachable) != 1 || len(home.Activity) != 1 {
		t.Fatalf("sections not all aggregated: peers=%d sessions=%d reachable=%d activity=%d",
			len(home.Peers), len(home.Sessions), len(home.Reachable), len(home.Activity))
	}
	if home.Sessions[0].ID != "9f2a" || home.Showing == nil || home.Showing.Name != "slide.png" {
		t.Errorf("session/cast wrong: %+v %+v", home.Sessions, home.Showing)
	}
	if home.Summary.PeersOnline != 1 || home.Summary.Sessions != 1 || home.Summary.Reachable != 1 {
		t.Errorf("summary counts wrong: %+v", home.Summary)
	}
	if home.Pending != -1 {
		t.Errorf("pending = %d, want -1 (no pendingCount wired)", home.Pending)
	}
}

// TestAPIHomeRespectsViewerACL proves the aggregated route is behind the same
// per-viewer ACL as every other endpoint.
func TestAPIHomeRespectsViewerACL(t *testing.T) {
	h := airServeHandler(airServeDeps{
		allow:    newACL([]string{"phone.mesh"}),
		identify: func(r *http.Request) (string, string) { return "k", r.Header.Get("X-Test-FQDN") },
	})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/home", nil)
	req.Header.Set("X-Test-FQDN", "stranger.mesh")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("stranger to /api/home = %d, want 403", rr.Code)
	}
}

// TestAPIHomeGETOnly proves the aggregated route is read-only.
func TestAPIHomeGETOnly(t *testing.T) {
	h := airServeHandler(airServeDeps{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/home", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/home = %d, want 405", rr.Code)
	}
}

// TestAPIHomeLedgerNotPolluted proves a home view never appends to the gateway
// enforcement ledger, and that an opt-in view-audit lands exactly one
// method:"air.home" record on its OWN hash chain — which still verifies.
func TestAPIHomeLedgerNotPolluted(t *testing.T) {
	// Enforcement ledger: a real hash-chained file (one prior record).
	ledger := filepath.Join(t.TempDir(), "audit.jsonl")
	var lb bytes.Buffer
	enf := policy.NewAuditLog(&lb, func() string { return "2026-07-22T12:00:00Z" })
	if err := enf.Append(policy.AuditRecord{Method: "tools/call", Decision: "allow", Peer: "a.mesh", Rule: -1}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ledger, lb.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(ledger)

	// Separate view chain over its own sink.
	var vb bytes.Buffer
	view := policy.NewAuditLog(&vb, func() string { return "2026-07-22T12:00:01Z" })

	h := airServeHandler(airServeDeps{
		receipts:  func(limit int) ([]json.RawMessage, error) { return tailAuditRecords(ledger, limit) },
		viewAudit: view,
		identify:  func(*http.Request) (string, string) { return "VK", "viewer.mesh" },
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/home", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("home status %d: %s", rr.Code, rr.Body)
	}

	// The enforcement ledger is byte-for-byte unchanged.
	after, _ := os.ReadFile(ledger)
	if !bytes.Equal(before, after) {
		t.Fatalf("home view mutated the enforcement ledger:\nbefore=%s\nafter=%s", before, after)
	}

	// The separate chain got exactly one air.home record, attributed to the viewer.
	lines := strings.Split(strings.TrimSpace(vb.String()), "\n")
	if len(lines) != 1 || !strings.Contains(vb.String(), `"method":"air.home"`) || !strings.Contains(vb.String(), "viewer.mesh") {
		t.Fatalf("view chain wrong: %q", vb.String())
	}
	res, err := policy.VerifyChain(bytes.NewReader(vb.Bytes()))
	if err != nil || !res.OK {
		t.Fatalf("view chain does not verify: err=%v res=%+v", err, res)
	}
}

// TestAPIHomePendingHiddenWithoutAllow proves the pending count is unknown (-1)
// when no pendingCount dep is wired — no approvals number leaks to a viewer.
func TestAPIHomePendingHiddenWithoutAllow(t *testing.T) {
	h := airServeHandler(airServeDeps{
		peers: func() ([]airPeerRow, error) { return nil, nil },
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/home", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("home status %d", rr.Code)
	}
	var home air.Home
	if err := json.Unmarshal(rr.Body.Bytes(), &home); err != nil {
		t.Fatal(err)
	}
	if home.Pending != -1 || home.Summary.Pending != -1 {
		t.Fatalf("pending leaked without --allow: home=%d summary=%d", home.Pending, home.Summary.Pending)
	}
}

// TestAirServeHostPinning proves the Host allow-list defeats DNS rebinding: a
// request whose Host is not the served mesh address is refused even when the
// Origin matches the Host (the case a same-origin check alone misses).
func TestAirServeHostPinning(t *testing.T) {
	h := airServeHandler(airServeDeps{allowedHosts: []string{"100.64.0.2:9800"}})

	// Rebinding: Host == Origin == attacker domain → refused.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "evil.example"
	req.Header.Set("Origin", "http://evil.example")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("rebound Host = %d, want 403", rr.Code)
	}

	// Legitimate: Host is the mesh address → served.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "100.64.0.2:9800"
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("mesh Host = %d, want 200", rr.Code)
	}

	// No allow-list (dev / tests) → Host check skipped.
	open := airServeHandler(airServeDeps{})
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "anything"
	open.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("no allow-list should skip Host check, got %d", rr.Code)
	}
}
