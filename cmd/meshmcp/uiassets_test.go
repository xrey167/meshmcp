package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgentOSStylesheet(t *testing.T) {
	mux := http.NewServeMux()
	registerAgentOSAssets(mux)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/assets/agent-os.css", nil))
	if rr.Code != http.StatusOK || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("stylesheet = %d %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	for _, token := range []string{"--mesh-accent", "prefers-color-scheme", "focus-visible", "prefers-reduced-motion"} {
		if !strings.Contains(rr.Body.String(), token) {
			t.Errorf("shared stylesheet missing %q", token)
		}
	}

	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/assets/agent-os.css", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST stylesheet = %d, want 405", rr.Code)
	}
}

func TestIndependentSurfacesLoadAgentOSFoundation(t *testing.T) {
	for name, page := range map[string]string{
		"approvals": approvalsHTML,
		"dashboard": dashHTML,
		"room":      roomHTML,
	} {
		if !strings.Contains(page, `href="/assets/agent-os.css"`) {
			t.Errorf("%s does not load shared Agent OS styles", name)
		}
	}
}

func TestDashboardEscapesUntrustedDecisions(t *testing.T) {
	if strings.Contains(dashHTML, `'<span class="tag '+d+'">'+d+'</span>'`) {
		t.Fatal("dashboard interpolates an untrusted decision into HTML")
	}
	if !strings.Contains(dashHTML, `const cls=/^(allow|deny|cosign)$/.test(d)?d:''`) ||
		!strings.Contains(dashHTML, `'+esc(d)+'</span>'`) {
		t.Fatal("dashboard must allowlist decision classes and escape their labels")
	}
}
