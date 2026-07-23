package embed

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func embedServer(t *testing.T, dim int, wantAuth string, fail *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantAuth != "" && r.Header.Get("Authorization") != wantAuth {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if fail != nil && fail.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		var req struct {
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		vec := make([]float64, dim)
		vec[0] = 3 // deliberately unnormalized: the client must normalize
		vec[1] = 4
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{"embedding": vec}},
		})
	}))
}

func TestHTTPEmbedderProbeAndNormalize(t *testing.T) {
	srv := embedServer(t, 8, "", nil)
	defer srv.Close()
	e, err := NewHTTP(srv.URL, "test-model", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.Dim() != 8 {
		t.Fatalf("dim = %d, want 8 (from probe)", e.Dim())
	}
	vec := e.Embed("hello")
	if len(vec) != 8 {
		t.Fatalf("len = %d", len(vec))
	}
	// 3-4-5 triangle: normalized components are 0.6 and 0.8.
	if diff := vec[0] - 0.6; diff > 1e-6 || diff < -1e-6 {
		t.Fatalf("not normalized: %v", vec[:2])
	}
}

func TestHTTPEmbedderAuthAndKeyEnv(t *testing.T) {
	srv := embedServer(t, 4, "Bearer sekrit", nil)
	defer srv.Close()

	t.Setenv("EMBED_TEST_KEY", "sekrit")
	if _, err := NewHTTP(srv.URL, "m", "EMBED_TEST_KEY", nil); err != nil {
		t.Fatalf("authorized probe failed: %v", err)
	}

	// A named-but-empty key env must fail closed at construction.
	os.Unsetenv("EMBED_TEST_KEY_MISSING")
	if _, err := NewHTTP(srv.URL, "m", "EMBED_TEST_KEY_MISSING", nil); err == nil {
		t.Fatal("empty key env must refuse construction")
	}

	// Wrong key: the probe fails closed (no silent unauthenticated fallback).
	t.Setenv("EMBED_TEST_KEY", "wrong")
	if _, err := NewHTTP(srv.URL, "m", "EMBED_TEST_KEY", nil); err == nil {
		t.Fatal("unauthorized probe must refuse construction")
	}
}

func TestHTTPEmbedderRuntimeFailureDegradesToZero(t *testing.T) {
	var fail atomic.Bool
	srv := embedServer(t, 4, "", &fail)
	defer srv.Close()
	var logged strings.Builder
	e, err := NewHTTP(srv.URL, "m", "", func(f string, a ...any) { logged.WriteString(f) })
	if err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	vec := e.Embed("x")
	if len(vec) != 4 {
		t.Fatalf("len = %d", len(vec))
	}
	for _, v := range vec {
		if v != 0 {
			t.Fatalf("degraded embed must be the zero vector, got %v", vec)
		}
	}
	if logged.Len() == 0 {
		t.Fatal("runtime failure must be logged")
	}
}
