package air

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFetchCatalog covers the transport-agnostic catalog fetch: a 200 parses,
// the raw body is returned for --json, a non-200 and an unparseable body error,
// and an oversized body is bounded.
func TestFetchCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte(`{"service":"meshmcp","version":"1","endpoints":[{"name":"fs","address":"a:1","transport":"stdio","steerable":true}]}`))
		case "/bad":
			_, _ = w.Write([]byte(`not json`))
		case "/huge":
			w.Write([]byte(`{"service":"x","endpoints":[`))
			for i := 0; i < 200000; i++ {
				w.Write([]byte(`{"name":"n","address":"a"},`))
			}
			w.Write([]byte(`{"name":"last","address":"a"}]}`))
		default:
			http.Error(w, "nope", http.StatusForbidden)
		}
	}))
	defer srv.Close()
	hc := srv.Client()

	// 200 → parsed + raw body.
	cat, body, err := FetchCatalog(hc, srv.URL+"/ok")
	if err != nil {
		t.Fatalf("fetch ok: %v", err)
	}
	if cat.Service != "meshmcp" || len(cat.Endpoints) != 1 || cat.Endpoints[0].Name != "fs" {
		t.Fatalf("parsed catalog wrong: %+v", cat)
	}
	if !strings.Contains(string(body), `"fs"`) {
		t.Fatalf("raw body not returned: %s", body)
	}
	if s := cat.Steerable(); len(s) != 1 {
		t.Fatalf("Steerable() = %+v", s)
	}

	// Non-200 → error, body surfaced.
	if _, b, err := FetchCatalog(hc, srv.URL+"/denied"); err == nil {
		t.Fatal("non-200 must error")
	} else if !strings.Contains(string(b), "nope") {
		t.Fatalf("error body not surfaced: %s", b)
	}

	// Unparseable → error.
	if _, _, err := FetchCatalog(hc, srv.URL+"/bad"); err == nil {
		t.Fatal("unparseable body must error")
	}

	// Oversized body is bounded (LimitReader truncates → JSON parse fails, no OOM).
	if _, b, err := FetchCatalog(hc, srv.URL+"/huge"); err == nil {
		t.Fatal("truncated oversized body must error, not parse")
	} else if len(b) > maxCatalogBody {
		t.Fatalf("body not bounded: %d bytes", len(b))
	}
}
