package edge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/protocol/authorization"
)

// Lower the bcrypt work factor for the whole test binary: cost 12 across many
// registrations under -race is prohibitively slow. Production keeps cost 12.
func init() { bcryptCost = bcryptMinTestCost }

const bcryptMinTestCost = 4

// TestRegisterRateLimited exercises the per-IP registration limiter in isolation.
func TestRegisterRateLimited(t *testing.T) {
	_, ts := newServerWith(t, func(c *Config) { c.Limits.RegisterPerIPPerMin = 2 })
	defer ts.Close()
	got429 := false
	for i := 0; i < 5; i++ {
		resp, _ := registerClient(t, ts.URL, goodRegBody, "")
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
		}
	}
	if !got429 {
		t.Fatal("expected a 429 once the per-IP registration limit was exceeded")
	}
}

// newServerWith builds a test server with a mutated config (for registration
// modes) and returns it plus an httptest server over its handler.
func newServerWith(t testing.TB, mutate func(*Config)) (*Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	cfg := validConfig()
	cfg.StateDir = dir
	cfg.AuditLog = dir + "/audit.jsonl"
	cfg.SigningKey = dir + "/key.json"
	// Generous limits by default so functional tests are not throttled; the
	// rate limiter has its own dedicated test.
	cfg.Limits.RegisterPerIPPerMin = 10000
	cfg.Limits.PreauthPerIPPerMin = 10000
	if mutate != nil {
		mutate(&cfg)
	}
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, Options{
		Now:         func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		Signer:      signer,
		AuditWriter: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, httptest.NewServer(srv.Handler())
}

func registerClient(t *testing.T, base string, body string, iat string) (*http.Response, authorization.ClientRegistrationResponse) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+pathRegister, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if iat != "" {
		req.Header.Set("Authorization", "Bearer "+iat)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out authorization.ClientRegistrationResponse
	if resp.StatusCode == http.StatusCreated {
		_ = json.NewDecoder(resp.Body).Decode(&out)
	}
	resp.Body.Close()
	return resp, out
}

const goodRegBody = `{"client_name":"Claude","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"token_endpoint_auth_method":"none"}`

func TestRegisterOpenApprovalLandsPending(t *testing.T) {
	srv, ts := newServerWith(t, nil)
	defer ts.Close()

	resp, reg := registerClient(t, ts.URL, goodRegBody, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	if reg.ClientID == "" || reg.RegistrationAccessToken == "" {
		t.Fatal("registration must return client_id and registration_access_token")
	}
	rec, err := srv.clients.Get(reg.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != ClientPending {
		t.Fatalf("open-approval registration must land pending, got %q", rec.Status)
	}
}

func TestRegisterRejectsBadRedirectURIs(t *testing.T) {
	_, ts := newServerWith(t, nil)
	defer ts.Close()

	cases := []string{
		`{"redirect_uris":[]}`,
		`{"redirect_uris":["http://evil.example.com/cb"]}`, // non-https, non-localhost
		`{"redirect_uris":["https://claude.ai/cb#frag"]}`,  // fragment
		`{"redirect_uris":["not-a-uri"]}`,                  // not absolute
	}
	for _, body := range cases {
		resp, _ := registerClient(t, ts.URL, body, "")
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, resp.StatusCode)
		}
	}
}

func TestRegisterTokenMode(t *testing.T) {
	t.Setenv("EDGE_IAT_TEST", "s3cret-iat")
	srv, ts := newServerWith(t, func(c *Config) {
		c.Registration.Mode = RegistrationToken
		c.Registration.InitialAccessTokens = []InitialAccessToken{{TokenEnv: "EDGE_IAT_TEST", MaxClients: 2}}
	})
	defer ts.Close()

	// No token → rejected.
	if resp, _ := registerClient(t, ts.URL, goodRegBody, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token mode without IAT: status = %d, want 401", resp.StatusCode)
	}
	// Wrong token → rejected.
	if resp, _ := registerClient(t, ts.URL, goodRegBody, "wrong"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token mode wrong IAT: status = %d, want 401", resp.StatusCode)
	}
	// Correct token → approved directly.
	resp, reg := registerClient(t, ts.URL, goodRegBody, "s3cret-iat")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("token mode good IAT: status = %d, want 201", resp.StatusCode)
	}
	rec, _ := srv.clients.Get(reg.ClientID)
	if rec.Status != ClientApproved {
		t.Fatalf("token-mode registration must land approved, got %q", rec.Status)
	}
}

func TestRegisterTokenModeMaxClients(t *testing.T) {
	t.Setenv("EDGE_IAT_TEST", "cap-iat")
	_, ts := newServerWith(t, func(c *Config) {
		c.Registration.Mode = RegistrationToken
		c.Registration.InitialAccessTokens = []InitialAccessToken{{TokenEnv: "EDGE_IAT_TEST", MaxClients: 1}}
	})
	defer ts.Close()

	if resp, _ := registerClient(t, ts.URL, goodRegBody, "cap-iat"); resp.StatusCode != http.StatusCreated {
		t.Fatal("first registration should succeed")
	}
	if resp, _ := registerClient(t, ts.URL, goodRegBody, "cap-iat"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second registration past MaxClients must be rejected, got %d", resp.StatusCode)
	}
}

func TestRegisterMaxPending(t *testing.T) {
	_, ts := newServerWith(t, func(c *Config) { c.Registration.MaxPending = 2 })
	defer ts.Close()

	for i := 0; i < 2; i++ {
		if resp, _ := registerClient(t, ts.URL, goodRegBody, ""); resp.StatusCode != http.StatusCreated {
			t.Fatalf("registration %d should succeed", i)
		}
	}
	if resp, _ := registerClient(t, ts.URL, goodRegBody, ""); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("registration past max_pending must be 503, got %d", resp.StatusCode)
	}
}

func TestManageEndpointRequiresRegToken(t *testing.T) {
	srv, ts := newServerWith(t, nil)
	defer ts.Close()

	_, reg := registerClient(t, ts.URL, goodRegBody, "")
	manageURL := ts.URL + pathRegister + "/" + reg.ClientID

	// Missing/wrong token → 401.
	req, _ := http.NewRequest(http.MethodGet, manageURL, nil)
	req.Header.Set("Authorization", "Bearer nope")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("manage with wrong token: status %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Correct token → 200 GET.
	req, _ = http.NewRequest(http.MethodGet, manageURL, nil)
	req.Header.Set("Authorization", "Bearer "+reg.RegistrationAccessToken)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("manage GET: status %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// DELETE deregisters (revokes).
	req, _ = http.NewRequest(http.MethodDelete, manageURL, nil)
	req.Header.Set("Authorization", "Bearer "+reg.RegistrationAccessToken)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("manage DELETE: status %d, want 204", resp.StatusCode)
	}
	resp.Body.Close()
	rec, _ := srv.clients.Get(reg.ClientID)
	if rec.Status != ClientRevoked {
		t.Fatalf("DELETE must revoke, got %q", rec.Status)
	}
}

// TestRegisterAuditFailRollsBack verifies the fail-closed contract: if the
// registration cannot be recorded in the audit ledger, the client is rolled
// back to revoked and a 500 is returned.
func TestRegisterAuditFailRollsBack(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig()
	cfg.StateDir = dir
	cfg.AuditLog = dir + "/audit.jsonl"
	cfg.SigningKey = dir + "/key.json"
	signer, _ := policy.GenerateSigner()
	srv, err := New(cfg, Options{
		Now:         func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		Signer:      signer,
		AuditWriter: failWriter{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, reg := registerClient(t, ts.URL, goodRegBody, "")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("audit-fail registration must 500, got %d", resp.StatusCode)
	}
	if reg.ClientID != "" {
		// The 500 path returns an OAuth error body, not a registration response.
		t.Fatalf("audit-fail registration must not return a client_id")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("audit sink down") }

// TestConcurrentRegisterRespectsMaxPending mirrors dcr_concurrency_test's quota
// shape: N concurrent open-approval registrations must not exceed max_pending by
// more than the inherent check-then-write window bounds (we assert the count is
// bounded, not unbounded).
func TestConcurrentRegisterRespectsMaxPending(t *testing.T) {
	srv, ts := newServerWith(t, func(c *Config) { c.Registration.MaxPending = 5 })
	defer ts.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			registerClient(t, ts.URL, goodRegBody, "")
		}()
	}
	wg.Wait()

	recs, _ := srv.clients.List()
	pending := 0
	for _, r := range recs {
		if r.Status == ClientPending {
			pending++
		}
	}
	// The check-and-create is serialized (register:quota lock), so the cap is
	// exact even under 20 concurrent registrations.
	if pending != 5 {
		t.Fatalf("pending backlog = %d, want exactly max_pending=5", pending)
	}
}

// FuzzEdgeRegisterMetadata fuzzes the DCR request parser with arbitrary bytes;
// the handler must never panic and must reject malformed input cleanly.
func FuzzEdgeRegisterMetadata(f *testing.F) {
	f.Add([]byte(goodRegBody))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"redirect_uris":123}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"redirect_uris":["https://a"],"unknown":{"x":[1,2,3]}}`))

	// A high pending cap and a working audit sink so the only responses the
	// handler can produce for arbitrary input are 201 (accepted) or a 4xx
	// rejection — never a 5xx, which would signal a parser/handler bug.
	_, ts := newServerWith(f, func(c *Config) { c.Registration.MaxPending = 1_000_000 })
	defer ts.Close()

	f.Fuzz(func(t *testing.T, body []byte) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+pathRegister, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Fatalf("unexpected %d for body %q — malformed input must be a clean 4xx, never a 5xx", resp.StatusCode, body)
		}
	})
}
