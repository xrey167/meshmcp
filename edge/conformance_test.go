package edge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/protocol/authorization"
)

// TestConformanceFullHandshake simulates a hosted MCP client (claude.ai) driving
// the entire flow against a real TLS edge server, using the SAME client-side
// discovery helpers the client implements: unauthenticated /mcp → 401 challenge
// → protected-resource metadata → authorization-server metadata → DCR → operator
// approval → authorize + PKCE → operator authz approval → code → token →
// initialize (session) → tools/call → refresh → expiry. It is the end-to-end
// proof that the edge speaks the contract claude.ai expects.
func TestConformanceFullHandshake(t *testing.T) {
	for _, mode := range []string{RegistrationOpenApproval, RegistrationToken} {
		t.Run(mode, func(t *testing.T) {
			runConformance(t, mode)
		})
	}
}

func runConformance(t *testing.T, regMode string) {
	dir := t.TempDir()

	// A mutable handler lets us learn the TLS server's URL (its own issuer) before
	// building the edge, so discovery documents point back at the test server.
	var mu sync.Mutex
	var inner http.Handler
	wrapper := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		h := inner
		mu.Unlock()
		if h == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		h.ServeHTTP(w, r)
	})
	ts := httptest.NewTLSServer(wrapper)
	defer ts.Close()
	client := ts.Client() // trusts the test cert

	cfg := validConfig()
	cfg.PublicURL = ts.URL // issuer == the test server
	cfg.StateDir = dir
	cfg.AuditLog = dir + "/audit.jsonl"
	cfg.SigningKey = dir + "/key.json"
	cfg.Limits.RegisterPerIPPerMin = 10000
	cfg.Limits.PreauthPerIPPerMin = 10000
	cfg.Limits.PerClientRPS = 10000
	cfg.Backend.Tools = []string{"search_*"}
	cfg.Backend.Policy = policyAllowSearch()
	cfg.OAuth.AccessTokenTTL = Duration(3 * time.Second) // short, so we can prove expiry
	if regMode == RegistrationToken {
		t.Setenv("CONF_IAT", "conf-iat-secret")
		cfg.Registration.Mode = RegistrationToken
		cfg.Registration.InitialAccessTokens = []InitialAccessToken{{TokenEnv: "CONF_IAT", MaxClients: 5}}
	}

	srv, err := New(cfg, Options{
		Now:         time.Now,
		Signer:      mustSigner(t),
		AuditWriter: &discardWriter{},
		DialBackend: startBackend(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	inner = srv.Handler()
	mu.Unlock()

	// 1. Unauthenticated /mcp → 401 with a resource-metadata pointer.
	resp := do(t, client, req(t, http.MethodPost, ts.URL+"/mcp", "", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth /mcp = %d, want 401", resp.StatusCode)
	}
	rmURL := authorization.ResourceMetadataURL(resp.Header.Get("WWW-Authenticate"))
	resp.Body.Close()
	if rmURL == "" {
		t.Fatal("401 must carry a resource_metadata pointer")
	}

	// 2. Fetch protected-resource metadata; confirm the discovery-URL helper agrees.
	if urls, err := authorization.ProtectedResourceMetadataURLs(ts.URL + "/mcp"); err != nil || len(urls) == 0 {
		t.Fatalf("client helper produced no PRM candidate URLs: %v", err)
	}
	var prm authorization.ProtectedResourceMetadata
	getJSON(t, client, rmURL, &prm)
	if len(prm.AuthorizationServers) == 0 {
		t.Fatal("PRM must advertise an authorization server")
	}

	// 3. Fetch authorization-server metadata via the client's discovery order.
	var asMeta authorization.AuthorizationServerMetadata
	found := false
	asURLs, err := authorization.AuthorizationServerMetadataURLs(prm.AuthorizationServers[0])
	if err != nil {
		t.Fatalf("AS metadata URL helper: %v", err)
	}
	for _, u := range asURLs {
		r := do(t, client, req(t, http.MethodGet, u, "", ""))
		if r.StatusCode == http.StatusOK {
			json.NewDecoder(r.Body).Decode(&asMeta)
			r.Body.Close()
			found = true
			break
		}
		r.Body.Close()
	}
	if !found || !asMeta.SupportsPKCE() {
		t.Fatalf("AS metadata not discoverable or missing PKCE: found=%v %+v", found, asMeta)
	}

	// 4. Dynamic Client Registration.
	regBody := `{"client_name":"claude.ai","redirect_uris":["` + testRedirect + `"],"token_endpoint_auth_method":"none"}`
	regReq := req(t, http.MethodPost, asMeta.RegistrationEndpoint, "", regBody)
	if regMode == RegistrationToken {
		regReq.Header.Set("Authorization", "Bearer conf-iat-secret")
	}
	rresp := do(t, client, regReq)
	if rresp.StatusCode != http.StatusCreated {
		t.Fatalf("DCR = %d, want 201", rresp.StatusCode)
	}
	var reg authorization.ClientRegistrationResponse
	json.NewDecoder(rresp.Body).Decode(&reg)
	rresp.Body.Close()
	if reg.ClientID == "" {
		t.Fatal("DCR returned no client_id")
	}

	// 5. Operator approves the client (open-approval mode requires it; token mode
	// already approved, and approving again is a no-op).
	if _, err := srv.clients.Approve(reg.ClientID, "operator"); err != nil {
		t.Fatalf("approve client: %v", err)
	}

	// 6. Authorize with PKCE → consent page.
	verifier, challenge := pkcePair()
	authzURL := asMeta.AuthorizationEndpoint + "?" + url.Values{
		"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "scope": {"mcp"}, "state": {"conf-state"},
	}.Encode()
	ar := do(t, client, req(t, http.MethodGet, authzURL, "", ""))
	ar.Body.Close()
	if ar.StatusCode != http.StatusOK {
		t.Fatalf("authorize = %d, want 200 consent page", ar.StatusCode)
	}

	// 7. Operator approves the authorization request.
	pend, _ := srv.authz.ListPending()
	if len(pend) == 0 {
		t.Fatal("no pending authz")
	}
	reqID := pend[0].RequestID
	if err := srv.authz.Approve(reqID, "operator"); err != nil {
		t.Fatal(err)
	}

	// 8. Poll status → code, extract from the redirect.
	sresp := do(t, client, req(t, http.MethodGet, asMeta.AuthorizationEndpoint+"/status?request_id="+reqID, "", ""))
	var sd map[string]string
	json.NewDecoder(sresp.Body).Decode(&sd)
	sresp.Body.Close()
	redir, _ := url.Parse(sd["redirect"])
	code := redir.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %v", sd)
	}
	if redir.Query().Get("state") != "conf-state" {
		t.Fatal("state not echoed back")
	}

	// 9. Token exchange (public client, auth=none).
	tresp := do(t, client, formReq(t, asMeta.TokenEndpoint, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {reg.ClientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	}))
	if tresp.StatusCode != http.StatusOK {
		t.Fatalf("token = %d, want 200", tresp.StatusCode)
	}
	var tok authorization.TokenResponse
	json.NewDecoder(tresp.Body).Decode(&tok)
	tresp.Body.Close()
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatal("token response missing access/refresh token")
	}

	// 10. initialize (opens a session), then a governed tools/call.
	ir := do(t, client, req(t, http.MethodPost, ts.URL+"/mcp", tok.AccessToken, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	sid := ir.Header.Get(headerSessionID)
	ir.Body.Close()
	if sid == "" {
		t.Fatal("initialize issued no session id")
	}
	cr := do(t, client, reqSession(t, ts.URL+"/mcp", tok.AccessToken, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_docs","arguments":{"q":"x"}}}`))
	var callResp map[string]any
	json.NewDecoder(cr.Body).Decode(&callResp)
	cr.Body.Close()
	if callResp["error"] != nil {
		t.Fatalf("governed tool call failed: %v", callResp["error"])
	}

	// 11. Refresh rotates to a new token set.
	rf := do(t, client, formReq(t, asMeta.TokenEndpoint, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {reg.ClientID},
	}))
	var tok2 authorization.TokenResponse
	json.NewDecoder(rf.Body).Decode(&tok2)
	rf.Body.Close()
	if rf.StatusCode != http.StatusOK || tok2.AccessToken == "" {
		t.Fatalf("refresh failed: %d", rf.StatusCode)
	}

	// 12. After the access-token TTL, the original token is rejected (401).
	time.Sleep(3200 * time.Millisecond)
	er := do(t, client, req(t, http.MethodPost, ts.URL+"/mcp", tok.AccessToken, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`))
	er.Body.Close()
	if er.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired token must 401, got %d", er.StatusCode)
	}
}

// --- small HTTP helpers for the conformance client ---

func req(t *testing.T, method, url, token, body string) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func reqSession(t *testing.T, url, token, sid, body string) *http.Request {
	r := req(t, http.MethodPost, url, token, body)
	r.Header.Set(headerSessionID, sid)
	return r
}

func formReq(t *testing.T, url string, form url.Values) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func do(t *testing.T, c *http.Client, r *http.Request) *http.Response {
	t.Helper()
	resp, err := c.Do(r)
	if err != nil {
		t.Fatalf("%s %s: %v", r.Method, r.URL, err)
	}
	return resp
}

func getJSON(t *testing.T, c *http.Client, url string, out any) {
	t.Helper()
	resp := do(t, c, req(t, http.MethodGet, url, "", ""))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}
