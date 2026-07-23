package edge

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/protocol/authorization"
)

// pkcePair returns a random verifier and its S256 challenge.
func pkcePair() (verifier, challenge string) {
	verifier = randToken()
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// approvedClient registers a client and drives it to approved, returning its id.
func approvedClient(t *testing.T, srv *Server, ts *httptest.Server, redirect string) string {
	t.Helper()
	body := `{"client_name":"Claude","redirect_uris":["` + redirect + `"],"token_endpoint_auth_method":"none"}`
	_, reg := registerClient(t, ts.URL, body, "")
	if _, err := srv.clients.Approve(reg.ClientID, "op"); err != nil {
		t.Fatal(err)
	}
	return reg.ClientID
}

// runAuthorize drives the authorize + operator-approve + status-poll flow and
// returns the authorization code from the redirect.
func runAuthorize(t *testing.T, srv *Server, ts *httptest.Server, clientID, redirect, challenge, state string) string {
	t.Helper()
	authzURL := ts.URL + pathAuthorize + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"mcp"},
		"state":                 {state},
	}.Encode()
	resp, err := http.Get(authzURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize page status = %d, want 200 (consent page)", resp.StatusCode)
	}

	// Find the pending request and approve it as the operator would.
	pend, _ := srv.authz.ListPending()
	if len(pend) == 0 {
		t.Fatal("no pending authorization request created")
	}
	reqID := pend[0].RequestID
	if err := srv.authz.Approve(reqID, "op"); err != nil {
		t.Fatal(err)
	}

	// Poll status → approved + redirect with code.
	sresp, err := http.Get(ts.URL + pathAuthorizeStat + "?request_id=" + reqID)
	if err != nil {
		t.Fatal(err)
	}
	var sd map[string]string
	json.NewDecoder(sresp.Body).Decode(&sd)
	sresp.Body.Close()
	if sd["status"] != "approved" || sd["redirect"] == "" {
		t.Fatalf("status poll = %v, want approved+redirect", sd)
	}
	ru, _ := url.Parse(sd["redirect"])
	if got := ru.Query().Get("state"); got != state {
		t.Fatalf("redirect state = %q, want %q", got, state)
	}
	code := ru.Query().Get("code")
	if code == "" {
		t.Fatal("redirect carries no code")
	}
	return code
}

func postToken(t *testing.T, base string, form url.Values) (*http.Response, authorization.TokenResponse) {
	t.Helper()
	resp, err := http.PostForm(base+pathToken, form)
	if err != nil {
		t.Fatal(err)
	}
	var tok authorization.TokenResponse
	if resp.StatusCode == http.StatusOK {
		json.NewDecoder(resp.Body).Decode(&tok)
	}
	resp.Body.Close()
	return resp, tok
}

const testRedirect = "https://claude.ai/api/mcp/auth_callback"

func TestAuthorizationCodeFlowHappyPath(t *testing.T) {
	srv, ts := newServerWith(t, nil)
	defer ts.Close()
	clientID := approvedClient(t, srv, ts, testRedirect)
	verifier, challenge := pkcePair()

	code := runAuthorize(t, srv, ts, clientID, testRedirect, challenge, "xyz-state")

	resp, tok := postToken(t, ts.URL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d, want 200", resp.StatusCode)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" || tok.TokenType != authorization.SchemeBearer {
		t.Fatalf("bad token response: %+v", tok)
	}
	// The access token maps to a capability that verifies against the signer for
	// a permitted tool and the configured backend.
	acc, err := srv.tokens.getAccess(tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.verify.Verify(acc.Capability, oauthIdentity(clientID), srv.cfg.Backend.Name, "search_docs"); err != nil {
		t.Fatalf("minted capability must verify for a permitted tool: %v", err)
	}
}

func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	srv, ts := newServerWith(t, nil)
	defer ts.Close()
	clientID := approvedClient(t, srv, ts, testRedirect)
	verifier, challenge := pkcePair()
	code := runAuthorize(t, srv, ts, clientID, testRedirect, challenge, "s")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}
	if resp, _ := postToken(t, ts.URL, form); resp.StatusCode != http.StatusOK {
		t.Fatal("first code use should succeed")
	}
	if resp, _ := postToken(t, ts.URL, form); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("second code use must be invalid_grant (400), got %d", resp.StatusCode)
	}
}

func TestAuthorizationCodeRejections(t *testing.T) {
	srv, ts := newServerWith(t, nil)
	defer ts.Close()
	clientID := approvedClient(t, srv, ts, testRedirect)
	verifier, challenge := pkcePair()

	newCode := func() string { return runAuthorize(t, srv, ts, clientID, testRedirect, challenge, "s") }

	// Wrong PKCE verifier.
	if resp, _ := postToken(t, ts.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {newCode()}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {"wrong-" + verifier},
	}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong PKCE verifier must be rejected, got %d", resp.StatusCode)
	}
	// Wrong redirect_uri.
	if resp, _ := postToken(t, ts.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {newCode()}, "client_id": {clientID},
		"redirect_uri": {"https://evil/cb"}, "code_verifier": {verifier},
	}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong redirect_uri must be rejected, got %d", resp.StatusCode)
	}
	// Wrong client_id.
	if resp, _ := postToken(t, ts.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {newCode()}, "client_id": {"edge-other"},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong client_id must be rejected, got %d", resp.StatusCode)
	}
}

func TestPublicClientTokenAuthNone(t *testing.T) {
	// A token request with NO Authorization header (public client, auth=none)
	// must be accepted.
	srv, ts := newServerWith(t, nil)
	defer ts.Close()
	clientID := approvedClient(t, srv, ts, testRedirect)
	verifier, challenge := pkcePair()
	code := runAuthorize(t, srv, ts, clientID, testRedirect, challenge, "s")

	req, _ := http.NewRequest(http.MethodPost, ts.URL+pathToken, strings.NewReader(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// deliberately no Authorization header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public-client token request must succeed without auth, got %d", resp.StatusCode)
	}
}

func TestRefreshRotationAndReuseRevokesFamily(t *testing.T) {
	srv, ts := newServerWith(t, nil)
	defer ts.Close()
	clientID := approvedClient(t, srv, ts, testRedirect)
	verifier, challenge := pkcePair()
	code := runAuthorize(t, srv, ts, clientID, testRedirect, challenge, "s")

	_, tok := postToken(t, ts.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	refresh1 := tok.RefreshToken

	// Rotate: refresh1 → new access + refresh2.
	resp, tok2 := postToken(t, ts.URL, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh1}, "client_id": {clientID},
	})
	if resp.StatusCode != http.StatusOK || tok2.RefreshToken == "" || tok2.RefreshToken == refresh1 {
		t.Fatalf("refresh rotation failed: status=%d resp=%+v", resp.StatusCode, tok2)
	}

	// Advance past the replay grace, then reuse refresh1 → family revocation.
	base := srv.now()
	srv.now = func() time.Time { return base.Add(refreshReplayGrace + time.Second) }
	if resp, _ := postToken(t, ts.URL, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh1}, "client_id": {clientID},
	}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("reuse of a rotated refresh token must be rejected, got %d", resp.StatusCode)
	}
	// The successor (refresh2) is now revoked too (family teardown).
	if resp, _ := postToken(t, ts.URL, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok2.RefreshToken}, "client_id": {clientID},
	}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("after reuse detection the whole family must be revoked, got %d", resp.StatusCode)
	}
}

func TestPendingClientCannotAuthorize(t *testing.T) {
	srv, ts := newServerWith(t, nil)
	defer ts.Close()
	// Register but do NOT approve.
	body := `{"client_name":"Claude","redirect_uris":["` + testRedirect + `"]}`
	_, reg := registerClient(t, ts.URL, body, "")

	_, challenge := pkcePair()
	authzURL := ts.URL + pathAuthorize + "?" + url.Values{
		"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()
	resp, _ := http.Get(authzURL)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("pending client authorize must be refused (400 error page), got %d", resp.StatusCode)
	}
	_ = srv
}

func TestAuthorizeRejectsNonS256AndBadRedirect(t *testing.T) {
	srv, ts := newServerWith(t, nil)
	defer ts.Close()
	clientID := approvedClient(t, srv, ts, testRedirect)

	// Unregistered redirect → error page (never a redirect).
	resp, _ := http.Get(ts.URL + pathAuthorize + "?" + url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://evil/cb"},
		"code_challenge": {"x"}, "code_challenge_method": {"S256"},
	}.Encode())
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unregistered redirect must be a 400 error page, got %d", resp.StatusCode)
	}

	// Missing PKCE → error redirect back to the (valid) redirect_uri.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r2, err := client.Get(ts.URL + pathAuthorize + "?" + url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusFound {
		t.Fatalf("missing PKCE must be an error redirect (302), got %d", r2.StatusCode)
	}
	loc, _ := url.Parse(r2.Header.Get("Location"))
	if loc.Query().Get("error") == "" {
		t.Fatal("error redirect must carry an error parameter")
	}
}

// TestConcurrentCodeRedemption ensures exactly one of N concurrent redemptions
// of the same code wins (claim-by-rename single-use).
func TestConcurrentCodeRedemption(t *testing.T) {
	srv, ts := newServerWith(t, nil)
	defer ts.Close()
	clientID := approvedClient(t, srv, ts, testRedirect)
	verifier, challenge := pkcePair()
	code := runAuthorize(t, srv, ts, clientID, testRedirect, challenge, "s")

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp, _ := postToken(t, ts.URL, form); resp.StatusCode == http.StatusOK {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one concurrent code redemption should win, got %d", wins)
	}
}

func TestPKCEVerifyUnit(t *testing.T) {
	v, c := pkcePair()
	if !pkceVerify(v, c) {
		t.Fatal("valid pair should verify")
	}
	if pkceVerify("other", c) {
		t.Fatal("wrong verifier must not verify")
	}
	if pkceVerify("", c) || pkceVerify(v, "") {
		t.Fatal("empty inputs must not verify")
	}
}
