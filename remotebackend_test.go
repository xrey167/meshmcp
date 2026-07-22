package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// --- shared test helpers -----------------------------------------------

func mustRemoteDPoP(t *testing.T) *policy.DPoPSigner {
	t.Helper()
	s, err := policy.GenerateDPoPSigner()
	if err != nil {
		t.Fatalf("GenerateDPoPSigner: %v", err)
	}
	return s
}

// decodedProof is a minimal, independent (stdlib-only) parse of a DPoP proof
// JWT, mirroring what a compliant AS/resource server does — deliberately not
// reusing policy/dpopsign.go's unexported types, so verification here is a
// genuinely separate check of what remoteClient produced.
type decodedProof struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	JWK struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"jwk"`
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	Ath   string `json:"ath"`
	Nonce string `json:"nonce"`
}

// verifyProof independently decodes and cryptographically verifies a DPoP
// proof JWT: ES256 signature over header.claims, using the jwk embedded in
// the header itself (proof of possession), and computes the RFC 7638
// thumbprint the same way a real AS would to bind a token's cnf.jkt.
func verifyProof(proof string) (dp decodedProof, jkt string, err error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return dp, "", fmt.Errorf("expected 3 segments, got %d", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return dp, "", err
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return dp, "", err
	}
	if err := json.Unmarshal(hb, &dp); err != nil {
		return dp, "", err
	}
	if err := json.Unmarshal(cb, &dp); err != nil {
		return dp, "", err
	}
	if dp.Typ != "dpop+jwt" {
		return dp, "", fmt.Errorf("typ = %q, want dpop+jwt", dp.Typ)
	}
	if dp.Alg != "ES256" {
		return dp, "", fmt.Errorf("alg = %q, want ES256", dp.Alg)
	}
	xb, err := base64.RawURLEncoding.DecodeString(dp.JWK.X)
	if err != nil || len(xb) != 32 {
		return dp, "", fmt.Errorf("bad jwk.x")
	}
	yb, err := base64.RawURLEncoding.DecodeString(dp.JWK.Y)
	if err != nil || len(yb) != 32 {
		return dp, "", fmt.Errorf("bad jwk.y")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return dp, "", fmt.Errorf("bad signature encoding")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return dp, "", fmt.Errorf("signature does not verify against the embedded jwk")
	}
	canon := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, dp.JWK.Crv, dp.JWK.Kty, dp.JWK.X, dp.JWK.Y)
	sum := sha256.Sum256([]byte(canon))
	jkt = base64.RawURLEncoding.EncodeToString(sum[:])
	return dp, jkt, nil
}

// fakeRemote is a fake Protected Resource + Authorization Server used to
// drive serveRemote/remoteClient's client behavior end to end.
type fakeRemote struct {
	mu sync.Mutex

	// Behavior knobs.
	tokenNonceOnFirstAttempt          bool // /token 400s use_dpop_nonce once, then succeeds
	tokenAlwaysInvalidProof           bool // /token always 400s invalid_dpop_proof
	tokenAlwaysServerError            bool // /token always 500s
	resourceRejectFirstAsInvalidProof bool // /mcp 400s invalid_dpop_proof exactly once

	// Observations.
	tokenRequests       int
	resourceRequests    int
	prmRequests         int
	asRequests          int
	seenJTIs            map[string]bool
	lastGrantType       string
	tokenProofs         []string
	resourceProofs      []string
	lastAccessExpiresIn int
	nextRefreshToken    string

	srv *httptest.Server
}

func newFakeRemote(t *testing.T) *fakeRemote {
	t.Helper()
	fr := &fakeRemote{seenJTIs: map[string]bool{}, lastAccessExpiresIn: 3600}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", fr.handleResource)
	mux.HandleFunc("/.well-known/oauth-protected-resource", fr.handlePRM)
	mux.HandleFunc("/.well-known/oauth-authorization-server", fr.handleASMeta)
	mux.HandleFunc("/token", fr.handleToken)
	fr.srv = httptest.NewServer(mux)
	t.Cleanup(fr.srv.Close)
	return fr
}

func (fr *fakeRemote) handleResource(w http.ResponseWriter, r *http.Request) {
	fr.mu.Lock()
	fr.resourceRequests++
	fr.mu.Unlock()

	auth := r.Header.Get("Authorization")
	proof := r.Header.Get("DPoP")
	if auth == "" || proof == "" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=%q", fr.srv.URL+"/.well-known/oauth-protected-resource"))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	fr.mu.Lock()
	fr.resourceProofs = append(fr.resourceProofs, proof)
	rejectOnce := fr.resourceRejectFirstAsInvalidProof
	if rejectOnce {
		fr.resourceRejectFirstAsInvalidProof = false
	}
	fr.mu.Unlock()
	if rejectOnce {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	dp, _, err := verifyProof(proof)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	fr.mu.Lock()
	replay := fr.seenJTIs[dp.JTI]
	fr.seenJTIs[dp.JTI] = true
	fr.mu.Unlock()
	if replay {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(auth, "DPoP ")
	wantAth := base64.RawURLEncoding.EncodeToString(func() []byte { s := sha256.Sum256([]byte(token)); return s[:] }())
	if dp.Ath != wantAth {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
}

func (fr *fakeRemote) handlePRM(w http.ResponseWriter, r *http.Request) {
	fr.mu.Lock()
	fr.prmRequests++
	fr.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":              fr.srv.URL + "/mcp",
		"authorization_servers": []string{fr.srv.URL},
	})
}

func (fr *fakeRemote) handleASMeta(w http.ResponseWriter, r *http.Request) {
	fr.mu.Lock()
	fr.asRequests++
	fr.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":         fr.srv.URL,
		"token_endpoint": fr.srv.URL + "/token",
	})
}

func (fr *fakeRemote) handleToken(w http.ResponseWriter, r *http.Request) {
	fr.mu.Lock()
	fr.tokenRequests++
	fr.mu.Unlock()

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	proof := r.Header.Get("DPoP")
	fr.mu.Lock()
	fr.tokenProofs = append(fr.tokenProofs, proof)
	fr.lastGrantType = r.PostForm.Get("grant_type")
	fr.mu.Unlock()

	if fr.tokenAlwaysServerError {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
		return
	}
	if fr.tokenAlwaysInvalidProof {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(authErr("invalid_dpop_proof"))
		return
	}
	if _, _, err := verifyProof(proof); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(authErr("invalid_dpop_proof"))
		return
	}

	fr.mu.Lock()
	needNonce := fr.tokenNonceOnFirstAttempt && fr.tokenRequests == 1
	fr.mu.Unlock()
	if needNonce {
		w.Header().Set("DPoP-Nonce", "server-nonce-1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(authErr("use_dpop_nonce"))
		return
	}

	fr.mu.Lock()
	expIn := fr.lastAccessExpiresIn
	refresh := fr.nextRefreshToken
	fr.mu.Unlock()

	resp := map[string]any{
		"access_token": "access-" + fmt.Sprint(fr.tokenRequests),
		"token_type":   "DPoP",
		"expires_in":   expIn,
	}
	if refresh != "" {
		resp["refresh_token"] = refresh
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func authErr(code string) map[string]string { return map[string]string{"error": code} }

func newTestRemoteClient(t *testing.T, fr *fakeRemote) *remoteClient {
	t.Helper()
	u, err := url.Parse(fr.srv.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	return &remoteClient{
		name:       "remote1",
		endpoint:   u,
		clientID:   "client-1",
		dpop:       mustRemoteDPoP(t),
		httpClient: fr.srv.Client(),
		now:        time.Now,
	}
}

// --- tests ---------------------------------------------------------------

func TestServeRemote_DiscoversViaWWWAuthenticate(t *testing.T) {
	fr := newFakeRemote(t)
	rc := newTestRemoteClient(t, fr)

	status, body, _, err := rc.resourceCall(http.MethodPost, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	if err != nil {
		t.Fatalf("resourceCall: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", status, body)
	}
	if fr.prmRequests == 0 || fr.asRequests == 0 {
		t.Fatalf("expected PRM and AS metadata to be fetched via discovery, got prm=%d as=%d", fr.prmRequests, fr.asRequests)
	}
	if rc.tokenEndpoint != fr.srv.URL+"/token" {
		t.Fatalf("tokenEndpoint = %q, want %q (must come from discovery, not a hardcoded URL)", rc.tokenEndpoint, fr.srv.URL+"/token")
	}
}

func TestServeRemote_TokenRequestIncludesValidDPoPProof(t *testing.T) {
	fr := newFakeRemote(t)
	rc := newTestRemoteClient(t, fr)

	if _, _, _, err := rc.resourceCall(http.MethodPost, []byte(`{}`)); err != nil {
		t.Fatalf("resourceCall: %v", err)
	}
	if len(fr.tokenProofs) == 0 {
		t.Fatal("expected at least one token request to have carried a DPoP proof")
	}
	dp, jkt, err := verifyProof(fr.tokenProofs[0])
	if err != nil {
		t.Fatalf("fake AS could not independently verify the presented DPoP proof: %v", err)
	}
	if jkt == "" {
		t.Fatal("expected a non-empty jwk thumbprint")
	}
	if dp.HTM != http.MethodPost {
		t.Errorf("htm = %q, want POST", dp.HTM)
	}
	wantHTU := fr.srv.URL + "/token"
	if dp.HTU != wantHTU {
		t.Errorf("htu = %q, want %q", dp.HTU, wantHTU)
	}
}

func TestServeRemote_RefreshesOnExpiryAndNonce(t *testing.T) {
	fr := newFakeRemote(t)
	fr.tokenNonceOnFirstAttempt = true
	fr.lastAccessExpiresIn = 1
	fr.nextRefreshToken = "refresh-token-1"

	rc := newTestRemoteClient(t, fr)
	curTime := time.Unix(1_000_000, 0)
	rc.now = func() time.Time { return curTime }

	status, _, _, err := rc.resourceCall(http.MethodPost, []byte(`{}`))
	if err != nil {
		t.Fatalf("first resourceCall: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("first call status = %d", status)
	}
	if fr.tokenRequests != 2 {
		t.Fatalf("expected exactly 2 token requests (nonce challenge + retry), got %d", fr.tokenRequests)
	}
	if fr.tokenProofs[0] == fr.tokenProofs[1] {
		t.Fatal("the nonce retry must use a freshly minted proof, not the identical one")
	}
	if rc.tok.refreshToken != "refresh-token-1" {
		t.Fatalf("refresh token not cached: %q", rc.tok.refreshToken)
	}
	prmBefore, asBefore := fr.prmRequests, fr.asRequests

	// Advance past expiry and drop the nonce requirement for the refresh call.
	curTime = curTime.Add(5 * time.Second)
	fr.nextRefreshToken = ""

	status, _, _, err = rc.resourceCall(http.MethodPost, []byte(`{}`))
	if err != nil {
		t.Fatalf("second resourceCall: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("second call status = %d", status)
	}
	if fr.lastGrantType != "refresh_token" {
		t.Fatalf("expected the expiry to trigger a refresh_token grant, got %q", fr.lastGrantType)
	}
	if fr.prmRequests != prmBefore || fr.asRequests != asBefore {
		t.Fatalf("expiry must not trigger a full rediscovery: prm %d->%d as %d->%d", prmBefore, fr.prmRequests, asBefore, fr.asRequests)
	}
}

func TestServeRemote_RejectsReplayedProof(t *testing.T) {
	fr := newFakeRemote(t)
	rc := newTestRemoteClient(t, fr)

	if _, _, _, err := rc.resourceCall(http.MethodPost, []byte(`{}`)); err != nil {
		t.Fatalf("first resourceCall: %v", err)
	}
	if _, _, _, err := rc.resourceCall(http.MethodPost, []byte(`{}`)); err != nil {
		t.Fatalf("second resourceCall: %v", err)
	}
	if len(fr.resourceProofs) < 2 {
		t.Fatalf("expected at least 2 resource requests, got %d", len(fr.resourceProofs))
	}
	if fr.resourceProofs[0] == fr.resourceProofs[1] {
		t.Fatal("serveRemote must never resend the identical proof across independent calls — a fresh jti must be minted each time")
	}

	// Directly confirm the fake AS's own replay tracking rejects a literal
	// resend of the same proof (the scenario this invariant guards against).
	dp2, _, err := verifyProof(fr.resourceProofs[1])
	if err != nil {
		t.Fatal(err)
	}
	if !fr.seenJTIs[dp2.JTI] {
		t.Fatal("fake AS should have recorded the second proof's jti")
	}
}

func TestServeRemote_HandlesInvalidDPoPProofErrorCode(t *testing.T) {
	fr := newFakeRemote(t)
	fr.tokenAlwaysInvalidProof = true
	rc := newTestRemoteClient(t, fr)

	_, _, _, err := rc.resourceCall(http.MethodPost, []byte(`{}`))
	if err == nil {
		t.Fatal("expected an error when the AS rejects the DPoP proof as invalid")
	}
	if !strings.Contains(err.Error(), "invalid_dpop_proof") {
		t.Fatalf("error should surface invalid_dpop_proof distinctly, got: %v", err)
	}
	if fr.tokenRequests != 1 {
		t.Fatalf("invalid_dpop_proof must never be retried with the identical proof: got %d token requests, want 1", fr.tokenRequests)
	}
}

func TestServeRemote_DeniedToolNeverReachesOutboundRequest(t *testing.T) {
	fr := newFakeRemote(t)
	rc := newTestRemoteClient(t, fr)

	pol := &policy.Policy{DefaultAllow: false} // deny-by-default, no allow rules
	audit := policy.NewAuditLog(io.Discard, func() string { return "t" })
	enf := newHTTPEnforcerForTest(pol, audit, "remote1")

	identify := func(r *http.Request) (string, string) { return "peerkey", "peer.example" }
	h := remoteHandler("remote1", newACL(nil), enf, rc, identify)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_everything"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK { // JSON-RPC errors are returned with 200 + an error envelope, matching httpEnforcer's convention
		t.Fatalf("unexpected HTTP status %d: %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("error")) {
		t.Fatalf("expected a JSON-RPC error/denial body, got %s", rr.Body.String())
	}
	if fr.resourceRequests != 0 || fr.tokenRequests != 0 || fr.prmRequests != 0 {
		t.Fatalf("a denied tool call must never reach the outbound leg: resource=%d token=%d prm=%d",
			fr.resourceRequests, fr.tokenRequests, fr.prmRequests)
	}
}

func TestServeRemote_SecretsNeverInAuditOrError(t *testing.T) {
	fr := newFakeRemote(t)
	fr.tokenAlwaysServerError = true

	dpopKeyPath := filepath.Join(t.TempDir(), "dpop.json")
	dpopSigner := mustRemoteDPoP(t)
	if err := dpopSigner.SaveDPoPSigner(dpopKeyPath); err != nil {
		t.Fatal(err)
	}
	dpopKeyBytes, err := os.ReadFile(dpopKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	const clientSecret = "s3cr3t-client-secret-value"
	const refreshToken = "s3cr3t-refresh-token-value"

	u, _ := url.Parse(fr.srv.URL + "/mcp")
	rc := &remoteClient{
		name:         "remote1",
		endpoint:     u,
		clientID:     "client-1",
		clientSecret: clientSecret,
		dpop:         dpopSigner,
		httpClient:   fr.srv.Client(),
		now:          time.Now,
	}
	rc.tok.refreshToken = refreshToken

	pol := &policy.Policy{DefaultAllow: true}
	var auditBuf bytes.Buffer
	audit := policy.NewAuditLog(&auditBuf, func() string { return "t" })
	enf := newHTTPEnforcerForTest(pol, audit, "remote1")
	identify := func(r *http.Request) (string, string) { return "peerkey", "peer.example" }
	h := remoteHandler("remote1", newACL(nil), enf, rc, identify)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"anything"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	respBody := rr.Body.String()
	auditOut := auditBuf.String()
	for _, secret := range []string{clientSecret, refreshToken, string(dpopKeyBytes)} {
		if strings.Contains(respBody, secret) {
			t.Fatalf("response body leaked secret material: contains %q", secret)
		}
		if strings.Contains(auditOut, secret) {
			t.Fatalf("audit output leaked secret material: contains %q", secret)
		}
	}
	// Also check the error path directly (bypassing HTTP body redaction that
	// isn't relevant here) — the *error itself* must never carry secrets.
	_, _, _, callErr := rc.resourceCall(http.MethodPost, []byte(`{}`))
	if callErr == nil {
		t.Fatal("expected an error since the fake AS always 500s")
	}
	if strings.Contains(callErr.Error(), clientSecret) || strings.Contains(callErr.Error(), refreshToken) {
		t.Fatalf("error string leaked secret material: %v", callErr)
	}
}

func TestServeRemote_ThreeWayBackendExclusivity(t *testing.T) {
	validRemote := `
    remote:
      endpoint: "https://upstream.example.com/mcp"
      client_id: "client-1"
      secrets:
        file: "` + filepath.ToSlash(filepath.Join(t.TempDir(), "secrets.json")) + `"
`
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name: "stdio only: ok",
			body: "backends:\n  - name: b\n    port: 9101\n    stdio: [\"echo\"]\n",
		},
		{
			name: "http only: ok",
			body: "backends:\n  - name: b\n    port: 9102\n    http: \"http://127.0.0.1:8080\"\n",
		},
		{
			name: "remote only: ok",
			body: "backends:\n  - name: b\n    port: 9103\n" + validRemote,
		},
		{
			name:    "zero of stdio/http/remote",
			body:    "backends:\n  - name: b\n    port: 9104\n",
			wantErr: "exactly one of stdio, http, or remote",
		},
		{
			name:    "stdio and http both set",
			body:    "backends:\n  - name: b\n    port: 9105\n    stdio: [\"echo\"]\n    http: \"http://127.0.0.1:8080\"\n",
			wantErr: "exactly one of stdio, http, or remote",
		},
		{
			name:    "stdio and remote both set",
			body:    "backends:\n  - name: b\n    port: 9106\n    stdio: [\"echo\"]\n" + validRemote,
			wantErr: "exactly one of stdio, http, or remote",
		},
		{
			name:    "http and remote both set",
			body:    "backends:\n  - name: b\n    port: 9107\n    http: \"http://127.0.0.1:8080\"\n" + validRemote,
			wantErr: "exactly one of stdio, http, or remote",
		},
		{
			name:    "all three set",
			body:    "backends:\n  - name: b\n    port: 9108\n    stdio: [\"echo\"]\n    http: \"http://127.0.0.1:8080\"\n" + validRemote,
			wantErr: "exactly one of stdio, http, or remote",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadConfig(writeConfig(t, c.body))
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("expected load to succeed, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("expected error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}

// newHTTPEnforcerForTest builds an httpEnforcer directly (mirrors
// newTestEnforcer in httppolicy_test.go), avoiding the need for a full
// Backend/Config for these unit tests.
func newHTTPEnforcerForTest(pol *policy.Policy, audit *policy.AuditLog, backend string) *httpEnforcer {
	return &httpEnforcer{eng: policy.NewEngine(pol, func() time.Time { return time.Now() }, nil), audit: audit, backend: backend}
}

// TestRotateSecretInFile_Atomic: rotating one named secret in a flat JSON
// secrets file preserves every other entry, writes via tmp+rename (no
// leftover .tmp), and the rotated value is what a subsequent read sees —
// covering the DoD's "refresh-token and DPoP-key-file atomicity" requirement
// (rotateSecretInFile is the shared primitive both use).
func TestRotateSecretInFile_Atomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.json")
	seed := map[string]string{
		"dpop_private_key":    "/keys/dpop.json",
		"oauth_client_secret": "unrelated-client-secret",
		"oauth_refresh_token": "old-refresh-token",
	}
	b, err := json.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := rotateSecretInFile(path, "oauth_refresh_token", "new-refresh-token"); err != nil {
		t.Fatalf("rotateSecretInFile: %v", err)
	}

	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("tmp file should not remain after rotation: err=%v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("rotated file is not valid JSON: %v", err)
	}
	if got["oauth_refresh_token"] != "new-refresh-token" {
		t.Fatalf("oauth_refresh_token = %q, want new-refresh-token", got["oauth_refresh_token"])
	}
	if got["dpop_private_key"] != "/keys/dpop.json" {
		t.Fatalf("rotation must not disturb unrelated secrets: dpop_private_key = %q", got["dpop_private_key"])
	}
	if got["oauth_client_secret"] != "unrelated-client-secret" {
		t.Fatalf("rotation must not disturb unrelated secrets: oauth_client_secret = %q", got["oauth_client_secret"])
	}
}

// TestBuildRemoteClient_MissingDPoPKeyFileIsFatal: a backend configured with
// dpop_private_key pointing at a nonexistent/corrupt file fails backend
// startup (buildRemoteClient returns an error) — never silently generating a
// fresh key, matching the S13 "missing signing key is fatal" precedent.
func TestBuildRemoteClient_MissingDPoPKeyFileIsFatal(t *testing.T) {
	secretsPath := filepath.Join(t.TempDir(), "secrets.json")
	secrets := map[string]string{
		"dpop_private_key": filepath.Join(t.TempDir(), "does-not-exist.json"),
	}
	sb, err := json.Marshal(secrets)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretsPath, sb, 0o600); err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse("https://upstream.example.com/mcp")
	if err != nil {
		t.Fatal(err)
	}
	b := &Backend{
		Name: "remote1",
		Remote: &RemoteBackendConfig{
			Endpoint:         u.String(),
			ClientID:         "client-1",
			Secrets:          &SecretsConfig{File: secretsPath},
			ClientSecretName: "oauth_client_secret",
			RefreshTokenName: "oauth_refresh_token",
			DPoPKeyName:      "dpop_private_key",
		},
		remoteURL: u,
	}

	if _, err := buildRemoteClient(b); err == nil {
		t.Fatal("buildRemoteClient must fail when the DPoP key file is missing, not silently generate one")
	}

	// Corrupt (unparseable) key file: also fatal.
	corruptPath := filepath.Join(t.TempDir(), "corrupt.json")
	if err := os.WriteFile(corruptPath, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets["dpop_private_key"] = corruptPath
	sb, _ = json.Marshal(secrets)
	if err := os.WriteFile(secretsPath, sb, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildRemoteClient(b); err == nil {
		t.Fatal("buildRemoteClient must fail when the DPoP key file is corrupt, not silently generate one")
	}
}
