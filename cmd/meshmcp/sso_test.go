package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

const (
	ssoTestIssuer = "https://idp.test.example"
	ssoTestAud    = "https://meshmcp.test"
	ssoTestKid    = "test-1"
	ssoTestPeerA  = "wg-key-AAAA"
	ssoTestPeerB  = "wg-key-BBBB"
)

type ssoFixture struct {
	key      *ecdsa.PrivateKey
	store    *policy.SSOGroups
	handler  http.Handler
	now      time.Time
	peerKey  string // what the injected identify returns (the transport root)
	peerFQDN string
	bindTTL  time.Duration
}

func newSSOFixture(t *testing.T) *ssoFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f := &ssoFixture{
		key:      key,
		now:      time.Unix(1_800_000_000, 0),
		peerKey:  ssoTestPeerA,
		peerFQDN: "agent-a.netbird.cloud",
		bindTTL:  time.Hour,
	}
	verifier := &policy.OIDCVerifier{
		Audience: ssoTestAud,
		Issuers: map[string]*policy.OIDCIssuer{
			ssoTestIssuer: {Alg: policy.OIDCAlgES256, Keys: map[string]crypto.PublicKey{ssoTestKid: &key.PublicKey}},
		},
	}
	f.store = policy.NewSSOGroups(func() time.Time { return f.now })
	identify := func(r *http.Request) (string, string) { return f.peerKey, f.peerFQDN }
	f.handler = ssoAttestHandler(verifier, f.store, identify, f.bindTTL, func() time.Time { return f.now }, nil)
	return f
}

func ssoB64JSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func ssoPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func (f *ssoFixture) sign(t *testing.T, alg, kid string, claims map[string]any) string {
	t.Helper()
	signingInput := ssoB64JSON(t, map[string]any{"alg": alg, "typ": "JWT", "kid": kid}) + "." + ssoB64JSON(t, claims)
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, f.key, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := append(ssoPad32(r.Bytes()), ssoPad32(s.Bytes())...)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *ssoFixture) claims() map[string]any {
	return map[string]any{
		"iss": ssoTestIssuer, "sub": "alice", "aud": ssoTestAud,
		"email": "alice@test.example", "groups": []string{"finance"},
		"iat": f.now.Add(-time.Minute).Unix(), "exp": f.now.Add(30 * time.Minute).Unix(),
	}
}

func (f *ssoFixture) post(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"token": token})
	req := httptest.NewRequest(http.MethodPost, "/v1/sso/attest", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func TestSSOAttest_ValidBinds(t *testing.T) {
	f := newSSOFixture(t)
	rec := f.post(t, f.sign(t, "ES256", ssoTestKid, f.claims()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	// The verified groups are now bound to the caller's TRANSPORT key.
	if !f.store.InGroup(ssoTestPeerA, "", "finance") {
		t.Fatal("finance should be bound to the transport key after a valid attest")
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["subject"] != "alice" {
		t.Fatalf("subject = %v, want alice", out["subject"])
	}
}

func TestSSOAttest_EmptyTransportRejectedNoBind(t *testing.T) {
	f := newSSOFixture(t)
	f.peerKey = "" // unattributable transport
	rec := f.post(t, f.sign(t, "ES256", ssoTestKid, f.claims()))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an unattributable transport", rec.Code)
	}
	// Nothing was bound — no Verify should even have been attempted, and the
	// (empty) key certainly holds nothing.
	if f.store.InGroup("", "", "finance") {
		t.Fatal("a blank transport key must never carry a binding")
	}
}

func TestSSOAttest_ForgedTokenNoBind(t *testing.T) {
	f := newSSOFixture(t)
	tok := f.sign(t, "ES256", ssoTestKid, f.claims())
	// Tamper the claims segment (grant admin) but keep the original signature.
	forged := f.claims()
	forged["groups"] = []string{"admin"}
	// Rebuild header.claims.sig with the ORIGINAL signature over different claims.
	parts := bytes.SplitN([]byte(tok), []byte("."), 3)
	tampered := string(parts[0]) + "." + ssoB64JSON(t, forged) + "." + string(parts[2])

	rec := f.post(t, tampered)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a forged token", rec.Code)
	}
	if f.store.InGroup(ssoTestPeerA, "", "admin") || f.store.InGroup(ssoTestPeerA, "", "finance") {
		t.Fatal("a forged token must bind NOTHING")
	}
}

func TestSSOAttest_ExpiredTokenNoBind(t *testing.T) {
	f := newSSOFixture(t)
	claims := f.claims()
	claims["exp"] = f.now.Add(-time.Second).Unix()
	rec := f.post(t, f.sign(t, "ES256", ssoTestKid, claims))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an expired token", rec.Code)
	}
	if f.store.InGroup(ssoTestPeerA, "", "finance") {
		t.Fatal("an expired token must bind nothing")
	}
}

// SACRED: a valid-but-wrong-audience token binds nothing AND does not alter the
// caller's mesh admission — the transport identity is untouched by a failed
// attest.
func TestSSOAttest_WrongAudNoBindTransportUnaffected(t *testing.T) {
	f := newSSOFixture(t)
	// An ACL that admits the transport key BEFORE any attest.
	admit := newACL([]string{"pubkey:" + ssoTestPeerA})
	if !admit.allows(ssoTestPeerA, f.peerFQDN) {
		t.Fatal("precondition: transport key should be admitted")
	}

	claims := f.claims()
	claims["aud"] = "https://some-other-saas.example/callback"
	rec := f.post(t, f.sign(t, "ES256", ssoTestKid, claims))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a wrong-audience token", rec.Code)
	}
	if f.store.InGroup(ssoTestPeerA, "", "finance") {
		t.Fatal("a wrong-audience token must bind nothing")
	}
	// The transport identity's admission is entirely unchanged by the failed
	// attest — the WireGuard key remains the root and is untouched.
	if !admit.allows(ssoTestPeerA, f.peerFQDN) {
		t.Fatal("SACRED: a failed attest must not alter the caller's transport admission")
	}
}

func TestSSOAttest_KeyBIsolation(t *testing.T) {
	f := newSSOFixture(t)
	// keyA attests successfully.
	if rec := f.post(t, f.sign(t, "ES256", ssoTestKid, f.claims())); rec.Code != http.StatusOK {
		t.Fatalf("keyA attest status = %d, want 200", rec.Code)
	}
	// keyB, presenting nothing, is never in keyA's groups.
	if f.store.InGroup(ssoTestPeerB, "", "finance") {
		t.Fatal("keyB must not inherit keyA's SSO binding")
	}
}

func TestSSOAttest_BindTTLCapped(t *testing.T) {
	f := newSSOFixture(t) // cap = 1h
	claims := f.claims()
	claims["exp"] = f.now.Add(2 * time.Hour).Unix() // longer than the cap
	rec := f.post(t, f.sign(t, "ES256", ssoTestKid, claims))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := int64(out["expires_at"].(float64))
	want := f.now.Add(time.Hour).Unix() // min(token exp 2h, now+cap 1h) = now+1h
	if got != want {
		t.Fatalf("expires_at = %d, want %d (capped to now+bind_ttl_max)", got, want)
	}
}

func TestSSOAttest_BindTTLFollowsShortToken(t *testing.T) {
	f := newSSOFixture(t) // cap = 1h; token exp is only 30m out
	rec := f.post(t, f.sign(t, "ES256", ssoTestKid, f.claims()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	got := int64(out["expires_at"].(float64))
	want := f.now.Add(30 * time.Minute).Unix() // min(token exp 30m, now+1h) = token exp
	if got != want {
		t.Fatalf("expires_at = %d, want the token exp %d", got, want)
	}
}

func TestSSOAttest_MethodAndOriginGuards(t *testing.T) {
	f := newSSOFixture(t)

	// GET is rejected.
	req := httptest.NewRequest(http.MethodGet, "/v1/sso/attest", nil)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", rec.Code)
	}

	// Cross-origin POST is rejected (CSRF guard).
	body, _ := json.Marshal(map[string]string{"token": "x"})
	req = httptest.NewRequest(http.MethodPost, "/v1/sso/attest", bytes.NewReader(body))
	req.Header.Set("Origin", "http://evil.example")
	rec = httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status = %d, want 403", rec.Code)
	}
}

func TestSSOAttest_MissingTokenRejected(t *testing.T) {
	f := newSSOFixture(t)
	rec := f.post(t, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing token", rec.Code)
	}
}
