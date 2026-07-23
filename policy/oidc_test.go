package policy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test IdP: generates an RSA (RS256) and an EC P-256 (ES256) keypair, signs
// JWTs with either, and serves its public keys as a JWKS httptest endpoint —
// the way a real OIDC IdP publishes them. The verifier under test pins the keys
// fetched+parsed from that endpoint; verification itself is offline.
// ---------------------------------------------------------------------------

const (
	testOIDCAud   = "https://meshmcp.example.org"
	testRSAIssuer = "https://idp.acme.example"   // pinned RS256
	testECIssuer  = "https://idp.globex.example" // pinned ES256
	testRSAKid    = "acme-rsa-1"
	testECKid     = "globex-ec-1"
)

type testIdP struct {
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	jwks   *httptest.Server
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	idp := &testIdP{rsaKey: rsaKey, ecKey: ecKey}
	doc, err := json.Marshal(map[string]any{
		"keys": []any{
			rsaJWK(testRSAKid, &rsaKey.PublicKey),
			ecJWK(testECKid, &ecKey.PublicKey),
		},
	})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	idp.jwks = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(idp.jwks.Close)
	return idp
}

// fetchedKeys fetches the served JWKS and parses it via the production ParseJWKS,
// so the httptest endpoint is genuinely exercised end-to-end. The verify path
// then uses the resulting pinned keys with no further network access.
func (idp *testIdP) fetchedKeys(t *testing.T) map[string]crypto.PublicKey {
	t.Helper()
	resp, err := http.Get(idp.jwks.URL)
	if err != nil {
		t.Fatalf("fetch jwks: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read jwks: %v", err)
	}
	keys, err := ParseJWKS(data)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	return keys
}

func rsaJWK(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecJWK(kid string, pub *ecdsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "EC", "kid": kid, "use": "sig", "alg": "ES256", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(oidcLeftPad32(pub.X.Bytes())),
		"y": base64.RawURLEncoding.EncodeToString(oidcLeftPad32(pub.Y.Bytes())),
	}
}

func oidcLeftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func b64urlJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// signRS256 signs claims as an RS256 JWT with the given header alg/kid (alg is a
// parameter so negative tests can lie about it).
func (idp *testIdP) signRS256(t *testing.T, alg, kid string, claims map[string]any) string {
	t.Helper()
	signingInput := b64urlJSON(t, map[string]any{"alg": alg, "typ": "JWT", "kid": kid}) + "." + b64urlJSON(t, claims)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.rsaKey, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// signES256 signs claims as an ES256 JWT (r||s) with the given header alg/kid.
func (idp *testIdP) signES256(t *testing.T, alg, kid string, claims map[string]any) string {
	t.Helper()
	signingInput := b64urlJSON(t, map[string]any{"alg": alg, "typ": "JWT", "kid": kid}) + "." + b64urlJSON(t, claims)
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, idp.ecKey, h[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	sig := append(oidcLeftPad32(r.Bytes()), oidcLeftPad32(s.Bytes())...)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func now() time.Time { return time.Unix(1_800_000_000, 0) }

// rsaClaims / ecClaims build a currently-valid claim set for the given issuer.
func rsaClaims() map[string]any {
	return map[string]any{
		"iss": testRSAIssuer, "sub": "user-1", "aud": testOIDCAud,
		"email": "u1@acme.example", "groups": []string{"finance", "eng"},
		"iat": now().Add(-time.Minute).Unix(), "exp": now().Add(time.Hour).Unix(),
	}
}

func ecClaims() map[string]any {
	return map[string]any{
		"iss": testECIssuer, "sub": "user-2", "aud": testOIDCAud,
		"email": "u2@globex.example", "groups": []string{"ops"},
		"iat": now().Add(-time.Minute).Unix(), "exp": now().Add(time.Hour).Unix(),
	}
}

// newVerifier pins both issuers from the fetched JWKS: acme→RS256(RSA key),
// globex→ES256(EC key).
func (idp *testIdP) newVerifier(t *testing.T) *OIDCVerifier {
	t.Helper()
	keys := idp.fetchedKeys(t)
	return &OIDCVerifier{
		Audience: testOIDCAud,
		Issuers: map[string]*OIDCIssuer{
			testRSAIssuer: {Alg: OIDCAlgRS256, Keys: map[string]crypto.PublicKey{testRSAKid: keys[testRSAKid]}},
			testECIssuer:  {Alg: OIDCAlgES256, Keys: map[string]crypto.PublicKey{testECKid: keys[testECKid]}},
		},
	}
}

// ---------------------------------------------------------------------------
// Happy path: valid RS256 + ES256 tokens verify and yield their groups.
// ---------------------------------------------------------------------------

func TestOIDC_ValidRS256Verifies(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	tok := idp.signRS256(t, "RS256", testRSAKid, rsaClaims())
	claims, err := v.Verify(tok, now())
	if err != nil {
		t.Fatalf("valid RS256 token should verify: %v", err)
	}
	if claims.Subject != "user-1" || claims.Email != "u1@acme.example" {
		t.Fatalf("wrong sub/email: %+v", claims)
	}
	if !hasGroup(claims.Groups, "finance") || !hasGroup(claims.Groups, "eng") {
		t.Fatalf("groups = %v, want finance+eng", claims.Groups)
	}
	if claims.ExpiresAt != now().Add(time.Hour).Unix() {
		t.Fatalf("ExpiresAt = %d, want token exp", claims.ExpiresAt)
	}
}

func TestOIDC_ValidES256Verifies(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	tok := idp.signES256(t, "ES256", testECKid, ecClaims())
	claims, err := v.Verify(tok, now())
	if err != nil {
		t.Fatalf("valid ES256 token should verify: %v", err)
	}
	if claims.Subject != "user-2" || !hasGroup(claims.Groups, "ops") {
		t.Fatalf("wrong claims: %+v", claims)
	}
}

// ---------------------------------------------------------------------------
// Forgery / tamper.
// ---------------------------------------------------------------------------

func TestOIDC_TamperedClaimsRejected(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	tok := idp.signRS256(t, "RS256", testRSAKid, rsaClaims())
	// Swap the claims segment for one granting group "admin" while keeping the
	// original signature — the signature no longer covers these bytes.
	forgedClaims := rsaClaims()
	forgedClaims["groups"] = []string{"admin"}
	parts := splitJWT(tok)
	tampered := parts[0] + "." + b64urlJSON(t, forgedClaims) + "." + parts[2]
	if _, err := v.Verify(tampered, now()); err == nil {
		t.Fatal("tampered claims must be rejected (signature no longer covers them)")
	}
}

func TestOIDC_WrongKeySignatureRejected(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	// A second IdP whose RSA key is NOT pinned signs a token claiming the pinned
	// issuer — the signature will not verify against the pinned key.
	attacker := newTestIdP(t)
	tok := attacker.signRS256(t, "RS256", testRSAKid, rsaClaims())
	if _, err := v.Verify(tok, now()); err == nil {
		t.Fatal("token signed by a non-pinned key must be rejected")
	}
}

// ---------------------------------------------------------------------------
// Algorithm attacks: alg:none and HS256 alg-confusion.
// ---------------------------------------------------------------------------

func TestOIDC_AlgNoneRejected(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	// alg:none, empty signature.
	tok := b64urlJSON(t, map[string]any{"alg": "none", "typ": "JWT", "kid": testRSAKid}) + "." + b64urlJSON(t, rsaClaims()) + "."
	if _, err := v.Verify(tok, now()); err == nil {
		t.Fatal("alg:none must be rejected")
	}
}

func TestOIDC_HS256AlgConfusionRejected(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	// Classic alg-confusion: sign an HS256 MAC using the RSA public key's DER
	// bytes as the shared secret, hoping the verifier treats the pinned public
	// key as an HMAC secret. It must instead reject on the pinned alg.
	pubDER, err := x509.MarshalPKIXPublicKey(&idp.rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	signingInput := b64urlJSON(t, map[string]any{"alg": "HS256", "typ": "JWT", "kid": testRSAKid}) + "." + b64urlJSON(t, rsaClaims())
	mac := hmac.New(sha256.New, pubDER)
	mac.Write([]byte(signingInput))
	tok := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if _, err := v.Verify(tok, now()); err == nil {
		t.Fatal("HS256 alg-confusion must be rejected (alg is pinned, never read to select)")
	}
}

func TestOIDC_WrongAlgForIssuerRejected(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	// An RS256-signed token claiming the ES256-pinned issuer: the header alg
	// (RS256) does not equal the issuer's pinned alg (ES256).
	claims := ecClaims() // iss = ES256-pinned issuer
	tok := idp.signRS256(t, "RS256", testECKid, claims)
	if _, err := v.Verify(tok, now()); err == nil {
		t.Fatal("RS256 token for an ES256-pinned issuer must be rejected")
	}
}

// ---------------------------------------------------------------------------
// Time window.
// ---------------------------------------------------------------------------

func TestOIDC_ExpiredRejected(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	claims := rsaClaims()
	claims["exp"] = now().Add(-time.Second).Unix()
	tok := idp.signRS256(t, "RS256", testRSAKid, claims)
	if _, err := v.Verify(tok, now()); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestOIDC_MissingExpRejected(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	claims := rsaClaims()
	delete(claims, "exp")
	tok := idp.signRS256(t, "RS256", testRSAKid, claims)
	if _, err := v.Verify(tok, now()); err == nil {
		t.Fatal("token missing exp must be rejected")
	}
}

func TestOIDC_NotYetValidRejected(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	claims := rsaClaims()
	claims["nbf"] = now().Add(time.Minute).Unix()
	tok := idp.signRS256(t, "RS256", testRSAKid, claims)
	if _, err := v.Verify(tok, now()); err == nil {
		t.Fatal("token with nbf in the future must be rejected")
	}
}

// ---------------------------------------------------------------------------
// Audience confusion.
// ---------------------------------------------------------------------------

func TestOIDC_WrongAudienceRejected(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	claims := rsaClaims()
	claims["aud"] = "https://some-other-saas.example/callback"
	tok := idp.signRS256(t, "RS256", testRSAKid, claims)
	if _, err := v.Verify(tok, now()); err == nil {
		t.Fatal("token with an aud lacking meshmcp's identity must be rejected")
	}
}

func TestOIDC_AudienceArrayContainingUsAccepted(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	claims := rsaClaims()
	claims["aud"] = []string{"https://other.example", testOIDCAud}
	tok := idp.signRS256(t, "RS256", testRSAKid, claims)
	if _, err := v.Verify(tok, now()); err != nil {
		t.Fatalf("aud array containing meshmcp's identity must verify: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Issuer pinning.
// ---------------------------------------------------------------------------

func TestOIDC_UnpinnedIssuerRejected(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	// Correctly signed by a pinned key, but the iss claim names an issuer that is
	// not in the pin set — rejected regardless of signature.
	claims := rsaClaims()
	claims["iss"] = "https://idp.unrelated.example"
	tok := idp.signRS256(t, "RS256", testRSAKid, claims)
	if _, err := v.Verify(tok, now()); err == nil {
		t.Fatal("token from an unpinned issuer must be rejected")
	}
}

func TestOIDC_UnknownKidRejected(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	claims := rsaClaims()
	tok := idp.signRS256(t, "RS256", "no-such-kid", claims)
	if _, err := v.Verify(tok, now()); err == nil {
		t.Fatal("token naming an unpinned kid must be rejected")
	}
}

// ---------------------------------------------------------------------------
// Configurable claim paths + JWKS parsing.
// ---------------------------------------------------------------------------

func TestOIDC_CustomGroupsClaimPath(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	v.GroupsClaim = "roles"
	claims := rsaClaims()
	delete(claims, "groups")
	claims["roles"] = []string{"treasury"}
	tok := idp.signRS256(t, "RS256", testRSAKid, claims)
	got, err := v.Verify(tok, now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !hasGroup(got.Groups, "treasury") {
		t.Fatalf("groups = %v, want [treasury] from custom claim path", got.Groups)
	}
}

func TestOIDC_SingleStringGroupAccepted(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	claims := rsaClaims()
	claims["groups"] = "finance" // a bare string, not an array
	tok := idp.signRS256(t, "RS256", testRSAKid, claims)
	got, err := v.Verify(tok, now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !hasGroup(got.Groups, "finance") || len(got.Groups) != 1 {
		t.Fatalf("groups = %v, want [finance]", got.Groups)
	}
}

func TestOIDC_ParseJWKSRejectsUnsupportedKty(t *testing.T) {
	_, err := ParseJWKS([]byte(`{"keys":[{"kty":"oct","kid":"x","k":"AAAA"}]}`))
	if err == nil {
		t.Fatal("ParseJWKS must reject an unsupported key type rather than silently drop it")
	}
}

func TestOIDC_ParseJWKSEmptyRejected(t *testing.T) {
	if _, err := ParseJWKS([]byte(`{"keys":[]}`)); err == nil {
		t.Fatal("ParseJWKS must reject an empty key set")
	}
}

// ---------------------------------------------------------------------------
// Malformed input.
// ---------------------------------------------------------------------------

func TestOIDC_MalformedTokenRejected(t *testing.T) {
	idp := newTestIdP(t)
	v := idp.newVerifier(t)
	for _, tok := range []string{"", "not-a-jwt", "a.b", "a.b.c.d", "!!!.???.$$$"} {
		if _, err := v.Verify(tok, now()); err == nil {
			t.Fatalf("malformed token %q must be rejected", tok)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func hasGroup(gs []string, want string) bool {
	for _, g := range gs {
		if g == want {
			return true
		}
	}
	return false
}

func splitJWT(tok string) [3]string {
	var out [3]string
	i := 0
	start := 0
	for j := 0; j < len(tok) && i < 3; j++ {
		if tok[j] == '.' {
			out[i] = tok[start:j]
			i++
			start = j + 1
		}
	}
	if i < 3 {
		out[i] = tok[start:]
	}
	return out
}
