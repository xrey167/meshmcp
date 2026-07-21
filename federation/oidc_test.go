package federation

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// signJWT builds a real RS256 JWT so the test exercises the actual verify path.
func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	pl, _ := json.Marshal(claims)
	signing := enc.EncodeToString(hdr) + "." + enc.EncodeToString(pl)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc.EncodeToString(sig)
}

func fixedNow() func() time.Time {
	base := time.Unix(1_800_000_000, 0)
	return func() time.Time { return base }
}

func TestOIDCVerifyAndMap(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := fixedNow()
	v := &OIDCVerifier{
		Issuer:   "https://idp.example.com",
		Audience: "meshmcp",
		Keys:     StaticJWKS{"k1": &key.PublicKey},
		Now:      now,
	}
	tok := signJWT(t, key, "k1", map[string]any{
		"iss": "https://idp.example.com", "aud": "meshmcp", "sub": "user-123",
		"email": "alice@acme.io", "groups": []string{"eng", "oncall"},
		"exp": now().Add(time.Hour).Unix(), "iat": now().Unix(),
	})
	c, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify legit token: %v", err)
	}
	if c.Subject != "user-123" || c.Email != "alice@acme.io" {
		t.Fatalf("claims wrong: %+v", c)
	}

	// SSO → org mapping via the shared Mapping table (by group, email, subject).
	b := NewBoundary(
		[]Grant{{Org: "acme", Tools: []string{"*"}}},
		[]Mapping{{Match: "group:oncall", Org: "acme", Principal: "acme-sso"}},
		nil,
	)
	if org := b.OrgForSSO(c); org != "acme" {
		t.Fatalf("group mapping: want acme, got %q", org)
	}
	if p := b.Principal(b.OrgForSSO(c)); p != "acme-sso" {
		t.Fatalf("principal: want acme-sso, got %q", p)
	}
	// A subject/email that maps to nothing is denied (org "").
	if org := b.OrgForSSO(OIDCClaims{Subject: "nobody", Email: "x@y.z"}); org != "" {
		t.Fatalf("unmapped identity should resolve to no org, got %q", org)
	}
}

func TestOIDCFailClosed(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := fixedNow()
	base := func(m map[string]any) map[string]any {
		out := map[string]any{"iss": "iss", "aud": "meshmcp", "sub": "u",
			"exp": now().Add(time.Hour).Unix()}
		for k, val := range m {
			out[k] = val
		}
		return out
	}
	v := &OIDCVerifier{Issuer: "iss", Audience: "meshmcp", Keys: StaticJWKS{"k1": &key.PublicKey}, Now: now}

	cases := map[string]string{
		"untrusted signer": signJWT(t, attacker, "k1", base(nil)),
		"wrong issuer":     signJWT(t, key, "k1", base(map[string]any{"iss": "evil"})),
		"wrong audience":   signJWT(t, key, "k1", base(map[string]any{"aud": "other"})),
		"expired":          signJWT(t, key, "k1", base(map[string]any{"exp": now().Add(-time.Hour).Unix()})),
		"no subject":       signJWT(t, key, "k1", base(map[string]any{"sub": ""})),
	}
	for name, tok := range cases {
		if _, err := v.Verify(tok); err == nil {
			t.Fatalf("%s: expected verification to fail", name)
		}
	}
	// A tampered payload (valid structure, broken signature) is refused.
	legit := signJWT(t, key, "k1", base(nil))
	parts := strings.Split(legit, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"iss","aud":"meshmcp","sub":"admin","exp":9999999999}`)) + "." + parts[2]
	if _, err := v.Verify(tampered); err == nil {
		t.Fatalf("tampered payload must fail signature check")
	}
}
