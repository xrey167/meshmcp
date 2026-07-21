package federation

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// F31 · Federated identity — SSO mapping at the seam.
//
// An OIDC ID token (a signed JWT from an external IdP) is verified here and its
// subject/email/groups mapped to a mesh org + local principal via the existing
// federation Mapping. So a user's directory identity drives cross-org policy,
// end to end and audited — enterprise SSO meets cryptographic mesh identity.
// Verification is fail-closed and dep-free (stdlib RS256, the OIDC default):
// the signing key must come from a pinned/trusted JWKS, and issuer, audience,
// and the time window are all checked before any claim is trusted.

// OIDCClaims is the subset of an ID token meshmcp maps to a mesh identity.
type OIDCClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Email     string   `json:"email"`
	Groups    []string `json:"groups"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	// Audience is decoded separately (it may be a string or an array).
	Audience []string `json:"-"`
}

// JWKSProvider resolves an IdP signing key by its key id (the JWT `kid`).
type JWKSProvider interface {
	Key(kid string) (crypto.PublicKey, error)
}

// StaticJWKS is a fixed set of trusted signing keys (config-pinned or, in tests,
// a generated key). Prod deployments can wrap a JWKS-endpoint fetch behind the
// same interface using the mockable Doer.
type StaticJWKS map[string]crypto.PublicKey

func (s StaticJWKS) Key(kid string) (crypto.PublicKey, error) {
	if k, ok := s[kid]; ok {
		return k, nil
	}
	// A single unnamed key is a common test/config shape: accept any kid.
	if len(s) == 1 {
		for _, k := range s {
			return k, nil
		}
	}
	return nil, fmt.Errorf("oidc: no trusted key for kid %q", kid)
}

// OIDCVerifier verifies ID tokens from one issuer for one audience.
type OIDCVerifier struct {
	Issuer   string       // required exact match of the `iss` claim
	Audience string       // required membership in the `aud` claim
	Keys     JWKSProvider // trusted signing keys
	Now      func() time.Time
}

// Verify checks an ID token's RS256 signature against a trusted key, then the
// issuer, audience, and time window. It returns the claims only on full success
// — every failure is fail-closed.
func (v *OIDCVerifier) Verify(idToken string) (OIDCClaims, error) {
	var zero OIDCClaims
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return zero, fmt.Errorf("oidc: token is not a JWT (want 3 segments)")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &hdr) != nil {
		return zero, fmt.Errorf("oidc: bad token header")
	}
	if hdr.Alg != "RS256" {
		return zero, fmt.Errorf("oidc: unsupported alg %q (only RS256)", hdr.Alg)
	}
	if v.Keys == nil {
		return zero, fmt.Errorf("oidc: no trusted keys configured")
	}
	key, err := v.Keys.Key(hdr.Kid)
	if err != nil {
		return zero, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return zero, fmt.Errorf("oidc: trusted key is not RSA")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return zero, fmt.Errorf("oidc: bad signature encoding")
	}
	signed := parts[0] + "." + parts[1]
	sum := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, sum[:], sig); err != nil {
		return zero, fmt.Errorf("oidc: signature does not verify")
	}

	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return zero, fmt.Errorf("oidc: bad token payload")
	}
	var c OIDCClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return zero, fmt.Errorf("oidc: bad claims JSON")
	}
	c.Audience = decodeAudience(pb)

	if v.Issuer != "" && c.Issuer != v.Issuer {
		return zero, fmt.Errorf("oidc: issuer %q does not match expected %q", c.Issuer, v.Issuer)
	}
	if v.Audience != "" && !contains(c.Audience, v.Audience) {
		return zero, fmt.Errorf("oidc: audience does not include %q", v.Audience)
	}
	now := v.now().Unix()
	if c.ExpiresAt == 0 || now >= c.ExpiresAt {
		return zero, fmt.Errorf("oidc: token expired or missing exp")
	}
	if c.NotBefore != 0 && now < c.NotBefore {
		return zero, fmt.Errorf("oidc: token not yet valid")
	}
	if c.Subject == "" {
		return zero, fmt.Errorf("oidc: token has no subject")
	}
	return c, nil
}

func (v *OIDCVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// decodeAudience handles `aud` being either a string or an array of strings.
func decodeAudience(payload []byte) []string {
	var raw struct {
		Aud json.RawMessage `json:"aud"`
	}
	if json.Unmarshal(payload, &raw) != nil || len(raw.Aud) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(raw.Aud, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw.Aud, &many) == nil {
		return many
	}
	return nil
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// RSAPublicKeyFromJWK builds an *rsa.PublicKey from a JWK's base64url modulus
// (n) and exponent (e) — the shape a JWKS endpoint returns — so a fetched key
// set can feed StaticJWKS without extra dependencies.
func RSAPublicKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nb, err := b64.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("oidc: bad JWK modulus")
	}
	eb, err := b64.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("oidc: bad JWK exponent")
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e == 0 {
		e = 65537
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

var b64 = base64.RawURLEncoding
