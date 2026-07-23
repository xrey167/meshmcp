package policy

// OIDC verification for SSO-mapped attribution (F31 v1).
//
// An OIDC token is presented OVER an already-authenticated mesh connection. The
// WireGuard transport identity (peerKey) is resolved first by the caller and
// stays the ROOT of trust; this verifier only turns a presented token into a set
// of additive claims (sub/email/groups) that the caller then binds to that
// transport key (see ssogroups.go). A forged, expired, wrong-audience, or
// unpinned-issuer token yields an error and therefore binds NOTHING — collapsing
// to today's deny behavior.
//
// The verifier deliberately MIRRORS federation/exchange.go's validateSubjectToken
// rather than importing it (federation already imports policy; importing back
// would create a cycle) and rather than promoting golang-jwt to a direct
// dependency (its runtime alg agility is the alg-confusion footgun this
// hand-rolled, pinned-alg verifier exists to avoid). Keys are STATICALLY pinned
// per issuer — there is no JWKS fetch or any outbound network call on the verify
// path; a forged token never triggers a network round-trip.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// OIDC signing algorithms this verifier accepts. Each issuer PINS exactly one of
// these by configuration; the value is NEVER read from a token's own header to
// select a verification path (alg-confusion + alg:none defense, mirroring
// federation/exchange.go's subjectTokenAlg constant). Real IdPs (Okta/Entra/
// Google) sign RS256; ES256 reuses the same r||s check the federation verifier
// and DPoP verifier already use.
const (
	OIDCAlgES256 = "ES256"
	OIDCAlgRS256 = "RS256"
)

// maxOIDCGroupsPerToken bounds how many group names a single verified token can
// contribute to a binding — a verified token comes from a pinned issuer, but a
// bound cap keeps a misconfigured/hostile IdP from bloating the in-memory store.
const maxOIDCGroupsPerToken = 256

// OIDCClaims is the additive attribution a verified token yields. It is NEVER an
// enforcement key: enforcement keys on the WireGuard transport key these claims
// are bound to (SSOGroups.Bind). Groups feed `group:<name>` policy matching;
// Subject/Email are attribution only.
type OIDCClaims struct {
	Subject   string
	Email     string
	Groups    []string
	ExpiresAt int64 // token's exp (unix seconds), so a bind can be TTL-bounded to it
}

// OIDCIssuer is one pinned external issuer: the single algorithm its tokens MUST
// carry (pinned, never selected from the token) and its public keys by JWK `kid`
// (a single-key issuer may key on ""). Keys are static and pinned; there is no
// fetch.
type OIDCIssuer struct {
	Alg  string                      // OIDCAlgES256 | OIDCAlgRS256, pinned
	Keys map[string]crypto.PublicKey // kid -> *rsa.PublicKey | *ecdsa.PublicKey
}

// keyFor selects the pinned key a token names via its `kid` header. An explicit
// kid must match a pinned key; a token that omits kid is honored only when the
// issuer pins exactly one key (or an unnamed "" key), never guessed among many.
func (iss *OIDCIssuer) keyFor(kid string) (crypto.PublicKey, error) {
	if kid != "" {
		if k, ok := iss.Keys[kid]; ok && k != nil {
			return k, nil
		}
		return nil, fmt.Errorf("oidc: no pinned key with kid %q for issuer", kid)
	}
	if k, ok := iss.Keys[""]; ok && k != nil {
		return k, nil
	}
	if len(iss.Keys) == 1 {
		for _, k := range iss.Keys {
			if k != nil {
				return k, nil
			}
		}
	}
	return nil, errors.New("oidc: token omits kid and the issuer pins multiple keys (ambiguous)")
}

// OIDCVerifier verifies an external IdP token against statically pinned issuer
// keys. Zero-value is unusable; construct with pinned Issuers + Audience.
type OIDCVerifier struct {
	// Issuers maps an EXACT issuer string to its pinned keys (no glob, no "*"
	// fallback — the collision-safe pattern federation/boundary.go's
	// OrgForIssuer uses). An issuer absent here is unpinned; every token
	// claiming it is rejected regardless of signature.
	Issuers map[string]*OIDCIssuer
	// Audience is meshmcp's identity that a token's `aud` MUST contain
	// (audience-confusion defense). Empty is treated as "matches nothing".
	Audience string
	// GroupsClaim / EmailClaim name the claim paths carrying the group list and
	// email; empty means the "groups" / "email" defaults.
	GroupsClaim string
	EmailClaim  string
}

func (v *OIDCVerifier) groupsClaim() string {
	if v.GroupsClaim != "" {
		return v.GroupsClaim
	}
	return "groups"
}

func (v *OIDCVerifier) emailClaim() string {
	if v.EmailClaim != "" {
		return v.EmailClaim
	}
	return "email"
}

// oidcHeader is the JOSE header of a presented token. `alg` is read ONLY to
// compare against the issuer's pinned alg (never to select a verify path); `kid`
// selects among an issuer's pinned keys, exactly like a JOSE library.
type oidcHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// oidcStdClaims is the standard claim set required for verification. Configurable
// claims (groups/email) are read separately from the raw claim bytes so their
// paths can be operator-set without changing this struct.
type oidcStdClaims struct {
	Issuer    string       `json:"iss"`
	Subject   string       `json:"sub"`
	Audience  oidcAudience `json:"aud"`
	IssuedAt  int64        `json:"iat,omitempty"`
	NotBefore int64        `json:"nbf,omitempty"`
	ExpiresAt int64        `json:"exp"`
}

// oidcAudience decodes a JWT `aud`, which per RFC 7519 §4.1.3 is a single string
// or an array of strings. (Duplicated package-private rather than imported from
// federation to avoid a policy<-federation import cycle.)
type oidcAudience []string

func (a *oidcAudience) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*a = oidcAudience{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(b, &multi); err != nil {
		return fmt.Errorf("aud must be a string or an array of strings: %w", err)
	}
	*a = oidcAudience(multi)
	return nil
}

func (a oidcAudience) contains(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}

// parseOIDCToken splits a compact JWS into header, raw claim bytes, the exact
// signing-input bytes the signature covers, and the raw signature. Pure
// structural decode — it makes NO trust decision; every trust decision is a named
// step in Verify.
func parseOIDCToken(token string) (hdr oidcHeader, claimBytes, signingInput, sig []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return hdr, nil, nil, nil, fmt.Errorf("oidc: expected 3 dot-separated segments, got %d", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return hdr, nil, nil, nil, fmt.Errorf("oidc: decode header: %w", err)
	}
	claimBytes, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return hdr, nil, nil, nil, fmt.Errorf("oidc: decode claims: %w", err)
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return hdr, nil, nil, nil, fmt.Errorf("oidc: decode signature: %w", err)
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return hdr, nil, nil, nil, fmt.Errorf("oidc: parse header: %w", err)
	}
	return hdr, claimBytes, []byte(parts[0] + "." + parts[1]), sig, nil
}

// Verify runs every required check in strict fail-closed order, returning zero
// claims + an error on the FIRST failure:
//
//  1. structural parse
//  2. alg is one of the accepted algorithms (rejects alg:none / HS256 outright)
//  3. pinned-issuer lookup (iss read from the UNVERIFIED token only as a key
//     selector — exactly like `kid` — grants no trust; unpinned issuer rejected)
//  4. alg-pin: header alg MUST equal the issuer's configured alg (never selected
//     from the header)
//  5. signature against the pinned key (ES256 r||s, or RS256 PKCS#1 v1.5)
//  6. audience contains meshmcp's identity (audience-confusion defense)
//  7. exp/nbf time window
//
// Only after all pass are the additive sub/email/groups claims extracted.
func (v *OIDCVerifier) Verify(token string, now time.Time) (OIDCClaims, error) {
	hdr, claimBytes, signingInput, sig, err := parseOIDCToken(token)
	if err != nil {
		return OIDCClaims{}, err
	}
	// Step 2: reject anything but a real asymmetric alg up front, so `alg:none`
	// and an HS256 alg-confusion attempt (MAC using the public key as the secret)
	// are refused before any key is even selected.
	if hdr.Alg != OIDCAlgES256 && hdr.Alg != OIDCAlgRS256 {
		return OIDCClaims{}, fmt.Errorf("oidc: alg %q is not an accepted signing algorithm", hdr.Alg)
	}
	var std oidcStdClaims
	if err := json.Unmarshal(claimBytes, &std); err != nil {
		return OIDCClaims{}, fmt.Errorf("oidc: parse claims: %w", err)
	}
	// Step 3: pinned-issuer lookup. The issuer is read from the unverified token
	// only to select which pinned key set to try; an unpinned issuer is rejected
	// regardless of signature.
	iss := v.Issuers[std.Issuer]
	if iss == nil {
		return OIDCClaims{}, fmt.Errorf("oidc: issuer %q is not pinned", std.Issuer)
	}
	// Step 4: alg pin — compare to the issuer's configured alg. Never selected
	// from the token header.
	if hdr.Alg != iss.Alg {
		return OIDCClaims{}, fmt.Errorf("oidc: alg %q is not the pinned %q for issuer %q", hdr.Alg, iss.Alg, std.Issuer)
	}
	// Step 5: signature against the pinned key named by kid.
	key, err := iss.keyFor(hdr.Kid)
	if err != nil {
		return OIDCClaims{}, err
	}
	if err := verifyOIDCSignature(iss.Alg, key, signingInput, sig); err != nil {
		return OIDCClaims{}, err
	}
	// Step 6: audience contains meshmcp's identity.
	if v.Audience == "" || !std.Audience.contains(v.Audience) {
		return OIDCClaims{}, fmt.Errorf("oidc: aud does not include %q (audience confusion)", v.Audience)
	}
	// Step 7: exp/nbf.
	if std.ExpiresAt == 0 || now.Unix() >= std.ExpiresAt {
		return OIDCClaims{}, errors.New("oidc: token expired (or missing exp)")
	}
	if std.NotBefore != 0 && now.Unix() < std.NotBefore {
		return OIDCClaims{}, errors.New("oidc: token not yet valid (nbf is in the future)")
	}
	// All checks passed — extract the additive attribution claims.
	claims := OIDCClaims{
		Subject:   std.Subject,
		Email:     extractStringClaim(claimBytes, v.emailClaim()),
		Groups:    extractGroupsClaim(claimBytes, v.groupsClaim()),
		ExpiresAt: std.ExpiresAt,
	}
	return claims, nil
}

// verifyOIDCSignature checks sig over signingInput with the pinned key. ES256 is
// the fixed-length r||s JWS encoding (RFC 7518 §3.4); RS256 is PKCS#1 v1.5 over
// SHA-256. The alg is the issuer's PINNED value, so the key type and check can
// never be steered by the token.
func verifyOIDCSignature(alg string, key crypto.PublicKey, signingInput, sig []byte) error {
	hash := sha256.Sum256(signingInput)
	switch alg {
	case OIDCAlgES256:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || pub == nil {
			return errors.New("oidc: pinned key is not an ECDSA key for ES256")
		}
		if len(sig) != 64 {
			return fmt.Errorf("oidc: ES256 signature must be 64 bytes (r||s), got %d", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, hash[:], r, s) {
			return errors.New("oidc: ES256 signature does not verify against the pinned key")
		}
		return nil
	case OIDCAlgRS256:
		pub, ok := key.(*rsa.PublicKey)
		if !ok || pub == nil {
			return errors.New("oidc: pinned key is not an RSA key for RS256")
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig); err != nil {
			return errors.New("oidc: RS256 signature does not verify against the pinned key")
		}
		return nil
	default:
		return fmt.Errorf("oidc: unsupported alg %q", alg)
	}
}

// extractStringClaim reads a single string claim at key from raw claim bytes,
// returning "" when absent or not a string.
func extractStringClaim(claimBytes []byte, key string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(claimBytes, &m) != nil {
		return ""
	}
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// extractGroupsClaim reads the group list at key, accepting either a JSON array
// of strings or a single string (some IdPs emit one group as a bare string). The
// result is bounded to maxOIDCGroupsPerToken.
func extractGroupsClaim(claimBytes []byte, key string) []string {
	var m map[string]json.RawMessage
	if json.Unmarshal(claimBytes, &m) != nil {
		return nil
	}
	raw, ok := m[key]
	if !ok {
		return nil
	}
	var arr []string
	if json.Unmarshal(raw, &arr) != nil {
		var single string
		if json.Unmarshal(raw, &single) == nil && single != "" {
			return []string{single}
		}
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, g := range arr {
		if g == "" {
			continue
		}
		out = append(out, g)
		if len(out) >= maxOIDCGroupsPerToken {
			break
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// JWKS (RFC 7517) parsing.
//
// Operators pin an IdP's published JSON Web Key Set STATICALLY (the honest v1:
// no fetch on the verify path). ParseJWKS turns that document into the pinned
// key map an OIDCIssuer holds. A real IdP serves this at a jwks_uri; wiring an
// automatic cached fetch of that URI (feeding the same pinned map) is the
// documented v2 extension — v1 pins the document itself so verification is
// offline and deterministic.
// ---------------------------------------------------------------------------

// jwk is one JSON Web Key (the subset meshmcp pins: RSA and EC P-256 public
// keys).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// ParseJWKS parses an RFC 7517 JWK Set into pinned public keys keyed by `kid`
// (an entry without a kid keys on ""). Only RSA and EC P-256 public keys are
// supported; any other key type is an error rather than a silently dropped key,
// so an operator can never believe a key is pinned when it is not.
func ParseJWKS(data []byte) (map[string]crypto.PublicKey, error) {
	var set jwkSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("jwks: not a valid JSON Web Key Set: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("jwks: key set is empty")
	}
	out := make(map[string]crypto.PublicKey, len(set.Keys))
	for i, k := range set.Keys {
		pub, err := k.publicKey()
		if err != nil {
			return nil, fmt.Errorf("jwks: key #%d (kid %q): %w", i+1, k.Kid, err)
		}
		if _, dup := out[k.Kid]; dup {
			return nil, fmt.Errorf("jwks: duplicate kid %q", k.Kid)
		}
		out[k.Kid] = pub
	}
	return out, nil
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		return k.rsaKey()
	case "EC":
		return k.ecKey()
	default:
		return nil, fmt.Errorf("unsupported kty %q (want RSA or EC)", k.Kty)
	}
}

func (k jwk) rsaKey() (*rsa.PublicKey, error) {
	if k.N == "" || k.E == "" {
		return nil, errors.New("RSA key missing n or e")
	}
	nb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.N, "="))
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.E, "="))
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() < 2 || e.Int64() > (1<<31-1) {
		return nil, errors.New("RSA exponent out of range")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, nil
}

func (k jwk) ecKey() (*ecdsa.PublicKey, error) {
	if k.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported EC curve %q (want P-256)", k.Crv)
	}
	if k.X == "" || k.Y == "" {
		return nil, errors.New("EC key missing x or y")
	}
	xb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.X, "="))
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.Y, "="))
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}
