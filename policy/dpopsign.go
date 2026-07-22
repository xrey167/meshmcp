package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xrey167/meshmcp/protocol/authorization"
)

// dpopKeyType is the on-disk discriminator for a policy/dpopsign.go key file.
// It exists so a DPoP (ECDSA P-256) key can never be silently loaded by
// policy/sign.go's Ed25519 LoadSigner, or vice versa: the two key files have
// deliberately distinct shapes, this field is the explicit tell.
const dpopKeyType = "dpop-es256"

// dpopTyp is the JWT "typ" header RFC 9449 requires on every DPoP proof.
const dpopTyp = "dpop+jwt"

// dpopAlg is the only signing algorithm this signer produces or a verifier
// should ever accept for a DPoP proof (alg-confusion defense: pinned by
// configuration, never read from an incoming header to select behavior).
const dpopAlg = "ES256"

// DPoPSigner holds a per-backend ECDSA P-256 key pair used to construct DPoP
// proof JWTs (RFC 9449 Section 4) as an OAuth 2.1 client. It is the
// signer/proof-construction side only — see Feature C0 for verification.
type DPoPSigner struct {
	priv *ecdsa.PrivateKey
}

// GenerateDPoPSigner creates a fresh ECDSA P-256 DPoP signing key.
func GenerateDPoPSigner() (*DPoPSigner, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &DPoPSigner{priv: priv}, nil
}

// dpopKeyFile is the on-disk form of a DPoP signing key. It deliberately does
// NOT reuse policy/sign.go's keyFile shape (hex Ed25519 private/public) — see
// dpopKeyType.
type dpopKeyFile struct {
	KeyType string `json:"key_type"` // always dpopKeyType
	D       string `json:"d"`        // base64url, unpadded, 32-byte private scalar
	X       string `json:"x"`        // base64url, unpadded, 32-byte public X
	Y       string `json:"y"`        // base64url, unpadded, 32-byte public Y
}

// leftPad32 returns b left-padded with zeros to 32 bytes (the P-256 field
// element width) — big.Int.Bytes() strips leading zeros, which would
// otherwise produce a variable-length, non-interoperable encoding.
func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// SaveDPoPSigner writes the key pair to path. The write is atomic (tmp file +
// os.Rename, matching cmd/vault/main.go's rotate()) so a process killed
// mid-write never leaves a corrupt or half-written key file in place of a
// good one, and the file is 0600 (owner-only), matching policy/sign.go.
func (s *DPoPSigner) SaveDPoPSigner(path string) error {
	kf := dpopKeyFile{
		KeyType: dpopKeyType,
		D:       b64url(leftPad32(s.priv.D.Bytes())),
		X:       b64url(leftPad32(s.priv.PublicKey.X.Bytes())),
		Y:       b64url(leftPad32(s.priv.PublicKey.Y.Bytes())),
	}
	b, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadDPoPSigner reads a key pair written by SaveDPoPSigner. It refuses a file
// that lacks the dpop-es256 key_type discriminator — including, in
// particular, a file written by policy/sign.go's SaveSigner — so the two
// signer types can never be cross-wired by pointing config at the wrong file.
func LoadDPoPSigner(path string) (*DPoPSigner, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf dpopKeyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		return nil, fmt.Errorf("parse dpop key %s: %w", path, err)
	}
	if kf.KeyType != dpopKeyType {
		return nil, fmt.Errorf("dpop key %s: key_type %q, want %q", path, kf.KeyType, dpopKeyType)
	}
	d, err := base64.RawURLEncoding.DecodeString(kf.D)
	if err != nil || len(d) != 32 {
		return nil, fmt.Errorf("dpop key %s: invalid private scalar", path)
	}
	x, err := base64.RawURLEncoding.DecodeString(kf.X)
	if err != nil || len(x) != 32 {
		return nil, fmt.Errorf("dpop key %s: invalid public X", path)
	}
	y, err := base64.RawURLEncoding.DecodeString(kf.Y)
	if err != nil || len(y) != 32 {
		return nil, fmt.Errorf("dpop key %s: invalid public Y", path)
	}
	curve := elliptic.P256()
	px := new(big.Int).SetBytes(x)
	py := new(big.Int).SetBytes(y)
	if !curve.IsOnCurve(px, py) {
		return nil, fmt.Errorf("dpop key %s: public point is not on P-256", path)
	}
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: px, Y: py},
		D:         new(big.Int).SetBytes(d),
	}
	return &DPoPSigner{priv: priv}, nil
}

// dpopJWK is the embedded public-key header of a DPoP proof (RFC 9449
// Section 4.2), and also the input to the RFC 7638 thumbprint below.
type dpopJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (s *DPoPSigner) jwk() dpopJWK {
	return dpopJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   b64url(leftPad32(s.priv.PublicKey.X.Bytes())),
		Y:   b64url(leftPad32(s.priv.PublicKey.Y.Bytes())),
	}
}

// Thumbprint computes the RFC 7638 JWK thumbprint (jkt) of this signer's
// public key: base64url(SHA-256(canonical JSON)), with the required members
// in strict lexicographic order (crv, kty, x, y) and no whitespace. This is
// NOT the same as json.Marshal-ing dpopJWK (whose field order is for
// readability, not the thumbprint spec) — the string is built explicitly.
func (s *DPoPSigner) Thumbprint() string {
	j := s.jwk()
	canon := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, j.Crv, j.Kty, j.X, j.Y)
	sum := sha256.Sum256([]byte(canon))
	return b64url(sum[:])
}

// dpopHeader is the JWT header of a DPoP proof.
type dpopHeader struct {
	Typ string  `json:"typ"`
	Alg string  `json:"alg"`
	JWK dpopJWK `json:"jwk"`
}

// DPoPClaims is the JWT claim set of a DPoP proof (RFC 9449 Section 4.2/4.3).
type DPoPClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	Ath   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// NormalizeHTU reduces a request URL to the htu form a DPoP proof binds to:
// scheme + host + path, with any query string and fragment excluded (the
// common DPoP profile normalization also required by Feature C0's verifier,
// stated here so client and verifier agree).
func NormalizeHTU(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// newJTI mints a fresh, unpredictable per-proof identifier.
func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return b64url(b[:]), nil
}

// Proof constructs a DPoP proof JWT (RFC 9449 Section 4.2) for one HTTP
// request. accessToken, when non-empty, adds the ath claim (Section 4.3) —
// required when presenting the proof alongside a DPoP-bound access token to a
// resource server, omitted for the token-endpoint request that mints the
// token in the first place. nonce, when non-empty, embeds the AS-issued
// DPoP-Nonce so a server requiring one accepts the proof.
func (s *DPoPSigner) Proof(method, rawURL string, now time.Time, accessToken, nonce string) (string, error) {
	htu, err := NormalizeHTU(rawURL)
	if err != nil {
		return "", fmt.Errorf("dpop proof: %w", err)
	}
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	claims := DPoPClaims{
		JTI:   jti,
		HTM:   method,
		HTU:   htu,
		IAT:   now.Unix(),
		Nonce: nonce,
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims.Ath = b64url(sum[:])
	}
	header := dpopHeader{Typ: dpopTyp, Alg: dpopAlg, JWK: s.jwk()}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64url(hb) + "." + b64url(cb)
	hash := sha256.Sum256([]byte(signingInput))
	r, sVal, err := ecdsa.Sign(rand.Reader, s.priv, hash[:])
	if err != nil {
		return "", err
	}
	sig := append(leftPad32(r.Bytes()), leftPad32(sVal.Bytes())...)
	return signingInput + "." + b64url(sig), nil
}

// ---------------------------------------------------------------------------
// Feature C0 — server-side DPoP proof verification (RFC 9449 §4.3/§7.1/§8).
//
// DPoPVerifier is structurally and functionally distinct from DPoPSigner
// above (client/proof-construction, Feature B) and from policy/sign.go's
// Ed25519 checkpoint verification: no verify path is shared between the
// three. Each required check is its own named, independently-testable
// function (see policy/dpopverify_test.go), composed by Verify below — not
// one opaque Verify(proof) bool.
// ---------------------------------------------------------------------------

// dpopFreshnessSkew and dpopMaxAge pin the iat freshness window (RFC 9449
// §11): a proof up to dpopFreshnessSkew in the future (clock skew) or up to
// dpopMaxAge in the past is accepted; anything outside that is rejected.
// These are concrete, pinned defaults per the design doc — not left open.
const (
	dpopFreshnessSkew = 60 * time.Second
	dpopMaxAge        = 300 * time.Second
	// dpopNonceTTL is the server-issued DPoP-Nonce lifetime (RFC 9449 §8).
	dpopNonceTTL = 300 * time.Second
)

// thumbprint computes the RFC 7638 JWK thumbprint of j itself. This is the
// verifier-side counterpart to DPoPSigner.Thumbprint (which computes the same
// value from a signer's own key) — kept as a separate method because the
// verifier only ever has the jwk as parsed out of an untrusted incoming
// proof, never a Signer instance to call Thumbprint() on.
func (j dpopJWK) thumbprint() string {
	canon := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, j.Crv, j.Kty, j.X, j.Y)
	sum := sha256.Sum256([]byte(canon))
	return b64url(sum[:])
}

// parseDPoPProof splits a proof JWT into its header, claims, and raw
// signature bytes, plus the exact signing-input bytes the signature covers.
// This is pure structural decoding — it makes no trust decision about the
// proof's validity; every trust decision below is its own separate step.
func parseDPoPProof(proof string) (hdr dpopHeader, claims DPoPClaims, signingInput, sig []byte, err error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return hdr, claims, nil, nil, fmt.Errorf("dpop proof: expected 3 dot-separated segments, got %d", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return hdr, claims, nil, nil, fmt.Errorf("dpop proof: decode header: %w", err)
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return hdr, claims, nil, nil, fmt.Errorf("dpop proof: decode claims: %w", err)
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return hdr, claims, nil, nil, fmt.Errorf("dpop proof: decode signature: %w", err)
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return hdr, claims, nil, nil, fmt.Errorf("dpop proof: parse header: %w", err)
	}
	if err := json.Unmarshal(cb, &claims); err != nil {
		return hdr, claims, nil, nil, fmt.Errorf("dpop proof: parse claims: %w", err)
	}
	return hdr, claims, []byte(parts[0] + "." + parts[1]), sig, nil
}

// checkAlgPinned is check 1 (algorithm pinning). It reads the proof's own alg
// header ONLY to compare it against the pinned dpopAlg constant — it never
// uses the header value to select which verification routine runs. That
// selection is fixed by verifyDPoPSignature below, which always attempts
// ECDSA P-256 regardless of alg. Together these two functions are the
// alg-confusion defense: an "alg": "none" or "alg": "HS256" proof is rejected
// here regardless of what the rest of the proof contains.
func checkAlgPinned(hdr dpopHeader) error {
	if hdr.Alg != dpopAlg {
		return fmt.Errorf("dpop proof: alg %q is not the pinned %q", hdr.Alg, dpopAlg)
	}
	return nil
}

// verifyDPoPSignature runs the one, fixed verification path this verifier
// ever runs: ECDSA over P-256, using the jwk embedded in the proof's own
// header. It never branches on hdr.Alg (see checkAlgPinned).
func verifyDPoPSignature(hdr dpopHeader, signingInput, sig []byte) error {
	if len(sig) != 64 {
		return fmt.Errorf("dpop proof: signature must be 64 bytes (r||s), got %d", len(sig))
	}
	if hdr.JWK.Kty != "EC" || hdr.JWK.Crv != "P-256" {
		return fmt.Errorf("dpop proof: jwk must be kty=EC crv=P-256")
	}
	xb, err := base64.RawURLEncoding.DecodeString(hdr.JWK.X)
	if err != nil || len(xb) != 32 {
		return fmt.Errorf("dpop proof: invalid jwk.x")
	}
	yb, err := base64.RawURLEncoding.DecodeString(hdr.JWK.Y)
	if err != nil || len(yb) != 32 {
		return fmt.Errorf("dpop proof: invalid jwk.y")
	}
	curve := elliptic.P256()
	px, py := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
	if !curve.IsOnCurve(px, py) {
		return fmt.Errorf("dpop proof: jwk public point is not on P-256")
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: px, Y: py}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	hash := sha256.Sum256(signingInput)
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return fmt.Errorf("dpop proof: signature does not verify against its embedded jwk")
	}
	return nil
}

// checkDPoPStructural is check 2: typ, htu (normalized exact match — see
// NormalizeHTU: scheme+host+path, query string and fragment excluded), htm,
// and a present, non-empty jti.
func checkDPoPStructural(hdr dpopHeader, claims DPoPClaims, method, rawURL string) error {
	if hdr.Typ != dpopTyp {
		return fmt.Errorf("dpop proof: typ %q, want %q", hdr.Typ, dpopTyp)
	}
	if claims.JTI == "" {
		return fmt.Errorf("dpop proof: jti must be present and non-empty")
	}
	if claims.HTM != method {
		return fmt.Errorf("dpop proof: htm %q does not match request method %q", claims.HTM, method)
	}
	wantHTU, err := NormalizeHTU(rawURL)
	if err != nil {
		return fmt.Errorf("dpop proof: normalize request url: %w", err)
	}
	if claims.HTU != wantHTU {
		return fmt.Errorf("dpop proof: htu %q does not match request url %q", claims.HTU, wantHTU)
	}
	return nil
}

// checkDPoPFreshness is check 3: iat must fall within [-dpopMaxAge,
// +dpopFreshnessSkew] of now.
func checkDPoPFreshness(claims DPoPClaims, now time.Time) error {
	age := now.Sub(time.Unix(claims.IAT, 0))
	if age > dpopMaxAge {
		return fmt.Errorf("dpop proof: iat is %s old, exceeds max age %s", age, dpopMaxAge)
	}
	if age < -dpopFreshnessSkew {
		return fmt.Errorf("dpop proof: iat is %s in the future, exceeds skew allowance %s", -age, dpopFreshnessSkew)
	}
	return nil
}

// checkDPoPKeyConfirmation is check 4, the actual sender-constraint: the
// proof's embedded jwk thumbprint must equal the cnf.jkt bound to the access
// token being presented. This is deliberately a distinct check (and, per the
// DoD, a distinct test) from signature validity — a proof can be perfectly,
// validly signed by SOME key and still fail this check because it isn't the
// key the token is bound to.
func checkDPoPKeyConfirmation(hdr dpopHeader, expectJKT string) error {
	if hdr.JWK.thumbprint() != expectJKT {
		return fmt.Errorf("dpop proof: jwk thumbprint does not match the token's bound cnf.jkt")
	}
	return nil
}

// checkDPoPAth is check 5: on a resource request (accessToken non-empty),
// ath must equal base64url(SHA-256(accessToken)).
func checkDPoPAth(claims DPoPClaims, accessToken string) error {
	sum := sha256.Sum256([]byte(accessToken))
	if want := b64url(sum[:]); claims.Ath != want {
		return fmt.Errorf("dpop proof: ath does not match sha256(access token)")
	}
	return nil
}

// DPoPReplayStore tracks used jti values and the server-issued nonce
// lifecycle (RFC 9449 §8) in one bounded store — nonces share jti's
// retention discipline per the design doc. It mirrors NonceStore's
// Use(id, expiry, now) bool shape (policy/delegation.go) for a familiar
// convention, extended with the issuance half a nonce additionally needs.
type DPoPReplayStore interface {
	// UseJTI is check 6 (replay tracking): it records jti as used until
	// expiry, returning false if it was already used (replay).
	UseJTI(jti string, expiry, now time.Time) bool
	// IssueNonce mints, records (until expiry), and returns a fresh nonce.
	IssueNonce(expiry, now time.Time) (string, error)
	// ConsumeNonce marks nonce used, returning false if it is unknown,
	// already used, or past its expiry — this is what makes a nonce
	// single-use.
	ConsumeNonce(nonce string, now time.Time) bool
	// Len reports the number of live (unevicted) entries, so a bounded-
	// retention test can assert on store size directly rather than on timing.
	Len() int
}

// MemDPoPReplayStore is the default, in-memory DPoPReplayStore.
//
// Retention is intentionally bounded to the freshness window (dpopMaxAge +
// dpopFreshnessSkew): every jti/nonce is evicted once its own expiry passes,
// so memory never grows without bound under sustained traffic. The direct
// consequence — documented here, not silently left as a gap — is that a
// gateway restart clears this store entirely. A proof captured before restart
// and replayed after restart is only exploitable if it is ALSO still within
// its freshness window (at most dpopMaxAge+dpopFreshnessSkew, i.e. a few
// minutes, by construction): this is an accepted, bounded residual risk
// (see docs/spec/OAUTH-STANDARDS.md, Feature C0), not a silent gap. An
// operator whose threat model requires surviving a replay across a restart
// must back this interface with durable storage instead (e.g. the same
// file-store discipline as FileApprovalStore) — that is a documented option,
// not the default.
type MemDPoPReplayStore struct {
	mu     sync.Mutex
	jtis   map[string]time.Time // jti -> expiry
	nonces map[string]time.Time // nonce -> expiry; deleted on first successful consume
}

// NewMemDPoPReplayStore constructs an empty in-memory replay store.
func NewMemDPoPReplayStore() *MemDPoPReplayStore {
	return &MemDPoPReplayStore{jtis: map[string]time.Time{}, nonces: map[string]time.Time{}}
}

// evictExpired drops entries whose expiry has passed. Must be called with
// m.mu held.
func (m *MemDPoPReplayStore) evictExpired(now time.Time) {
	for k, exp := range m.jtis {
		if now.After(exp) {
			delete(m.jtis, k)
		}
	}
	for k, exp := range m.nonces {
		if now.After(exp) {
			delete(m.nonces, k)
		}
	}
}

func (m *MemDPoPReplayStore) UseJTI(jti string, expiry, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictExpired(now)
	if _, used := m.jtis[jti]; used {
		return false
	}
	m.jtis[jti] = expiry
	return true
}

func (m *MemDPoPReplayStore) IssueNonce(expiry, now time.Time) (string, error) {
	nonce, err := newJTI()
	if err != nil {
		return "", fmt.Errorf("dpop nonce: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictExpired(now)
	m.nonces[nonce] = expiry
	return nonce, nil
}

func (m *MemDPoPReplayStore) ConsumeNonce(nonce string, now time.Time) bool {
	if nonce == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictExpired(now)
	exp, ok := m.nonces[nonce]
	if !ok || now.After(exp) {
		return false
	}
	delete(m.nonces, nonce) // single-use: consumed on first valid presentation
	return true
}

func (m *MemDPoPReplayStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.jtis) + len(m.nonces)
}

// DPoPErrorKind identifies which RFC 9449 wire error a failed verification
// maps to, so a caller can choose between the invalid_dpop_proof and
// use_dpop_nonce responses (see WriteDPoPTokenError/WriteDPoPResourceError).
type DPoPErrorKind int

const (
	DPoPErrInvalidProof DPoPErrorKind = iota
	DPoPErrUseNonce
)

// wireCode is the standard OAuth/RFC 9449 error string for k.
func (k DPoPErrorKind) wireCode() string {
	if k == DPoPErrUseNonce {
		return "use_dpop_nonce"
	}
	return "invalid_dpop_proof"
}

// DPoPVerifyError wraps a verification failure with the wire-error kind it
// maps to.
type DPoPVerifyError struct {
	Kind DPoPErrorKind
	Err  error
}

func (e *DPoPVerifyError) Error() string { return e.Err.Error() }
func (e *DPoPVerifyError) Unwrap() error { return e.Err }

// DPoPVerifier verifies inbound DPoP proofs (RFC 9449 §4.3/§7.1/§8). It is a
// server-side type, structurally and functionally distinct from DPoPSigner
// (client/proof-construction, Feature B) and from policy/sign.go's Ed25519
// checkpoint verification.
type DPoPVerifier struct {
	Replay DPoPReplayStore
}

// NewDPoPVerifier constructs a verifier backed by the default in-memory
// replay store (see MemDPoPReplayStore's residual-risk documentation).
func NewDPoPVerifier() *DPoPVerifier {
	return &DPoPVerifier{Replay: NewMemDPoPReplayStore()}
}

// DPoPVerifyRequest is everything Verify needs to check one presented proof
// against one HTTP request.
type DPoPVerifyRequest struct {
	Proof  string // the raw DPoP proof JWT
	Method string // the actual HTTP method of the request
	URL    string // the actual request URL (htu is checked against NormalizeHTU(URL))
	Now    time.Time

	// AccessToken, when non-empty, is the access token presented alongside
	// this proof; the ath claim is then required to bind to it (check 5).
	// Leave empty for a token-endpoint request, where there is no token yet.
	AccessToken string
	// ExpectJKT, when non-empty, is the cnf.jkt the presented AccessToken is
	// bound to; the proof's jwk thumbprint must match it (check 4). Leave
	// empty when no token is bound yet (e.g. the very first token-endpoint
	// proof, before any token has been issued to bind a key to).
	ExpectJKT string
	// RequireNonce, when true, requires claims.Nonce to be a live,
	// unconsumed nonce this verifier previously issued (RFC 9449 §8).
	RequireNonce bool
}

// Verify runs every required check (RFC 9449 §4.3/§7.1/§8) in order, each a
// named, independently-callable step, and fails closed on the first failing
// one: alg pin -> signature -> structural claims -> freshness -> key
// confirmation -> ath -> nonce -> replay. The jti is recorded (check 6) only
// once every other check has independently passed, and recording happens
// before Verify returns success — so a jti is never "spent" on a proof that
// was going to be rejected anyway, and is always spent before the caller
// treats the request as authorized.
func (v *DPoPVerifier) Verify(req DPoPVerifyRequest) error {
	hdr, claims, signingInput, sig, err := parseDPoPProof(req.Proof)
	if err != nil {
		return &DPoPVerifyError{Kind: DPoPErrInvalidProof, Err: err}
	}
	if err := checkAlgPinned(hdr); err != nil {
		return &DPoPVerifyError{Kind: DPoPErrInvalidProof, Err: err}
	}
	if err := verifyDPoPSignature(hdr, signingInput, sig); err != nil {
		return &DPoPVerifyError{Kind: DPoPErrInvalidProof, Err: err}
	}
	if err := checkDPoPStructural(hdr, claims, req.Method, req.URL); err != nil {
		return &DPoPVerifyError{Kind: DPoPErrInvalidProof, Err: err}
	}
	if err := checkDPoPFreshness(claims, req.Now); err != nil {
		return &DPoPVerifyError{Kind: DPoPErrInvalidProof, Err: err}
	}
	if req.ExpectJKT != "" {
		if err := checkDPoPKeyConfirmation(hdr, req.ExpectJKT); err != nil {
			return &DPoPVerifyError{Kind: DPoPErrInvalidProof, Err: err}
		}
	}
	if req.AccessToken != "" {
		if err := checkDPoPAth(claims, req.AccessToken); err != nil {
			return &DPoPVerifyError{Kind: DPoPErrInvalidProof, Err: err}
		}
	}
	if req.RequireNonce {
		if !v.Replay.ConsumeNonce(claims.Nonce, req.Now) {
			return &DPoPVerifyError{Kind: DPoPErrUseNonce, Err: fmt.Errorf("dpop proof: nonce missing, unknown, expired, or already used")}
		}
	}
	freshUntil := req.Now.Add(dpopMaxAge + dpopFreshnessSkew)
	if !v.Replay.UseJTI(claims.JTI, freshUntil, req.Now) {
		return &DPoPVerifyError{Kind: DPoPErrInvalidProof, Err: fmt.Errorf("dpop proof: jti %q already used (replay)", claims.JTI)}
	}
	return nil
}

// IssueChallengeNonce mints a fresh, single-use, TTL-bound nonce for a
// use_dpop_nonce challenge (RFC 9449 §8) — called by a handler that decides
// (missing/consumed/expired nonce) to re-challenge the caller.
func (v *DPoPVerifier) IssueChallengeNonce(now time.Time) (string, error) {
	return v.Replay.IssueNonce(now.Add(dpopNonceTTL), now)
}

// WriteDPoPTokenError writes a token-endpoint-shaped DPoP error response:
// status 400 with a JSON body matching authorization.TokenErrorResponse
// (RFC 6749 §5.2, extended by RFC 9449 with use_dpop_nonce/
// invalid_dpop_proof) and, when nonce is non-empty, a DPoP-Nonce header. This
// is the exact shape remotebackend.go's parseDPoPChallenge (Feature B) already
// parses via its status==400 JSON-body branch.
func WriteDPoPTokenError(w http.ResponseWriter, kind DPoPErrorKind, nonce string) {
	if nonce != "" {
		w.Header().Set("DPoP-Nonce", nonce)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(authorization.TokenErrorResponse{Error: kind.wireCode()})
}

// WriteDPoPResourceError writes a resource-server-shaped DPoP error response:
// status 401 with a WWW-Authenticate: DPoP error="..." header (RFC 9449 §8)
// and, when nonce is non-empty, a DPoP-Nonce header. This is the exact shape
// remotebackend.go's parseDPoPChallenge (Feature B) already parses via its
// WWW-Authenticate branch.
func WriteDPoPResourceError(w http.ResponseWriter, kind DPoPErrorKind, nonce string) {
	if nonce != "" {
		w.Header().Set("DPoP-Nonce", nonce)
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("DPoP error=%q", kind.wireCode()))
	w.WriteHeader(http.StatusUnauthorized)
}
