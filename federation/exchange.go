// Package federation, this file: RFC 8693 token exchange + RFC 9396 Rich
// Authorization Request (authorization_details) mapping for Feature C2 of
// docs/spec/OAUTH-STANDARDS.md.
//
// Like dcr.go, this is a standalone, independently-testable http.Handler
// surface — it is NOT wired into federate.go's buildBoundaryServer or any
// live listener in this slice (Feature C3, deliberately deferred; see the
// design doc's "exposure-model question"). Every endpoint here is exercised
// only via httptest.NewServer / direct ServeHTTP/function calls in
// exchange_test.go.
package federation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/protocol/authorization"
)

// exchangeMaxBodyBytes bounds every C2 request body (mirrors the S26
// http.MaxBytesReader control already applied to /v1/approve, /v1/deny, and
// dcr.go's /oauth2/register).
const exchangeMaxBodyBytes = 32 << 10

// federationGrantMaxLifetime caps a token-exchange-minted CapabilityClaims.
// This is deliberately SHORTER than policy/capability.go's general-purpose
// maxCapLifetime (24h), not the same ceiling: a federation grant is handed
// to an external, non-mesh partner that has no per-request DPoP rebinding
// the way this façade's own token-endpoint traffic does (Feature C0), so a
// leaked/misused grant's blast radius should be bounded well below the
// general 24h ceiling. This is the implementer decision the design doc's
// C2 section explicitly requires be stated, with its reasoning.
const federationGrantMaxLifetime = 1 * time.Hour

// subjectTokenAlg is the only signing algorithm this exchange accepts for a
// presented subject_token, pinned by server configuration — never selected
// by the token's own alg header (the same alg-confusion defense
// policy/dpopsign.go's DPoP verifier uses, kept as its own constant here
// since this is a distinct trust domain: external partner subject tokens,
// not DPoP proofs).
const subjectTokenAlg = "ES256"

// authDetailsType is the single, closed, enumerated authorization_details
// (RFC 9396) "type" value this exchange accepts. Any entry with a different
// type is rejected outright — this constant is the closed enumeration the
// design doc requires to exist.
const authDetailsType = "urn:meshmcp:federation-grant"

// ExchangeServer implements the RFC 8693 token-exchange endpoint (Feature
// C2). It is a plain, independently-testable http.Handler — see the package
// doc comment above.
type ExchangeServer struct {
	// Verifier checks the mandatory DPoP proof (Feature C0) on every
	// exchange request, before the subject token is parsed at all.
	Verifier *policy.DPoPVerifier
	// Signer mints the resulting grant via the existing
	// Signer.IssueCapability — the exchange never mints a token any other
	// way (no parallel token-minting code path).
	Signer *policy.Signer
	// Boundary resolves org from the validated subject-token issuer (via
	// OrgForIssuer) and supplies the org's configured Grant.Tools/Corpora
	// that the requested authorization_details are intersected against.
	Boundary *Boundary
	// PinnedIssuers is the per-org subject-token trust root: an exact issuer
	// string maps to the ES256 public key its signature is verified
	// against. An issuer absent from this map is unpinned; every subject
	// token claiming it is rejected outright, regardless of signature.
	// There is no JWKS fetch or outbound network call here; the key is
	// static, pinned, per-org operator configuration, matching the design
	// doc's "pinned JWKS/issuer key" requirement without adding a network
	// dependency to this slice.
	PinnedIssuers map[string]*ecdsa.PublicKey
	// ExchangeAudience is meshmcp's exchange endpoint identity; a subject
	// token's aud must contain this value (the Critical-severity
	// audience-confusion check).
	ExchangeAudience string
	// Scheme reconstructs the "htu" an inbound request's DPoP proof must
	// match. RFC 9449 normalizes htu to scheme+host+path, but a server only
	// ever sees host+path on the wire (net/http strips scheme from
	// r.URL for a server-received request) — so the scheme is server
	// configuration, not something read off the request. Defaults to
	// "https" (this façade's listener is TLS-terminated per the design
	// doc's exposure-model recommendation); tests against a plain
	// httptest.NewServer must set this to "http".
	Scheme string
	// Now is an injectable clock; nil means time.Now.
	Now func() time.Time
}

func (s *ExchangeServer) clock() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *ExchangeServer) scheme() string {
	if s.Scheme != "" {
		return s.Scheme
	}
	return "https"
}

// requestURL reconstructs the htu DPoP proofs on this request must match.
// Deliberately built from r.Host + r.URL.Path only (never r.URL.Scheme/
// Host, which a server-received request does not populate) so behavior is
// identical whether this handler is driven via httptest.NewServer or a real
// listener.
func (s *ExchangeServer) requestURL(r *http.Request) string {
	return s.scheme() + "://" + r.Host + r.URL.Path
}

// Handler returns the RFC 8693 mux: POST /oauth2/token. Production wiring
// (listener, TLS) is out of scope for this slice — see the design doc's
// exposure-model question.
func (s *ExchangeServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", s.handleExchange)
	return mux
}

func (s *ExchangeServer) handleExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	now := s.clock()

	// DPoP gates everything else. A missing or invalid proof is rejected
	// BEFORE the request body — and therefore the subject_token — is
	// parsed at all (docs/spec/OAUTH-STANDARDS.md Feature C2: "ordering
	// matters ... rejected before the subject token is even parsed").
	proof := r.Header.Get("DPoP")
	if proof == "" {
		policy.WriteDPoPTokenError(w, policy.DPoPErrInvalidProof, "")
		return
	}
	if err := s.Verifier.Verify(policy.DPoPVerifyRequest{
		Proof:  proof,
		Method: r.Method,
		URL:    s.requestURL(r),
		Now:    now,
	}); err != nil {
		kind := policy.DPoPErrInvalidProof
		var verr *policy.DPoPVerifyError
		if errors.As(err, &verr) {
			kind = verr.Kind
		}
		nonce := ""
		if kind == policy.DPoPErrUseNonce {
			nonce, _ = s.Verifier.IssueChallengeNonce(now)
		}
		policy.WriteDPoPTokenError(w, kind, nonce)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, exchangeMaxBodyBytes)
	if err := r.ParseForm(); err != nil {
		writeExchangeError(w, http.StatusBadRequest, "invalid_request", "malformed or oversized request body")
		return
	}
	if got := r.PostFormValue("grant_type"); got != authorization.GrantTokenExchange {
		writeExchangeError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be "+authorization.GrantTokenExchange)
		return
	}
	subjectToken := r.PostFormValue("subject_token")
	if subjectToken == "" {
		writeExchangeError(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	}
	if r.PostFormValue("subject_token_type") == "" {
		writeExchangeError(w, http.StatusBadRequest, "invalid_request", "subject_token_type is required")
		return
	}

	claims, err := s.validateSubjectToken(subjectToken, now)
	if err != nil {
		writeExchangeError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	// Org resolution uses the VALIDATED issuer, never the subject claim —
	// closes the issuer-collision attack (docs/spec/OAUTH-STANDARDS.md
	// Feature C2).
	org := s.Boundary.OrgForIssuer(claims.Issuer)
	if org == "" {
		writeExchangeError(w, http.StatusBadRequest, "invalid_target", "issuer is not mapped to a federation org")
		return
	}

	entries, err := decodeAuthorizationDetails(r.PostFormValue("authorization_details"))
	if err != nil {
		writeExchangeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tools, corpora, audience, err := unionAuthDetails(entries)
	if err != nil {
		writeExchangeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// The union above is now intersected against the org's existing
	// configured Grant.Tools/Grant.Corpora — never the requested set alone
	// (docs/spec/OAUTH-STANDARDS.md Feature C2, "Scope intersection").
	tools = intersectGranted(tools, s.Boundary.grants[org])
	corpora = clampCorpora(intersectGranted(corpora, s.Boundary.corpora[org]))
	if len(tools) == 0 {
		writeExchangeError(w, http.StatusBadRequest, "invalid_scope", "requested authorization_details grant nothing this org is permitted")
		return
	}

	exp := now.Add(federationGrantMaxLifetime)
	token, err := s.Signer.IssueCapability(policy.CapabilityClaims{
		Issuer:    "federation-exchange:" + org,
		Subject:   s.Boundary.Principal(org),
		Audience:  audience,
		Tools:     tools,
		Corpora:   corpora,
		ExpiresAt: exp.Unix(),
	}, now)
	if err != nil {
		writeExchangeError(w, http.StatusInternalServerError, "server_error", "failed to mint capability: "+err.Error())
		return
	}

	writeExchangeJSON(w, http.StatusOK, authorization.TokenExchangeResponse{
		AccessToken:     token,
		IssuedTokenType: authorization.TokenTypeAccessToken,
		TokenType:       "N_A", // this is a meshmcp CapabilityClaims token, not a bearer/DPoP OAuth token
		ExpiresIn:       int64(federationGrantMaxLifetime / time.Second),
	})
}

func writeExchangeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeExchangeError(w http.ResponseWriter, status int, code, desc string) {
	writeExchangeJSON(w, status, authorization.TokenErrorResponse{Error: code, ErrorDescription: desc})
}

// ---------------------------------------------------------------------------
// Subject-token parsing and validation.
//
// This is a hand-rolled JWT structural decode + ES256 signature check, kept
// deliberately independent of policy/dpopsign.go's DPoP verifier: the two
// verify different tokens for different purposes (an external partner's
// subject token here vs. a DPoP proof there) and must not share a verify
// path. Every trust decision is its own named step, matching the DPoP
// verifier's style, not one opaque function.
// ---------------------------------------------------------------------------

// subjectTokenHeader is the JWT header of an external subject token
// presented to the exchange endpoint.
type subjectTokenHeader struct {
	Alg string `json:"alg"`
}

// jwtAudience decodes a JWT "aud" claim, which per RFC 7519 §4.1.3 may be
// either a single string or an array of strings.
type jwtAudience []string

func (a *jwtAudience) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*a = jwtAudience{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(b, &multi); err != nil {
		return fmt.Errorf("aud must be a string or an array of strings: %w", err)
	}
	*a = jwtAudience(multi)
	return nil
}

func (a jwtAudience) contains(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}

// subjectTokenClaims is the claim set this exchange reads from a presented
// subject_token. Unrecognized claims are ignored — the strict,
// unknown-field-rejecting decode guarantee is scoped to authorization_details
// entries only (RFC 9396), not to the subject token's own claim set.
type subjectTokenClaims struct {
	Issuer    string      `json:"iss"`
	Subject   string      `json:"sub"`
	Audience  jwtAudience `json:"aud"`
	IssuedAt  int64       `json:"iat,omitempty"`
	NotBefore int64       `json:"nbf,omitempty"`
	ExpiresAt int64       `json:"exp"`
}

// parseSubjectToken splits a subject_token JWT into its header, claims, and
// raw signature bytes, plus the exact signing-input bytes the signature
// covers. This is pure structural decoding — it makes no trust decision;
// every trust decision is a separate step below.
func parseSubjectToken(token string) (hdr subjectTokenHeader, claims subjectTokenClaims, signingInput, sig []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return hdr, claims, nil, nil, fmt.Errorf("subject_token: expected 3 dot-separated segments, got %d", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return hdr, claims, nil, nil, fmt.Errorf("subject_token: decode header: %w", err)
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return hdr, claims, nil, nil, fmt.Errorf("subject_token: decode claims: %w", err)
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return hdr, claims, nil, nil, fmt.Errorf("subject_token: decode signature: %w", err)
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return hdr, claims, nil, nil, fmt.Errorf("subject_token: parse header: %w", err)
	}
	if err := json.Unmarshal(cb, &claims); err != nil {
		return hdr, claims, nil, nil, fmt.Errorf("subject_token: parse claims: %w", err)
	}
	return hdr, claims, []byte(parts[0] + "." + parts[1]), sig, nil
}

// verifySubjectTokenSignature checks sig against pub over signingInput using
// ECDSA P-256 (the only algorithm subjectTokenAlg pins). The JWS ES256
// signature encoding (RFC 7518 §3.4) is the fixed-length r||s concatenation,
// not ASN.1 DER — the same shape policy/dpopsign.go's DPoP signatures use.
func verifySubjectTokenSignature(pub *ecdsa.PublicKey, signingInput, sig []byte) error {
	if len(sig) != 64 {
		return fmt.Errorf("subject_token: signature must be 64 bytes (r||s), got %d", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	sVal := new(big.Int).SetBytes(sig[32:])
	hash := sha256.Sum256(signingInput)
	if !ecdsa.Verify(pub, hash[:], r, sVal) {
		return fmt.Errorf("subject_token: signature does not verify against the org's pinned key")
	}
	return nil
}

func checkSubjectTokenAudience(claims subjectTokenClaims, want string) error {
	if want == "" || !claims.Audience.contains(want) {
		return fmt.Errorf("subject_token: aud does not include %q (audience confusion)", want)
	}
	return nil
}

func checkSubjectTokenTimeWindow(claims subjectTokenClaims, now time.Time) error {
	if claims.ExpiresAt == 0 || now.Unix() >= claims.ExpiresAt {
		return fmt.Errorf("subject_token: expired (or missing exp)")
	}
	if claims.NotBefore != 0 && now.Unix() < claims.NotBefore {
		return fmt.Errorf("subject_token: not yet valid (nbf is in the future)")
	}
	return nil
}

// validateSubjectToken runs every required check (docs/spec/OAUTH-STANDARDS.md
// Feature C2, "Subject-token validation") in order, failing closed on the
// first failing one: alg pin -> pinned-issuer key lookup -> signature ->
// audience -> exp/nbf.
func (s *ExchangeServer) validateSubjectToken(token string, now time.Time) (subjectTokenClaims, error) {
	hdr, claims, signingInput, sig, err := parseSubjectToken(token)
	if err != nil {
		return subjectTokenClaims{}, err
	}
	if hdr.Alg != subjectTokenAlg {
		return subjectTokenClaims{}, fmt.Errorf("subject_token: alg %q is not the pinned %q", hdr.Alg, subjectTokenAlg)
	}
	// The claimed issuer is read from the UNVERIFIED token only to select
	// which pinned key to attempt verification with (exactly like a "kid"
	// lookup in a JOSE library) — it grants no trust by itself. An issuer
	// absent from PinnedIssuers, and a present one whose signature does not
	// verify, are both rejected below; this is check 1 (signature against a
	// per-org PINNED key) and covers "unpinned or mismatched issuer"
	// (TestExchange_SubjectTokenWrongIssuerRejected).
	pub, known := s.PinnedIssuers[claims.Issuer]
	if !known || pub == nil {
		return subjectTokenClaims{}, fmt.Errorf("subject_token: issuer %q is not a pinned issuer", claims.Issuer)
	}
	if err := verifySubjectTokenSignature(pub, signingInput, sig); err != nil {
		return subjectTokenClaims{}, err
	}
	// Check 2 (issuer matches the org's configured, pinned issuer) is
	// enforced by construction: pub was looked up BY claims.Issuer, so a
	// successfully-verified token's Issuer is, tautologically, the pinned
	// issuer whose key just verified it. Stated explicitly so a future
	// refactor of PinnedIssuers' keying can't silently drop this guarantee.
	//
	// Check 3: audience contains meshmcp's exchange endpoint identity — the
	// Critical-severity finding this slice exists to close.
	if err := checkSubjectTokenAudience(claims, s.ExchangeAudience); err != nil {
		return subjectTokenClaims{}, err
	}
	// Check 4: exp/nbf on the subject token itself, independent of any
	// exchange-token expiry applied afterward.
	if err := checkSubjectTokenTimeWindow(claims, now); err != nil {
		return subjectTokenClaims{}, err
	}
	return claims, nil
}

// ---------------------------------------------------------------------------
// RFC 9396 authorization_details (RAR) mapping.
// ---------------------------------------------------------------------------

// authDetailEntry is the exact, closed field set accepted for
// authDetailsType. It is decoded with DisallowUnknownFields, so an entry of
// this type carrying any field beyond these four rejects the WHOLE exchange
// request (400), not just that field — the strengthened RAR guarantee
// docs/spec/OAUTH-STANDARDS.md Feature C2 requires.
type authDetailEntry struct {
	Type      string   `json:"type"`
	Actions   []string `json:"actions,omitempty"`   // tool-name globs -> CapabilityClaims.Tools
	Locations []string `json:"locations,omitempty"` // backend name -> CapabilityClaims.Audience
	Datatypes []string `json:"datatypes,omitempty"` // corpus/subgraph globs -> CapabilityClaims.Corpora
}

// decodeAuthorizationDetails parses the RFC 9396 authorization_details form
// parameter (a JSON array, form-encoded as a string) into the closed entry
// type above. Every entry must be of authDetailsType and strictly decodable
// (no unrecognized fields); any violation rejects the entire request, not
// just the offending entry.
func decodeAuthorizationDetails(raw string) ([]authDetailEntry, error) {
	if raw == "" {
		return nil, fmt.Errorf("authorization_details is required")
	}
	var rawEntries []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &rawEntries); err != nil {
		return nil, fmt.Errorf("authorization_details: not a valid JSON array: %w", err)
	}
	if len(rawEntries) == 0 {
		return nil, fmt.Errorf("authorization_details: array must not be empty")
	}
	entries := make([]authDetailEntry, 0, len(rawEntries))
	for i, re := range rawEntries {
		var e authDetailEntry
		dec := json.NewDecoder(bytes.NewReader(re))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("authorization_details[%d]: %w", i, err)
		}
		if e.Type != authDetailsType {
			return nil, fmt.Errorf("authorization_details[%d]: unrecognized type %q", i, e.Type)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// unionAuthDetails combines multiple authorization_details entries as
// specified: the union of their tool/corpus globs. Locations must resolve to
// exactly one backend/audience across all entries (CapabilityClaims.Audience
// is a single string, not a set) — zero or more-than-one distinct value is
// rejected as an ambiguous request.
func unionAuthDetails(entries []authDetailEntry) (tools, corpora []string, audience string, err error) {
	toolSeen := map[string]bool{}
	corpusSeen := map[string]bool{}
	locSeen := map[string]bool{}
	for _, e := range entries {
		for _, a := range e.Actions {
			if a != "" && !toolSeen[a] {
				toolSeen[a] = true
				tools = append(tools, a)
			}
		}
		for _, d := range e.Datatypes {
			if d != "" && !corpusSeen[d] {
				corpusSeen[d] = true
				corpora = append(corpora, d)
			}
		}
		for _, l := range e.Locations {
			if l != "" {
				locSeen[l] = true
			}
		}
	}
	if len(locSeen) > 1 {
		return nil, nil, "", fmt.Errorf("authorization_details: locations must resolve to exactly one backend, got %d distinct values", len(locSeen))
	}
	for l := range locSeen {
		audience = l
	}
	if audience == "" {
		return nil, nil, "", fmt.Errorf("authorization_details: at least one entry must specify a location (backend/audience)")
	}
	if len(tools) == 0 {
		return nil, nil, "", fmt.Errorf("authorization_details: at least one entry must specify actions (tools)")
	}
	return tools, corpora, audience, nil
}

// intersectGranted keeps only the requested globs that the org's configured
// grant (federation/boundary.go's Grant.Tools/Grant.Corpora) actually
// covers: an exact match against a granted entry, a granted "*" wildcard, or
// a concrete (non-glob) requested name matched against a granted glob. Two
// non-identical globs, neither of which is "*", never intersect here — this
// is a conservative subset rule, not general glob-algebra, and is
// deliberately the shape that makes "never wider than the org's grant"
// straightforward to guarantee (docs/spec/OAUTH-STANDARDS.md Feature C2,
// "Scope intersection").
// federationDenyAllCorpus is a corpus glob that no real corpus name can equal
// or match: it contains a NUL byte, illegal in any corpus identifier, and is
// not a valid path.Match pattern. Stamping it on a federation-minted
// capability whose corpora intersection came out empty makes
// policy.CapabilityClaims.AllowsCorpus deny every corpus by default.
const federationDenyAllCorpus = "\x00-federation-no-corpus"

// clampCorpora is the deny-by-default guard for federation-minted capabilities.
// CapabilityClaims.AllowsCorpus treats an empty Corpora list as "no restriction"
// (allow every corpus) — the correct default for a locally-issued capability,
// but the exact opposite of what a cross-org token must do. An empty corpora
// intersection here means the org granted this partner no corpus, or the
// partner requested none; either way the minted token must reach no corpus, not
// all of them. This matches federation/boundary.go's CheckCorpus convention
// ("empty grant means no corpus is shared"). Returning a non-empty deny-all
// sentinel is what enforces that, since the empty list cannot.
func clampCorpora(corpora []string) []string {
	if len(corpora) == 0 {
		return []string{federationDenyAllCorpus}
	}
	return corpora
}

func intersectGranted(requested, granted []string) []string {
	if len(granted) == 0 || len(requested) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, req := range requested {
		if req == "" || seen[req] {
			continue
		}
		for _, g := range granted {
			if g == "*" || g == req {
				out = append(out, req)
				seen[req] = true
				break
			}
			if !strings.ContainsAny(req, "*?[") {
				if ok, _ := path.Match(g, req); ok {
					out = append(out, req)
					seen[req] = true
					break
				}
			}
		}
	}
	return out
}
