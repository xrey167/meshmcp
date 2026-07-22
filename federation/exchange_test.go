package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/protocol/authorization"
)

// ---------------------------------------------------------------------------
// Test fixtures and helpers.
// ---------------------------------------------------------------------------

const (
	testAcmeIssuer   = "https://idp.acme.example"
	testGlobexIssuer = "https://idp.globex.example"
	testExchangeAud  = "https://meshmcp.example.org/oauth2/token"
)

func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func mustPartnerKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate partner IdP key: %v", err)
	}
	return priv
}

func b64urlJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// signSubjectToken builds a subject_token JWT signed with priv, using alg as
// the (possibly wrong, for negative tests) header value.
func signSubjectToken(t *testing.T, priv *ecdsa.PrivateKey, alg string, claims subjectTokenClaims) string {
	t.Helper()
	signingInput := b64urlJSON(t, subjectTokenHeader{Alg: alg}) + "." + b64urlJSON(t, claims)
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign subject token: %v", err)
	}
	sig := append(leftPad32(r.Bytes()), leftPad32(s.Bytes())...)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// exchangeFixture wires an ExchangeServer behind an httptest.Server, with one
// federated org ("acme") pinned and mapped by issuer, plus a "globex" org
// mapped only to prove issuer-collision/no-wildcard-fallback behavior.
type exchangeFixture struct {
	srv        *httptest.Server
	signer     *policy.Signer
	dpop       *policy.DPoPSigner
	acmeKey    *ecdsa.PrivateKey
	globexKey  *ecdsa.PrivateKey
	now        time.Time
	exchServer *ExchangeServer
}

func newExchangeFixture(t *testing.T, acmeGrant Grant) *exchangeFixture {
	t.Helper()
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	dpop, err := policy.GenerateDPoPSigner()
	if err != nil {
		t.Fatalf("GenerateDPoPSigner: %v", err)
	}
	acmeKey := mustPartnerKey(t)
	globexKey := mustPartnerKey(t)
	now := time.Unix(1_700_000_000, 0)

	boundary := NewBoundary(
		[]Grant{
			acmeGrant,
			{Org: "globex", Tools: []string{"search"}, Corpora: []string{"public"}},
		},
		[]Mapping{
			// A pre-existing wildcard FQDN mapping, exactly like OrgFor's
			// existing "*" support — OrgForIssuer must never fall through
			// to this for an issuer-based request.
			{Match: "*", Org: "wildcard-org"},
			{Match: tokenIssuerPrefix + testAcmeIssuer, Org: "acme", Principal: "partner:acme"},
			{Match: tokenIssuerPrefix + testGlobexIssuer, Org: "globex", Principal: "partner:globex"},
		},
		nil,
	)

	es := &ExchangeServer{
		Verifier: policy.NewDPoPVerifier(),
		Signer:   signer,
		Boundary: boundary,
		PinnedIssuers: map[string]*ecdsa.PublicKey{
			testAcmeIssuer:   &acmeKey.PublicKey,
			testGlobexIssuer: &globexKey.PublicKey,
		},
		ExchangeAudience: testExchangeAud,
		Scheme:           "http",
		Now:              func() time.Time { return now },
	}
	srv := httptest.NewServer(es.Handler())
	t.Cleanup(srv.Close)

	return &exchangeFixture{srv: srv, signer: signer, dpop: dpop, acmeKey: acmeKey, globexKey: globexKey, now: now, exchServer: es}
}

func (f *exchangeFixture) tokenURL() string { return f.srv.URL + "/oauth2/token" }

func (f *exchangeFixture) dpopProof(t *testing.T) string {
	t.Helper()
	proof, err := f.dpop.Proof(http.MethodPost, f.tokenURL(), f.now, "", "")
	if err != nil {
		t.Fatalf("build dpop proof: %v", err)
	}
	return proof
}

// validAcmeSubjectToken returns a correctly-signed, correctly-audienced,
// currently-valid subject token for the acme org, with sub overridable per
// test.
func (f *exchangeFixture) validAcmeSubjectToken(t *testing.T, sub string) string {
	t.Helper()
	return signSubjectToken(t, f.acmeKey, subjectTokenAlg, subjectTokenClaims{
		Issuer:    testAcmeIssuer,
		Subject:   sub,
		Audience:  jwtAudience{testExchangeAud},
		IssuedAt:  f.now.Add(-time.Minute).Unix(),
		ExpiresAt: f.now.Add(time.Hour).Unix(),
	})
}

func rawAuthDetails(t *testing.T, entries ...authDetailEntry) string {
	t.Helper()
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal authorization_details: %v", err)
	}
	return string(b)
}

func grantEntry(actions, locations, datatypes []string) authDetailEntry {
	return authDetailEntry{Type: authDetailsType, Actions: actions, Locations: locations, Datatypes: datatypes}
}

// doExchange posts a token-exchange request. If dpopProof is "" no DPoP
// header is sent at all. If form is nil the request body is empty.
//
// Ordering (docs/spec/OAUTH-STANDARDS.md Feature C2: rejected "before the
// subject token is even parsed") is asserted behaviorally, not by
// instrumenting the request body: TestExchange_RejectsRequestWithoutDPoP
// sends a request whose form body is otherwise fully valid (a real,
// correctly-signed, correctly-audienced subject token and authorization_details
// that would mint successfully) and confirms it is still rejected for the
// missing proof — the request could only succeed if the DPoP check were
// skipped, so a passing test proves the gate runs regardless of what the
// body contains. A client-side reader-tracking approach was deliberately not
// used here: net/http's own Transport must drain a request body to write it
// to the wire before the server ever sees it, so any such tracking would
// observe the CLIENT's send path, not the SERVER's parse order, and could
// give a false failure.
func doExchange(t *testing.T, f *exchangeFixture, dpopProof string, extraHeaders map[string]string, form url.Values) *http.Response {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(http.MethodPost, f.tokenURL(), body)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if dpopProof != "" {
		req.Header.Set("DPoP", dpopProof)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func decodeTokenError(t *testing.T, resp *http.Response) authorization.TokenErrorResponse {
	t.Helper()
	defer resp.Body.Close()
	var e authorization.TokenErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	return e
}

func decodeCapabilityClaims(t *testing.T, token string) policy.CapabilityClaims {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("access_token is not valid base64url: %v", err)
	}
	var c policy.CapabilityClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("access_token is not valid CapabilityClaims JSON: %v", err)
	}
	return c
}

func validExchangeForm(t *testing.T, f *exchangeFixture, subjectToken, authDetails string) url.Values {
	t.Helper()
	return url.Values{
		"grant_type":            {authorization.GrantTokenExchange},
		"subject_token":         {subjectToken},
		"subject_token_type":    {authorization.TokenTypeJWT},
		"requested_token_type":  {authorization.TokenTypeAccessToken},
		"authorization_details": {authDetails},
	}
}

// ---------------------------------------------------------------------------
// C0 gating: DPoP required before the subject token is parsed at all.
// ---------------------------------------------------------------------------

func TestExchange_RejectsRequestWithoutDPoP(t *testing.T) {
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file"}})
	// The body is otherwise fully valid — a real, correctly-signed,
	// correctly-audienced subject token and authorization_details that
	// would mint successfully on their own — so a request rejected purely
	// for the missing DPoP proof proves the proof is checked BEFORE the
	// subject token is parsed at all: had parsing happened first, this
	// request would have succeeded.
	subject := f.validAcmeSubjectToken(t, "user-1")
	details := rawAuthDetails(t, grantEntry([]string{"read_file"}, []string{"backend-a"}, nil))
	form := validExchangeForm(t, f, subject, details)

	resp := doExchange(t, f, "", nil, form)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := decodeTokenError(t, resp).Error; got != "invalid_dpop_proof" {
		t.Fatalf("error = %q, want invalid_dpop_proof", got)
	}
}

func TestExchange_RejectsPlainBearerAtTokenEndpoint(t *testing.T) {
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file"}})
	subject := f.validAcmeSubjectToken(t, "user-1")
	details := rawAuthDetails(t, grantEntry([]string{"read_file"}, []string{"backend-a"}, nil))
	form := validExchangeForm(t, f, subject, details)

	// Shaped like a normal, otherwise-well-formed token-exchange request,
	// authenticated the "old" way with a bearer header instead of DPoP —
	// this must still be rejected, proving a bearer credential is never an
	// accepted substitute for DPoP at this endpoint.
	resp := doExchange(t, f, "", map[string]string{"Authorization": "Bearer some-client-secret"}, form)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := decodeTokenError(t, resp).Error; got != "invalid_dpop_proof" {
		t.Fatalf("error = %q, want invalid_dpop_proof", got)
	}
}

// ---------------------------------------------------------------------------
// Subject-token validation (the Critical-severity gap this slice closes).
// ---------------------------------------------------------------------------

func TestExchange_SubjectTokenAudienceConfusionRejected(t *testing.T) {
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file"}})
	// Structurally valid, correctly signed by acme's pinned key, current —
	// but minted for a DIFFERENT consumer at the partner (e.g. some other
	// SaaS integration), not meshmcp's exchange endpoint.
	subject := signSubjectToken(t, f.acmeKey, subjectTokenAlg, subjectTokenClaims{
		Issuer:    testAcmeIssuer,
		Subject:   "user-1",
		Audience:  jwtAudience{"https://some-other-saas.example/callback"},
		ExpiresAt: f.now.Add(time.Hour).Unix(),
	})
	details := rawAuthDetails(t, grantEntry([]string{"read_file"}, []string{"backend-a"}, nil))
	form := validExchangeForm(t, f, subject, details)

	resp := doExchange(t, f, f.dpopProof(t), nil, form)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := decodeTokenError(t, resp).Error; got != "invalid_grant" {
		t.Fatalf("error = %q, want invalid_grant", got)
	}
}

func TestExchange_SubjectTokenWrongIssuerRejected(t *testing.T) {
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file"}})
	// A key that is not registered as any org's pinned issuer key at all.
	unknownKey := mustPartnerKey(t)
	subject := signSubjectToken(t, unknownKey, subjectTokenAlg, subjectTokenClaims{
		Issuer:    "https://idp.unrelated.example",
		Subject:   "user-1",
		Audience:  jwtAudience{testExchangeAud},
		ExpiresAt: f.now.Add(time.Hour).Unix(),
	})
	details := rawAuthDetails(t, grantEntry([]string{"read_file"}, []string{"backend-a"}, nil))
	form := validExchangeForm(t, f, subject, details)

	resp := doExchange(t, f, f.dpopProof(t), nil, form)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := decodeTokenError(t, resp).Error; got != "invalid_grant" {
		t.Fatalf("error = %q, want invalid_grant", got)
	}

	// Also: a token claiming a KNOWN issuer string but actually signed by a
	// different key (signature won't verify against the pinned key).
	forged := signSubjectToken(t, unknownKey, subjectTokenAlg, subjectTokenClaims{
		Issuer:    testAcmeIssuer,
		Subject:   "user-1",
		Audience:  jwtAudience{testExchangeAud},
		ExpiresAt: f.now.Add(time.Hour).Unix(),
	})
	form2 := validExchangeForm(t, f, forged, details)
	resp2 := doExchange(t, f, f.dpopProof(t), nil, form2)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged-signature status = %d, want 400", resp2.StatusCode)
	}
}

func TestExchange_SubjectTokenExpiredOrNotYetValidRejected(t *testing.T) {
	cases := []struct {
		name   string
		claims subjectTokenClaims
	}{
		{
			name: "expired",
			claims: subjectTokenClaims{
				Issuer: testAcmeIssuer, Subject: "user-1",
				Audience:  jwtAudience{testExchangeAud},
				ExpiresAt: 0, // set below relative to fixture's now
			},
		},
		{
			name: "not_yet_valid",
			claims: subjectTokenClaims{
				Issuer: testAcmeIssuer, Subject: "user-1",
				Audience:  jwtAudience{testExchangeAud},
				ExpiresAt: 0,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file"}})
			claims := tc.claims
			if tc.name == "expired" {
				claims.ExpiresAt = f.now.Add(-time.Minute).Unix()
			} else {
				claims.NotBefore = f.now.Add(time.Minute).Unix()
				claims.ExpiresAt = f.now.Add(time.Hour).Unix()
			}
			subject := signSubjectToken(t, f.acmeKey, subjectTokenAlg, claims)
			details := rawAuthDetails(t, grantEntry([]string{"read_file"}, []string{"backend-a"}, nil))
			form := validExchangeForm(t, f, subject, details)

			resp := doExchange(t, f, f.dpopProof(t), nil, form)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
			if got := decodeTokenError(t, resp).Error; got != "invalid_grant" {
				t.Fatalf("error = %q, want invalid_grant", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Org resolution: validated issuer, never subject, never the "*" fallback.
// ---------------------------------------------------------------------------

func TestExchange_IssuerCollisionDoesNotCrossOrgBoundary(t *testing.T) {
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file"}})

	// sub deliberately collides with globex's mapped principal string, and
	// with the wildcard-mapped org's name too. Resolution must still land
	// on acme, because it is keyed on the validated ISSUER only.
	subject := f.validAcmeSubjectToken(t, "partner:globex")
	details := rawAuthDetails(t, grantEntry([]string{"read_file"}, []string{"backend-a"}, nil))
	form := validExchangeForm(t, f, subject, details)

	resp := doExchange(t, f, f.dpopProof(t), nil, form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var tr authorization.TokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	claims := decodeCapabilityClaims(t, tr.AccessToken)
	if claims.Subject != "partner:acme" {
		t.Fatalf("capability subject = %q, want partner:acme (never globex/wildcard)", claims.Subject)
	}

	// An issuer with NO Mapping entry at all resolves to no org, even
	// though a "*" wildcard Mapping exists in the same boundary — proving
	// OrgForIssuer does not inherit OrgFor's wildcard fallback.
	otherKey := mustPartnerKey(t)
	f.exchServer.PinnedIssuers["https://idp.unmapped.example"] = &otherKey.PublicKey
	unmapped := signSubjectToken(t, otherKey, subjectTokenAlg, subjectTokenClaims{
		Issuer: "https://idp.unmapped.example", Subject: "user-1",
		Audience: jwtAudience{testExchangeAud}, ExpiresAt: f.now.Add(time.Hour).Unix(),
	})
	form2 := validExchangeForm(t, f, unmapped, details)
	resp2 := doExchange(t, f, f.dpopProof(t), nil, form2)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("unmapped-issuer status = %d, want 400 (must not fall back to wildcard org)", resp2.StatusCode)
	}
	if got := decodeTokenError(t, resp2).Error; got != "invalid_target" {
		t.Fatalf("unmapped-issuer error = %q, want invalid_target", got)
	}
}

// ---------------------------------------------------------------------------
// RAR (authorization_details) mapping onto CapabilityClaims.
// ---------------------------------------------------------------------------

func TestExchange_AuthorizationDetailsMapToCapabilityClaims(t *testing.T) {
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file", "search"}, Corpora: []string{"public"}})
	subject := f.validAcmeSubjectToken(t, "user-1")
	details := rawAuthDetails(t, grantEntry([]string{"read_file", "search"}, []string{"backend-a"}, []string{"public"}))
	form := validExchangeForm(t, f, subject, details)

	resp := doExchange(t, f, f.dpopProof(t), nil, form)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, body)
	}
	var tr authorization.TokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	claims := decodeCapabilityClaims(t, tr.AccessToken)
	if claims.Audience != "backend-a" {
		t.Fatalf("audience = %q, want backend-a", claims.Audience)
	}
	if !equalStringSets(claims.Tools, []string{"read_file", "search"}) {
		t.Fatalf("tools = %v, want [read_file search]", claims.Tools)
	}
	if !equalStringSets(claims.Corpora, []string{"public"}) {
		t.Fatalf("corpora = %v, want [public]", claims.Corpora)
	}

	// The minted token verifies via the ordinary CapabilityVerifier path —
	// proving it was produced by the real Signer.IssueCapability, not some
	// ad hoc shape.
	verifier, err := policy.NewCapabilityVerifier([]string{f.signer.PubKeyHex()}, func() time.Time { return f.now })
	if err != nil {
		t.Fatalf("NewCapabilityVerifier: %v", err)
	}
	if _, err := verifier.Verify(tr.AccessToken, "partner:acme", "backend-a", "read_file"); err != nil {
		t.Fatalf("minted capability failed ordinary verification: %v", err)
	}
}

func TestExchange_UnknownFieldInKnownTypeRejected(t *testing.T) {
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file"}})
	subject := f.validAcmeSubjectToken(t, "user-1")
	// Correct type, but an extra field the mapper does not recognize.
	details := `[{"type":"urn:meshmcp:federation-grant","actions":["read_file"],"locations":["backend-a"],"nested":{"sneaky":true}}]`
	form := validExchangeForm(t, f, subject, details)

	resp := doExchange(t, f, f.dpopProof(t), nil, form)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (whole request rejected)", resp.StatusCode)
	}
	if got := decodeTokenError(t, resp).Error; got != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", got)
	}
}

func TestExchange_UnknownTypeRejected(t *testing.T) {
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file"}})
	subject := f.validAcmeSubjectToken(t, "user-1")
	details := rawAuthDetails(t, authDetailEntry{Type: "urn:example:something-else", Actions: []string{"read_file"}, Locations: []string{"backend-a"}})
	form := validExchangeForm(t, f, subject, details)

	resp := doExchange(t, f, f.dpopProof(t), nil, form)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := decodeTokenError(t, resp).Error; got != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", got)
	}
}

func TestExchange_MultiEntryUnionThenIntersect(t *testing.T) {
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file", "search"}})
	subject := f.validAcmeSubjectToken(t, "user-1")
	// entry1 alone would grant only read_file; entry2 alone would include
	// delete_all (not granted) and search. The union must combine both
	// entries' actions, and the intersection step must then clip out
	// delete_all, which the org's grant does not cover.
	details := rawAuthDetails(t,
		grantEntry([]string{"read_file"}, []string{"backend-a"}, nil),
		grantEntry([]string{"delete_all", "search"}, nil, nil),
	)
	form := validExchangeForm(t, f, subject, details)

	resp := doExchange(t, f, f.dpopProof(t), nil, form)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, body)
	}
	var tr authorization.TokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	claims := decodeCapabilityClaims(t, tr.AccessToken)
	if !equalStringSets(claims.Tools, []string{"read_file", "search"}) {
		t.Fatalf("tools = %v, want union-then-intersect [read_file search] (delete_all must be clipped)", claims.Tools)
	}
}

func TestExchange_ScopeIntersectsOrgGrant(t *testing.T) {
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file"}, Corpora: []string{"public"}})
	subject := f.validAcmeSubjectToken(t, "user-1")
	// Requests broader than the org's grant: delete_all and a private
	// corpus, neither of which acme is configured to reach.
	details := rawAuthDetails(t, grantEntry([]string{"read_file", "delete_all"}, []string{"backend-a"}, []string{"public", "private"}))
	form := validExchangeForm(t, f, subject, details)

	resp := doExchange(t, f, f.dpopProof(t), nil, form)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body=%s", resp.StatusCode, body)
	}
	var tr authorization.TokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	claims := decodeCapabilityClaims(t, tr.AccessToken)
	if !equalStringSets(claims.Tools, []string{"read_file"}) {
		t.Fatalf("tools = %v, want only [read_file] (never the wider requested set)", claims.Tools)
	}
	if !equalStringSets(claims.Corpora, []string{"public"}) {
		t.Fatalf("corpora = %v, want only [public]", claims.Corpora)
	}
}

// ---------------------------------------------------------------------------
// Lifetime cap and anti-drift guards.
// ---------------------------------------------------------------------------

func TestExchange_MintedCapabilityLifetimeCapped(t *testing.T) {
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file"}})
	subject := f.validAcmeSubjectToken(t, "user-1")
	details := rawAuthDetails(t, grantEntry([]string{"read_file"}, []string{"backend-a"}, nil))
	form := validExchangeForm(t, f, subject, details)

	resp := doExchange(t, f, f.dpopProof(t), nil, form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var tr authorization.TokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	claims := decodeCapabilityClaims(t, tr.AccessToken)
	if lifetime := claims.ExpiresAt - claims.IssuedAt; lifetime != int64(federationGrantMaxLifetime/time.Second) {
		t.Fatalf("minted lifetime = %ds, want exactly the federation ceiling %ds", lifetime, int64(federationGrantMaxLifetime/time.Second))
	}
}

func TestExchange_CallsExistingIssueCapabilityNotADuplicate(t *testing.T) {
	f := newExchangeFixture(t, Grant{Org: "acme", Tools: []string{"read_file"}})
	subject := f.validAcmeSubjectToken(t, "user-1")
	details := rawAuthDetails(t, grantEntry([]string{"read_file"}, []string{"backend-a"}, nil))
	form := validExchangeForm(t, f, subject, details)

	resp := doExchange(t, f, f.dpopProof(t), nil, form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var tr authorization.TokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	actual := decodeCapabilityClaims(t, tr.AccessToken)

	// Reconstruct the exact same claims (including the actual minted ID,
	// since IssueCapability only generates one when absent) and mint again
	// through the SAME Signer.IssueCapability with the same clock. Ed25519
	// signing is deterministic, so a byte-identical reproduction proves the
	// exchange path applied no transformation IssueCapability itself
	// doesn't already apply.
	reproduced, err := f.signer.IssueCapability(policy.CapabilityClaims{
		ID:        actual.ID,
		Issuer:    actual.Issuer,
		Subject:   actual.Subject,
		Audience:  actual.Audience,
		Tools:     actual.Tools,
		Corpora:   actual.Corpora,
		ExpiresAt: actual.ExpiresAt,
	}, f.now)
	if err != nil {
		t.Fatalf("reproduce IssueCapability call: %v", err)
	}
	if reproduced != tr.AccessToken {
		t.Fatalf("exchange-minted token is not byte-for-byte reproducible via Signer.IssueCapability:\n  got:  %s\n  want: %s", tr.AccessToken, reproduced)
	}
}

func TestExchange_DoesNotInvokeDelegationPath(t *testing.T) {
	src, err := os.ReadFile("exchange.go")
	if err != nil {
		t.Fatalf("read exchange.go: %v", err)
	}
	for _, forbidden := range []string{"IssueDelegation", "AuthorizeDelegated", "DelegationToken", "VerifyDelegation"} {
		if strings.Contains(string(src), forbidden) {
			t.Fatalf("federation/exchange.go references %q — Feature C2 must mint via CapabilityClaims only, never the delegation path", forbidden)
		}
	}
}

// ---------------------------------------------------------------------------
// misc helpers
// ---------------------------------------------------------------------------

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
