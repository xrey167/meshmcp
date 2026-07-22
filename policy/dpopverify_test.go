package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/protocol/authorization"
)

// tamperProofHeader rebuilds proof with its header mutated but claims and
// signature bytes untouched — used to construct alg-confusion attempts. The
// resulting proof is deliberately no longer validly signed over its new
// header (mutating the header changes the signing input), which is fine:
// checkAlgPinned must reject it before signature verification even matters.
func tamperProofHeader(t *testing.T, proof string, mutate func(h *dpopHeader)) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof must have 3 segments, got %d", len(parts))
	}
	var hdr dpopHeader
	if err := json.Unmarshal(decodeSegment(t, parts[0]), &hdr); err != nil {
		t.Fatal(err)
	}
	mutate(&hdr)
	hb, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	return b64url(hb) + "." + parts[1] + "." + parts[2]
}

func asDPoPVerifyError(t *testing.T, err error) *DPoPVerifyError {
	t.Helper()
	var verr *DPoPVerifyError
	if !errors.As(err, &verr) {
		t.Fatalf("expected a *DPoPVerifyError, got %T: %v", err, err)
	}
	return verr
}

// TestVerify_ValidProofAccepted is the baseline positive case every negative
// case below is a variant of.
func TestVerify_ValidProofAccepted(t *testing.T) {
	signer := mustDPoPSigner(t)
	v := NewDPoPVerifier()
	now := time.Unix(1_700_000_000, 0)
	proof, err := signer.Proof(http.MethodPost, "https://res.example.com/mcp", now, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(DPoPVerifyRequest{
		Proof: proof, Method: http.MethodPost, URL: "https://res.example.com/mcp", Now: now,
	}); err != nil {
		t.Fatalf("valid proof should verify: %v", err)
	}
}

// TestVerify_AlgConfusionRejected: a proof whose header claims alg: none or
// alg: HS256 is rejected regardless of whether some interpretation of the
// signature bytes would validate — the pin, not the header, decides.
func TestVerify_AlgConfusionRejected(t *testing.T) {
	signer := mustDPoPSigner(t)
	v := NewDPoPVerifier()
	now := time.Unix(1_700_000_100, 0)
	base, err := signer.Proof(http.MethodGet, "https://res.example.com/mcp", now, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []string{"none", "HS256"} {
		tampered := tamperProofHeader(t, base, func(h *dpopHeader) { h.Alg = alg })
		err := v.Verify(DPoPVerifyRequest{
			Proof: tampered, Method: http.MethodGet, URL: "https://res.example.com/mcp", Now: now,
		})
		if err == nil {
			t.Fatalf("alg=%q must be rejected", alg)
		}
		if verr := asDPoPVerifyError(t, err); verr.Kind != DPoPErrInvalidProof {
			t.Fatalf("alg=%q: want DPoPErrInvalidProof, got %v", alg, verr.Kind)
		}
	}
}

// TestVerify_WrongJKTRejected: a structurally valid, correctly-signed proof
// whose jwk thumbprint does not match the token's bound cnf.jkt is rejected —
// a distinct case from "invalid signature" (this is the sender-constraint).
func TestVerify_WrongJKTRejected(t *testing.T) {
	signer := mustDPoPSigner(t)
	other := mustDPoPSigner(t)
	v := NewDPoPVerifier()
	now := time.Unix(1_700_000_200, 0)
	proof, err := signer.Proof(http.MethodGet, "https://res.example.com/mcp", now, "", "")
	if err != nil {
		t.Fatal(err)
	}
	err = v.Verify(DPoPVerifyRequest{
		Proof: proof, Method: http.MethodGet, URL: "https://res.example.com/mcp", Now: now,
		ExpectJKT: other.Thumbprint(),
	})
	if err == nil {
		t.Fatal("a proof signed by a different key than the token is bound to must be rejected")
	}
	if verr := asDPoPVerifyError(t, err); verr.Kind != DPoPErrInvalidProof {
		t.Fatalf("want DPoPErrInvalidProof, got %v", verr.Kind)
	}
	// The same proof, checked against its OWN signer's thumbprint, verifies —
	// proving the rejection above was specifically about jkt, not the proof.
	if err := v.Verify(DPoPVerifyRequest{
		Proof: proof, Method: http.MethodGet, URL: "https://res.example.com/mcp", Now: now,
		ExpectJKT: signer.Thumbprint(),
	}); err != nil {
		t.Fatalf("the correct jkt should verify: %v", err)
	}
}

// TestVerify_HTUMismatchRejected: a proof built for a different URL or
// method than the actual request is rejected; the documented normalization
// rule (query string excluded) behaves as specified, not stricter or looser.
func TestVerify_HTUMismatchRejected(t *testing.T) {
	signer := mustDPoPSigner(t)
	v := NewDPoPVerifier()
	now := time.Unix(1_700_000_300, 0)

	proof, err := signer.Proof(http.MethodGet, "https://a.example.com/one", now, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(DPoPVerifyRequest{
		Proof: proof, Method: http.MethodGet, URL: "https://b.example.com/two", Now: now,
	}); err == nil {
		t.Fatal("a proof for a different URL must be rejected")
	}

	proof2, err := signer.Proof(http.MethodGet, "https://a.example.com/one", now, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(DPoPVerifyRequest{
		Proof: proof2, Method: http.MethodPost, URL: "https://a.example.com/one", Now: now,
	}); err == nil {
		t.Fatal("a proof for a different method must be rejected")
	}

	// Normalization sub-case: the query string is excluded from htu, so a
	// proof minted against a URL WITH a query string still matches the
	// actual request URL WITHOUT one.
	proof3, err := signer.Proof(http.MethodGet, "https://a.example.com/one?foo=bar", now, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(DPoPVerifyRequest{
		Proof: proof3, Method: http.MethodGet, URL: "https://a.example.com/one", Now: now,
	}); err != nil {
		t.Fatalf("query string must be excluded from the htu comparison: %v", err)
	}
}

// TestVerify_StaleIatRejected: an iat older than the pinned max age (300s) is
// rejected; an iat too far in the future beyond the skew allowance (60s) is
// also rejected.
func TestVerify_StaleIatRejected(t *testing.T) {
	signer := mustDPoPSigner(t)
	v := NewDPoPVerifier()
	iat := time.Unix(1_700_000_400, 0)

	tooOld, err := signer.Proof(http.MethodGet, "https://res.example.com/mcp", iat, "", "")
	if err != nil {
		t.Fatal(err)
	}
	now := iat.Add(dpopMaxAge + time.Second)
	if err := v.Verify(DPoPVerifyRequest{
		Proof: tooOld, Method: http.MethodGet, URL: "https://res.example.com/mcp", Now: now,
	}); err == nil {
		t.Fatal("an iat older than the max age must be rejected")
	}

	tooFuture, err := signer.Proof(http.MethodGet, "https://res.example.com/mcp", iat.Add(dpopFreshnessSkew+time.Second), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(DPoPVerifyRequest{
		Proof: tooFuture, Method: http.MethodGet, URL: "https://res.example.com/mcp", Now: iat,
	}); err == nil {
		t.Fatal("an iat further in the future than the skew allowance must be rejected")
	}
}

// TestVerify_FreshIatWithinSkewAccepted: an iat within the pinned skew
// window (including a few seconds in the future) is accepted — the window
// isn't accidentally zero-tolerance.
func TestVerify_FreshIatWithinSkewAccepted(t *testing.T) {
	signer := mustDPoPSigner(t)
	v := NewDPoPVerifier()
	now := time.Unix(1_700_000_500, 0)

	future, err := signer.Proof(http.MethodGet, "https://res.example.com/mcp", now.Add(10*time.Second), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(DPoPVerifyRequest{
		Proof: future, Method: http.MethodGet, URL: "https://res.example.com/mcp", Now: now,
	}); err != nil {
		t.Fatalf("iat a few seconds in the future (within skew) should verify: %v", err)
	}

	old, err := signer.Proof(http.MethodGet, "https://res.example.com/mcp", now.Add(-250*time.Second), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(DPoPVerifyRequest{
		Proof: old, Method: http.MethodGet, URL: "https://res.example.com/mcp", Now: now,
	}); err != nil {
		t.Fatalf("iat within the max-age window should verify: %v", err)
	}
}

// TestVerify_ReplayedJTIRejected: the same jti presented twice within the
// freshness window: first accepted, second rejected.
func TestVerify_ReplayedJTIRejected(t *testing.T) {
	signer := mustDPoPSigner(t)
	v := NewDPoPVerifier()
	now := time.Unix(1_700_000_600, 0)
	proof, err := signer.Proof(http.MethodGet, "https://res.example.com/mcp", now, "", "")
	if err != nil {
		t.Fatal(err)
	}
	req := DPoPVerifyRequest{Proof: proof, Method: http.MethodGet, URL: "https://res.example.com/mcp", Now: now}
	if err := v.Verify(req); err != nil {
		t.Fatalf("first presentation should verify: %v", err)
	}
	if err := v.Verify(req); err == nil {
		t.Fatal("a replayed jti must be rejected on the second presentation")
	}
}

// TestVerify_JTIRetentionBounded: the replay store's memory usage does not
// grow unboundedly under a long-running stream of unique jtis — entries
// older than the freshness window are evicted, asserted via store size.
func TestVerify_JTIRetentionBounded(t *testing.T) {
	store := NewMemDPoPReplayStore()
	base := time.Unix(1_700_001_000, 0)
	const n = 500
	for i := 0; i < n; i++ {
		now := base.Add(time.Duration(i) * time.Second)
		jti := fmt.Sprintf("jti-%d", i)
		if !store.UseJTI(jti, now.Add(dpopMaxAge+dpopFreshnessSkew), now) {
			t.Fatalf("jti %d should not itself be a replay", i)
		}
	}
	maxLive := int((dpopMaxAge+dpopFreshnessSkew)/time.Second) + 2
	if got := store.Len(); got > maxLive {
		t.Fatalf("replay store grew unboundedly: Len()=%d after %d unique, 1s-apart jtis (want <= %d)", got, n, maxLive)
	}
}

// TestVerify_RestartReplayWindow simulates a verifier restart (a fresh
// in-memory store) and confirms a proof captured before restart, still
// within its freshness window, CAN replay after restart — this is the
// accepted, documented residual risk (docs/spec/OAUTH-STANDARDS.md Feature
// C0), asserted explicitly here so it is a known, tracked behavior, not a
// silent gap. A second assertion confirms a proof outside its freshness
// window is rejected post-restart regardless.
func TestVerify_RestartReplayWindow(t *testing.T) {
	signer := mustDPoPSigner(t)
	t0 := time.Unix(1_700_002_000, 0)

	v1 := NewDPoPVerifier()
	proof, err := signer.Proof(http.MethodGet, "https://res.example.com/mcp", t0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	req := DPoPVerifyRequest{Proof: proof, Method: http.MethodGet, URL: "https://res.example.com/mcp", Now: t0}
	if err := v1.Verify(req); err != nil {
		t.Fatalf("pre-restart verify should succeed: %v", err)
	}

	// Restart: a brand new verifier, empty replay store.
	v2 := NewDPoPVerifier()
	stillFresh := req
	stillFresh.Now = t0.Add(100 * time.Second) // within the freshness window
	if err := v2.Verify(stillFresh); err != nil {
		t.Fatalf("accepted residual risk: a still-fresh proof must replay successfully across a restart, got: %v", err)
	}

	// A stale proof is rejected post-restart regardless — the residual risk
	// is bounded to the freshness window, not an unconditional bypass.
	v3 := NewDPoPVerifier()
	proofOld, err := signer.Proof(http.MethodGet, "https://res.example.com/mcp", t0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	tooLate := DPoPVerifyRequest{Proof: proofOld, Method: http.MethodGet, URL: "https://res.example.com/mcp", Now: t0.Add(dpopMaxAge + time.Second)}
	if err := v3.Verify(tooLate); err == nil {
		t.Fatal("a stale proof must be rejected even against a fresh post-restart store")
	}
}

// TestVerify_AthMismatchRejected: a proof whose ath claim does not match
// sha256(actual presented access token) is rejected on a resource request.
func TestVerify_AthMismatchRejected(t *testing.T) {
	signer := mustDPoPSigner(t)
	v := NewDPoPVerifier()
	now := time.Unix(1_700_003_000, 0)
	token := "opaque-token-1"
	proof, err := signer.Proof(http.MethodGet, "https://res.example.com/mcp", now, token, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(DPoPVerifyRequest{
		Proof: proof, Method: http.MethodGet, URL: "https://res.example.com/mcp", Now: now,
		AccessToken: "a-different-token",
	}); err == nil {
		t.Fatal("ath mismatch must be rejected")
	}
	if err := v.Verify(DPoPVerifyRequest{
		Proof: proof, Method: http.MethodGet, URL: "https://res.example.com/mcp", Now: now,
		AccessToken: token,
	}); err != nil {
		t.Fatalf("the matching access token should verify: %v", err)
	}
}

// TestVerify_NonceRequiredAndSingleUse: a first request without a nonce gets
// use_dpop_nonce; a retry with the issued nonce succeeds; a second request
// reusing the same (already-consumed) nonce is rejected.
func TestVerify_NonceRequiredAndSingleUse(t *testing.T) {
	signer := mustDPoPSigner(t)
	v := NewDPoPVerifier()
	now := time.Unix(1_700_004_000, 0)
	url := "https://res.example.com/mcp"

	proof1, err := signer.Proof(http.MethodGet, url, now, "", "")
	if err != nil {
		t.Fatal(err)
	}
	err = v.Verify(DPoPVerifyRequest{Proof: proof1, Method: http.MethodGet, URL: url, Now: now, RequireNonce: true})
	if verr := asDPoPVerifyError(t, err); verr.Kind != DPoPErrUseNonce {
		t.Fatalf("nonce-less request should get use_dpop_nonce, got %v", verr.Kind)
	}

	nonce, err := v.IssueChallengeNonce(now)
	if err != nil {
		t.Fatal(err)
	}

	proof2, err := signer.Proof(http.MethodGet, url, now, "", nonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(DPoPVerifyRequest{Proof: proof2, Method: http.MethodGet, URL: url, Now: now, RequireNonce: true}); err != nil {
		t.Fatalf("proof carrying the issued nonce should verify: %v", err)
	}

	proof3, err := signer.Proof(http.MethodGet, url, now, "", nonce) // same, already-consumed nonce
	if err != nil {
		t.Fatal(err)
	}
	err = v.Verify(DPoPVerifyRequest{Proof: proof3, Method: http.MethodGet, URL: url, Now: now, RequireNonce: true})
	if verr := asDPoPVerifyError(t, err); verr.Kind != DPoPErrUseNonce {
		t.Fatalf("a reused nonce must be rejected with use_dpop_nonce, got %v", verr.Kind)
	}
}

// TestVerify_NonceExpiry: a nonce presented after its TTL has elapsed is
// rejected, prompting a fresh use_dpop_nonce challenge rather than being
// silently accepted.
func TestVerify_NonceExpiry(t *testing.T) {
	signer := mustDPoPSigner(t)
	v := NewDPoPVerifier()
	url := "https://res.example.com/mcp"
	t0 := time.Unix(1_700_005_000, 0)
	nonce, err := v.IssueChallengeNonce(t0)
	if err != nil {
		t.Fatal(err)
	}

	// Present the nonce after its TTL elapsed, with a FRESH iat so the
	// rejection is isolated to nonce expiry, not iat staleness.
	late := t0.Add(dpopNonceTTL + time.Second)
	proof, err := signer.Proof(http.MethodGet, url, late, "", nonce)
	if err != nil {
		t.Fatal(err)
	}
	err = v.Verify(DPoPVerifyRequest{Proof: proof, Method: http.MethodGet, URL: url, Now: late, RequireNonce: true})
	if verr := asDPoPVerifyError(t, err); verr.Kind != DPoPErrUseNonce {
		t.Fatalf("an expired nonce must prompt a fresh use_dpop_nonce challenge, got %v", verr.Kind)
	}
}

// TestVerify_ErrorResponseShapeIsSpecCompliant: rejections surface
// invalid_dpop_proof / use_dpop_nonce in the wire format a compliant client
// expects. Cross-checked against the same shared protocol/authorization
// helpers (ParseChallenge, TokenErrorResponse) remotebackend.go's
// parseDPoPChallenge (Feature B) uses to parse these exact responses.
func TestVerify_ErrorResponseShapeIsSpecCompliant(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteDPoPResourceError(rec, DPoPErrUseNonce, "nonce-abc")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("resource error status = %d, want 401", rec.Code)
	}
	scheme, params := authorization.ParseChallenge(rec.Header().Get("WWW-Authenticate"))
	if !strings.EqualFold(scheme, "DPoP") || params[authorization.ChallengeError] != "use_dpop_nonce" {
		t.Fatalf("WWW-Authenticate not spec-shaped: %q", rec.Header().Get("WWW-Authenticate"))
	}
	if got := rec.Header().Get("DPoP-Nonce"); got != "nonce-abc" {
		t.Fatalf("DPoP-Nonce header = %q, want nonce-abc", got)
	}

	rec2 := httptest.NewRecorder()
	WriteDPoPTokenError(rec2, DPoPErrInvalidProof, "")
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("token error status = %d, want 400", rec2.Code)
	}
	var te authorization.TokenErrorResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &te); err != nil {
		t.Fatalf("token error body not JSON: %v", err)
	}
	if te.Error != "invalid_dpop_proof" {
		t.Fatalf("token error body = %+v, want invalid_dpop_proof", te)
	}
}

// TestDPoP_ClientServerInterop drives Feature B's DPoPSigner directly against
// Feature C0's DPoPVerifier over real HTTP (httptest), with no fake AS in
// between: a token round trip (including a use_dpop_nonce challenge) and a
// resource round trip (including cnf.jkt binding and the ath check) both
// succeed. This proves the two components speak the same wire protocol, not
// just that each is self-consistent against its own test fakes.
//
// PRM/AS-metadata discovery itself is Feature B's already-tested concern
// (remotebackend_test.go); this test focuses on the token+resource exchange,
// which is what is actually new here (C0's own verifier).
func TestDPoP_ClientServerInterop(t *testing.T) {
	signer := mustDPoPSigner(t)
	verifier := NewDPoPVerifier()
	const accessToken = "interop-access-token-1"

	var mu sync.Mutex
	var boundJKT string

	var srv *httptest.Server
	mux := http.NewServeMux()

	challenge := func(w http.ResponseWriter, err error, resource bool) {
		kind := DPoPErrInvalidProof
		var verr *DPoPVerifyError
		if errors.As(err, &verr) {
			kind = verr.Kind
		}
		nonce := ""
		if kind == DPoPErrUseNonce {
			n, nerr := verifier.IssueChallengeNonce(time.Now())
			if nerr != nil {
				http.Error(w, "nonce issuance failed", http.StatusInternalServerError)
				return
			}
			nonce = n
		}
		if resource {
			WriteDPoPResourceError(w, kind, nonce)
		} else {
			WriteDPoPTokenError(w, kind, nonce)
		}
	}

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		proof := r.Header.Get("DPoP")
		reqURL := "http://" + r.Host + r.URL.Path
		err := verifier.Verify(DPoPVerifyRequest{
			Proof: proof, Method: r.Method, URL: reqURL, Now: time.Now(), RequireNonce: true,
		})
		if err != nil {
			challenge(w, err, false)
			return
		}
		// Bind the issued token's cnf.jkt to the proof's own jwk thumbprint,
		// exactly as a real AS would after independently verifying proof of
		// possession.
		hdr, _, _, _, perr := parseDPoPProof(proof)
		if perr != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		mu.Lock()
		boundJKT = hdr.JWK.thumbprint()
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": accessToken, "token_type": "DPoP", "expires_in": 3600,
		})
	})

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		proof := r.Header.Get("DPoP")
		if auth != "DPoP "+accessToken || proof == "" {
			WriteDPoPResourceError(w, DPoPErrInvalidProof, "")
			return
		}
		reqURL := "http://" + r.Host + r.URL.Path
		mu.Lock()
		jkt := boundJKT
		mu.Unlock()
		err := verifier.Verify(DPoPVerifyRequest{
			Proof: proof, Method: r.Method, URL: reqURL, Now: time.Now(),
			AccessToken: accessToken, ExpectJKT: jkt, RequireNonce: true,
		})
		if err != nil {
			challenge(w, err, true)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	})

	srv = httptest.NewServer(mux)
	defer srv.Close()
	client := srv.Client()

	tokenURL := srv.URL + "/token"
	resourceURL := srv.URL + "/mcp"

	doToken := func(nonce string) *http.Response {
		proof, err := signer.Proof(http.MethodPost, tokenURL, time.Now(), "", nonce)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, tokenURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("DPoP", proof)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := doToken("")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected a use_dpop_nonce challenge (400) on the nonce-less token attempt, got %d", resp.StatusCode)
	}
	var te authorization.TokenErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&te); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if te.Error != "use_dpop_nonce" {
		t.Fatalf("token challenge error = %q, want use_dpop_nonce", te.Error)
	}
	nonce := resp.Header.Get("DPoP-Nonce")
	if nonce == "" {
		t.Fatal("expected a DPoP-Nonce header on the token challenge")
	}

	resp2 := doToken(nonce)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("token request with the issued nonce failed: %d %s", resp2.StatusCode, body)
	}
	var tr authorization.TokenResponse
	if err := json.NewDecoder(resp2.Body).Decode(&tr); err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken != accessToken {
		t.Fatalf("access token = %q, want %q", tr.AccessToken, accessToken)
	}

	doResource := func(nonce string) *http.Response {
		proof, err := signer.Proof(http.MethodPost, resourceURL, time.Now(), tr.AccessToken, nonce)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, resourceURL, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "DPoP "+tr.AccessToken)
		req.Header.Set("DPoP", proof)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	rresp := doResource("")
	if rresp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected a use_dpop_nonce challenge (401) on the nonce-less resource attempt, got %d", rresp.StatusCode)
	}
	scheme, params := authorization.ParseChallenge(rresp.Header.Get("WWW-Authenticate"))
	rresp.Body.Close()
	if !strings.EqualFold(scheme, "DPoP") || params[authorization.ChallengeError] != "use_dpop_nonce" {
		t.Fatalf("resource challenge WWW-Authenticate = %q, want DPoP error=use_dpop_nonce", rresp.Header.Get("WWW-Authenticate"))
	}
	rnonce := rresp.Header.Get("DPoP-Nonce")
	if rnonce == "" {
		t.Fatal("expected a DPoP-Nonce header on the resource challenge")
	}

	rresp2 := doResource(rnonce)
	defer rresp2.Body.Close()
	if rresp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(rresp2.Body)
		t.Fatalf("resource call with nonce+ath+jkt binding failed: %d %s", rresp2.StatusCode, body)
	}
}
