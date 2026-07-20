package policy

import (
	"strings"
	"testing"
	"time"
)

func issueTok(t *testing.T, s *Signer, c DelegationClaims, now time.Time) DelegationToken {
	t.Helper()
	tok, err := s.IssueDelegation(c, now)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func baseClaims() DelegationClaims {
	return DelegationClaims{
		Caller: "callerKey", Router: "routerKey", Audience: "upstream1",
		Backend: "payments", Tool: "transfer", Args: []byte(`{"amount":10}`),
	}
}

func baseReq() DelegationRequest {
	return DelegationRequest{
		Router: "routerKey", Audience: "upstream1", Backend: "payments",
		Tool: "transfer", Args: []byte(`{"amount":10}`),
	}
}

// TestDelegationValid: a correctly-issued token verifies for its exact hop.
func TestDelegationValid(t *testing.T) {
	auth := mustSigner(t)
	now := time.Unix(1000, 0)
	tok := issueTok(t, auth, baseClaims(), now)
	if err := VerifyDelegation(tok, auth.PubKeyHex(), baseReq(), now, NewMemNonceStore()); err != nil {
		t.Fatalf("valid delegation should verify: %v", err)
	}
}

// TestDelegationForgedOrigin: unsigned/forged identity is never trusted — a
// token signed by a non-authority key is rejected even if its fields look right.
func TestDelegationForgedOrigin(t *testing.T) {
	auth := mustSigner(t)
	attacker := mustSigner(t)
	now := time.Unix(1000, 0)
	tok := issueTok(t, attacker, baseClaims(), now) // signed by the wrong key
	if err := VerifyDelegation(tok, auth.PubKeyHex(), baseReq(), now, NewMemNonceStore()); err == nil {
		t.Fatal("a token not signed by the pinned authority must be rejected")
	}
	// An empty pin never verifies (trust requires a pinned authority key).
	if err := VerifyDelegation(tok, "", baseReq(), now, NewMemNonceStore()); err == nil {
		t.Fatal("verification without a pinned authority must fail")
	}
}

// TestDelegationWrongBackend: a token minted for another backend/audience does
// not authorize this upstream.
func TestDelegationWrongBackend(t *testing.T) {
	auth := mustSigner(t)
	now := time.Unix(1000, 0)
	tok := issueTok(t, auth, baseClaims(), now)

	otherBackend := baseReq()
	otherBackend.Backend = "deploy"
	if err := VerifyDelegation(tok, auth.PubKeyHex(), otherBackend, now, NewMemNonceStore()); err == nil {
		t.Fatal("delegation for backend 'payments' must not authorize 'deploy'")
	}
	otherAud := baseReq()
	otherAud.Audience = "upstream2"
	if err := VerifyDelegation(tok, auth.PubKeyHex(), otherAud, now, NewMemNonceStore()); err == nil {
		t.Fatal("delegation for audience 'upstream1' must not authorize 'upstream2'")
	}
}

// TestDelegationChangedArgs: changing the arguments invalidates the token.
func TestDelegationChangedArgs(t *testing.T) {
	auth := mustSigner(t)
	now := time.Unix(1000, 0)
	tok := issueTok(t, auth, baseClaims(), now)
	req := baseReq()
	req.Args = []byte(`{"amount":10000}`)
	if err := VerifyDelegation(tok, auth.PubKeyHex(), req, now, NewMemNonceStore()); err == nil {
		t.Fatal("changed arguments must invalidate the delegation")
	}
}

// TestDelegationExpired: an expired token is rejected, and lifetime is capped.
func TestDelegationExpired(t *testing.T) {
	auth := mustSigner(t)
	now := time.Unix(1000, 0)
	tok := issueTok(t, auth, baseClaims(), now)
	if err := VerifyDelegation(tok, auth.PubKeyHex(), baseReq(), now.Add(6*time.Minute), NewMemNonceStore()); err == nil {
		t.Fatal("expired delegation must be rejected")
	}
	// Even asking for a longer lifetime is capped.
	c := baseClaims()
	c.ExpiresAt = now.Add(24 * time.Hour)
	capped := issueTok(t, auth, c, now)
	if capped.ExpiresAt > now.Add(maxDelegationLifetime).Unix() {
		t.Fatal("delegation lifetime must be capped")
	}
}

// TestDelegationReplay: a token's nonce can be used only once.
func TestDelegationReplay(t *testing.T) {
	auth := mustSigner(t)
	now := time.Unix(1000, 0)
	tok := issueTok(t, auth, baseClaims(), now)
	nonces := NewMemNonceStore()
	if err := VerifyDelegation(tok, auth.PubKeyHex(), baseReq(), now, nonces); err != nil {
		t.Fatalf("first use should verify: %v", err)
	}
	if err := VerifyDelegation(tok, auth.PubKeyHex(), baseReq(), now, nonces); err == nil {
		t.Fatal("replaying a delegation token (same nonce) must be rejected")
	}
}

// TestDelegationWrongRouter: a token minted for one router cannot be presented
// by another (a compromised sibling router cannot borrow it).
func TestDelegationWrongRouter(t *testing.T) {
	auth := mustSigner(t)
	now := time.Unix(1000, 0)
	tok := issueTok(t, auth, baseClaims(), now)
	req := baseReq()
	req.Router = "otherRouterKey"
	if err := VerifyDelegation(tok, auth.PubKeyHex(), req, now, NewMemNonceStore()); err == nil {
		t.Fatal("a token for routerKey must not be usable by otherRouterKey")
	}
}

// TestDelegationScopeIntersection: the upstream allows only the intersection of
// caller, router, and delegation. Either the caller OR the router being denied
// denies the call — a router cannot widen a caller's authority, and a caller
// cannot exceed the router's.
func TestDelegationScopeIntersection(t *testing.T) {
	allow := Decision{Outcome: OutcomeAllow, Allow: true}
	deny := Decision{Outcome: OutcomeDeny, Reason: "not permitted"}

	// All allow → allow.
	if d := AuthorizeDelegated(allow, allow, nil); d.Outcome != OutcomeAllow {
		t.Fatal("caller+router+delegation all allow should allow")
	}
	// Router privilege exceeds caller (caller denied) → deny.
	if d := AuthorizeDelegated(deny, allow, nil); d.Outcome != OutcomeDeny {
		t.Fatal("caller-denied must deny even if the router is allowed")
	}
	// Caller privilege exceeds router (router denied) → deny.
	if d := AuthorizeDelegated(allow, deny, nil); d.Outcome != OutcomeDeny {
		t.Fatal("router-denied must deny even if the caller is allowed")
	}
	// Invalid delegation → deny regardless of policy.
	if d := AuthorizeDelegated(allow, allow, errDelegation()); d.Outcome != OutcomeDeny {
		t.Fatal("an invalid delegation must deny")
	}
}

func errDelegation() error { return &delegErr{} }

type delegErr struct{}

func (*delegErr) Error() string { return "bad token" }

// TestDelegationNestedHops: a second hop needs its OWN delegation bound to the
// second audience; the first hop's token does not carry over.
func TestDelegationNestedHops(t *testing.T) {
	auth := mustSigner(t)
	now := time.Unix(1000, 0)
	// Hop 1: routerKey -> upstream1.
	hop1 := issueTok(t, auth, baseClaims(), now)
	// Presenting hop1 at upstream2 (a nested hop) must fail — wrong audience.
	req2 := baseReq()
	req2.Audience = "upstream2"
	req2.Router = "router2Key"
	if err := VerifyDelegation(hop1, auth.PubKeyHex(), req2, now, NewMemNonceStore()); err == nil {
		t.Fatal("a first-hop token must not authorize a nested second hop")
	}
	// A properly-minted hop-2 token verifies.
	c2 := baseClaims()
	c2.Router = "router2Key"
	c2.Audience = "upstream2"
	hop2 := issueTok(t, auth, c2, now)
	if err := VerifyDelegation(hop2, auth.PubKeyHex(), req2, now, NewMemNonceStore()); err != nil {
		t.Fatalf("a correctly-minted hop-2 token should verify: %v", err)
	}
}

// TestDelegationCompromisedRouterCannotWiden: a router that edits the token to
// widen scope (different tool) breaks the signature.
func TestDelegationCompromisedRouterCannotWiden(t *testing.T) {
	auth := mustSigner(t)
	now := time.Unix(1000, 0)
	tok := issueTok(t, auth, baseClaims(), now)
	tok.Tool = "drop_database" // tamper to widen
	req := baseReq()
	req.Tool = "drop_database"
	if err := VerifyDelegation(tok, auth.PubKeyHex(), req, now, NewMemNonceStore()); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampering the tool must break the signature, got: %v", err)
	}
}
