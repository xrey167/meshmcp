package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Router/federation delegation (Phase 4). A router (or federation boundary) is
// an enforcement point for the ORIGINAL caller, not a confused deputy that
// forwards under its own identity. Instead of conveying the downstream caller as
// unsigned _meta (which an upstream must never trust), the router presents a
// signed, short-lived DelegationToken bound to the exact hop, and the upstream
// authorizes the intersection of: original-caller permissions AND router-service
// permissions AND the delegation scope.

// maxDelegationLifetime bounds how long a delegation token is valid.
const maxDelegationLifetime = 5 * time.Minute

// DelegationToken is a signed authorization for a router to act for one caller
// on one upstream hop. Its signature covers every field, so a compromised router
// cannot widen the scope (change tool/backend/audience/args) without the
// authority key.
type DelegationToken struct {
	Version   int    `json:"v"`
	Nonce     string `json:"nonce"`    // unique per token (replay identifier)
	Caller    string `json:"caller"`   // ORIGINAL caller WireGuard public key
	Router    string `json:"router"`   // router (delegate) WireGuard public key
	Audience  string `json:"aud"`      // upstream this token is valid at
	Backend   string `json:"backend"`  // backend the call targets upstream
	Tool      string `json:"tool"`     // tool or method being delegated
	ReqHash   string `json:"req_hash"` // canonical hash of the request arguments
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	PubKey    string `json:"pubkey"`        // trusted router-authority signer (hex)
	Sig       string `json:"sig,omitempty"` // Ed25519 over signingBytes
}

func (t DelegationToken) signingBytes() []byte {
	t.Sig = ""
	b, _ := json.Marshal(t)
	return b
}

// DelegationClaims are the caller-set fields for issuing a token.
type DelegationClaims struct {
	Caller    string
	Router    string
	Audience  string
	Backend   string
	Tool      string
	Args      []byte // request arguments; hashed canonically into ReqHash
	ExpiresAt time.Time
}

// IssueDelegation signs claims into a DelegationToken. The lifetime is capped at
// maxDelegationLifetime — a token can never authorize for longer.
func (s *Signer) IssueDelegation(c DelegationClaims, now time.Time) (DelegationToken, error) {
	if c.Caller == "" || c.Router == "" || c.Audience == "" || c.Backend == "" || c.Tool == "" {
		return DelegationToken{}, fmt.Errorf("delegation: caller, router, audience, backend, and tool are required")
	}
	exp := c.ExpiresAt
	if exp.IsZero() || exp.After(now.Add(maxDelegationLifetime)) {
		exp = now.Add(maxDelegationLifetime)
	}
	tok := DelegationToken{
		Version: 1, Nonce: newNonce(),
		Caller: c.Caller, Router: c.Router, Audience: c.Audience,
		Backend: c.Backend, Tool: c.Tool, ReqHash: canonicalArgsHash(c.Args),
		IssuedAt: now.Unix(), ExpiresAt: exp.Unix(),
	}
	tok.PubKey = s.PubKeyHex()
	tok.Sig = hex.EncodeToString(ed25519.Sign(s.priv, tok.signingBytes()))
	return tok, nil
}

// DelegationRequest is what an upstream checks a presented token against — the
// actual hop it is about to serve.
type DelegationRequest struct {
	Router   string // the peer that connected upstream (transport-proven)
	Audience string // this upstream's own identity
	Backend  string
	Tool     string
	Args     []byte
}

// NonceStore records used delegation nonces for replay protection.
type NonceStore interface {
	// Use marks nonce used until expiry, returning false if it was already used.
	Use(nonce string, expiry time.Time, now time.Time) bool
}

// MemNonceStore is an in-memory NonceStore that forgets expired nonces.
type MemNonceStore struct {
	mu   sync.Mutex
	seen map[string]int64 // nonce -> expiry unix
}

func NewMemNonceStore() *MemNonceStore { return &MemNonceStore{seen: map[string]int64{}} }

func (m *MemNonceStore) Use(nonce string, expiry time.Time, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Opportunistically drop expired entries.
	for k, exp := range m.seen {
		if now.Unix() > exp {
			delete(m.seen, k)
		}
	}
	if _, used := m.seen[nonce]; used {
		return false
	}
	m.seen[nonce] = expiry.Unix()
	return true
}

// VerifyDelegation checks a token for a specific upstream hop. expectAuthority is
// the pinned trusted router-authority public key (required — an empty pin never
// verifies). It rejects an unsupported token version, a forged/other signer, a
// token minted for a different audience/backend/tool/router, changed arguments,
// an expired token, an over-long lifetime (the verifier re-enforces the issuer's
// 5-minute ceiling as defense in depth, like CapabilityVerifier), and a replayed
// nonce. A nil nonces store skips replay protection (single-use is then the
// caller's responsibility) — production must supply one.
func VerifyDelegation(tok DelegationToken, expectAuthority string, req DelegationRequest, now time.Time, nonces NonceStore) error {
	if tok.Version != 1 {
		return fmt.Errorf("delegation: unsupported token version %d", tok.Version)
	}
	if expectAuthority == "" || tok.PubKey != expectAuthority {
		return fmt.Errorf("delegation: signer is not the pinned router authority")
	}
	pub, err := hex.DecodeString(tok.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("delegation: invalid authority public key")
	}
	sig, err := hex.DecodeString(tok.Sig)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), tok.signingBytes(), sig) {
		return fmt.Errorf("delegation: signature does not verify")
	}
	// Bind to this exact hop. A token minted for another audience/backend/tool,
	// or presented by a different router, or with changed args, does not apply.
	if tok.Router != req.Router {
		return fmt.Errorf("delegation: token router does not match the presenting peer")
	}
	if tok.Audience != req.Audience {
		return fmt.Errorf("delegation: token audience %q is not this upstream %q", tok.Audience, req.Audience)
	}
	if tok.Backend != req.Backend || tok.Tool != req.Tool {
		return fmt.Errorf("delegation: token is not for this backend/tool")
	}
	if tok.ReqHash != canonicalArgsHash(req.Args) {
		return fmt.Errorf("delegation: request arguments do not match the approved delegation")
	}
	// Time window. The verifier re-enforces the mint-time lifetime ceiling as
	// defense in depth (mirrors CapabilityVerifier): even a token signed by the
	// pinned authority never authorizes longer than maxDelegationLifetime.
	if tok.ExpiresAt-tok.IssuedAt > int64(maxDelegationLifetime/time.Second) {
		return fmt.Errorf("delegation: token lifetime exceeds the %s maximum", maxDelegationLifetime)
	}
	if now.Unix() > tok.ExpiresAt {
		return fmt.Errorf("delegation: token expired")
	}
	if nonces != nil && !nonces.Use(tok.Nonce, time.Unix(tok.ExpiresAt, 0), now) {
		return fmt.Errorf("delegation: token replay (nonce already used)")
	}
	return nil
}

// AuthorizeDelegated computes the upstream's decision as the INTERSECTION of the
// original caller's permissions, the router service's permissions, and a valid
// delegation. It allows only when the delegation verifies AND both the caller
// and the router are independently allowed the tool by the upstream's own
// policy. This makes a router unable to widen a caller's authority, and a caller
// unable to exceed what the router itself may do.
//
// The router leg is checked BEFORE the caller leg: the filter evaluates the
// side-effecting caller leg (single-use approval / rate-token consumption)
// only when the router leg already allows, so on a router deny the untouched
// zero-value caller leg must never be the reported cause (delegation_wire.go).
func AuthorizeDelegated(callerDec, routerDec Decision, delegationErr error) Decision {
	if delegationErr != nil {
		return Decision{Outcome: OutcomeDeny, RuleID: -1, Reason: "delegation invalid: " + delegationErr.Error()}
	}
	if routerDec.Outcome != OutcomeAllow {
		reason := routerDec.Reason
		if reason == "" {
			reason = "router service is not permitted this tool"
		}
		return Decision{Outcome: OutcomeDeny, RuleID: routerDec.RuleID, Reason: "denied by router policy: " + reason}
	}
	if callerDec.Outcome != OutcomeAllow {
		reason := callerDec.Reason
		if reason == "" {
			reason = "original caller is not permitted this tool"
		}
		return Decision{Outcome: OutcomeDeny, RuleID: callerDec.RuleID, Reason: "denied by caller policy: " + reason}
	}
	// Intersection allows: the most restrictive cost applies.
	cost := callerDec.Cost
	if routerDec.Cost > cost {
		cost = routerDec.Cost
	}
	return Decision{Allow: true, Outcome: OutcomeAllow, RuleID: callerDec.RuleID, Reason: "allowed by caller ∩ router ∩ delegation", Cost: cost}
}
