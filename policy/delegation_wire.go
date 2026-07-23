package policy

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Router-delegation wire shape (Phase 4). The router presents a per-call
// DelegationToken in a tools/call params._meta field; the upstream filter
// strips it before the line can reach the backend, trace, audit, or secret
// injection (same invariant as the capability token), verifies it against a
// PINNED authority key set, and authorizes the intersection of the original
// caller's and the router's permissions (AuthorizeDelegated). The raw
// meshmcpOriginPeer/Key _meta stays informational only — identity comes from
// the signed token and the transport, never from unsigned _meta.

// DelegationMetaKey is where a presented delegation token rides in a
// tools/call params._meta (com.meshmcp/ is the security-token namespace).
const DelegationMetaKey = "com.meshmcp/delegation"

// EncodeDelegation serializes a token for the wire: base64url(JSON(token)),
// the same encoding as capability tokens.
func EncodeDelegation(tok DelegationToken) (string, error) {
	b, err := json.Marshal(tok)
	if err != nil {
		return "", fmt.Errorf("delegation: marshal token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodeDelegation parses a wire token. It fails closed on any decode problem.
func DecodeDelegation(encoded string) (DelegationToken, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return DelegationToken{}, fmt.Errorf("delegation: token is not valid base64url")
	}
	var tok DelegationToken
	if err := json.Unmarshal(raw, &tok); err != nil {
		return DelegationToken{}, fmt.Errorf("delegation: token is not valid JSON")
	}
	return tok, nil
}

// DelegationVerifier verifies presented delegation tokens for one backend
// against a pinned set of router-authority public keys, this upstream's own
// audience identity, and a shared nonce store (replay protection). A token
// never supplies its own trust root: its embedded pubkey must be pinned.
type DelegationVerifier struct {
	pins     map[string]bool
	audience string
	nonces   NonceStore
	now      func() time.Time
}

// NewDelegationVerifier pins the given hex authority keys. Fail-closed
// construction: it refuses an empty key set, a malformed key, an empty
// audience (an empty audience would make every verify fail at the first call —
// fail at startup instead), and a nil nonce store (a nil store would skip
// replay protection).
func NewDelegationVerifier(publicKeysHex []string, audience string, nonces NonceStore, now func() time.Time) (*DelegationVerifier, error) {
	if now == nil {
		now = time.Now
	}
	if audience == "" {
		return nil, fmt.Errorf("delegation verifier needs this upstream's own audience identity")
	}
	if nonces == nil {
		return nil, fmt.Errorf("delegation verifier needs a nonce store (replay protection is not optional)")
	}
	v := &DelegationVerifier{pins: map[string]bool{}, audience: audience, nonces: nonces, now: now}
	for _, h := range publicKeysHex {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid trusted delegation authority key %q", short(h))
		}
		v.pins[h] = true
	}
	if len(v.pins) == 0 {
		return nil, fmt.Errorf("delegation verifier needs at least one trusted public key")
	}
	return v, nil
}

// Check decodes and verifies a presented wire token for one exact hop. router
// is the transport-proven connecting peer (never taken from the token or
// _meta). It returns the decoded token so the caller can evaluate the original
// caller's own policy and audit both identities + nonce. Fail-closed: a token
// signed by an unpinned authority verifies against an empty pin, which never
// verifies (delegation.go).
func (v *DelegationVerifier) Check(encoded, router, backend, tool string, args []byte) (DelegationToken, error) {
	tok, err := DecodeDelegation(encoded)
	if err != nil {
		return DelegationToken{}, err
	}
	pin := ""
	if v.pins[tok.PubKey] {
		pin = tok.PubKey
	}
	req := DelegationRequest{Router: router, Audience: v.audience, Backend: backend, Tool: tool, Args: args}
	if err := VerifyDelegation(tok, pin, req, v.now(), v.nonces); err != nil {
		return tok, err
	}
	return tok, nil
}

// SetDelegationVerifier attaches a delegation verifier to the filter. When
// required is true every tools/call must present a valid delegation token,
// regardless of policy. Delegation governs tools/call ONLY (v1): other JSON-RPC
// methods (resources/read, prompts/get, tools/list, ...) are never gated by it
// — required:true does NOT make the whole backend router-only, and those
// surfaces stay governed by the policy's methods rules (spec
// ROUTER-DELEGATION.md, honest v1 limits). When false, a call WITH a token is
// verified and intersected; a call without one falls through to the ordinary
// single-hop policy path (mixed direct+routed backends).
func (f *Filter) SetDelegationVerifier(v *DelegationVerifier, required bool) {
	f.delegVerifier = v
	f.delegRequired = required
}

// delegationAudit carries what the audit record must preserve for a delegated
// call: both identities plus the nonce (spec ROUTER-DELEGATION.md). relevant is
// set whenever a token was presented OR required, so denials (invalid token,
// missing required token) are attributed too.
type delegationAudit struct {
	relevant bool
	caller   string // token's caller claim ("" when no/undecodable token)
	nonce    string
}

// applyDelegation folds a presented delegation token into the policy decision.
// dec is the decision for the CONNECTING peer (the router) under this
// backend's own policy — the router leg of the intersection. The caller leg is
// evaluated from the VERIFIED token's caller claim, never from unsigned _meta.
// Outcomes:
//   - required + no token       → deny (fail closed: no tools/call without a token);
//   - token that fails Check    → deny ("delegation invalid: ...");
//   - valid token               → AuthorizeDelegated(callerDec, routerDec):
//     allow only when caller AND router are independently allowed; a co-sign
//     outcome on either leg is not-allow and therefore denies (a delegated hop
//     is not a co-sign enforcement point in v1); max cost wins.
//
// INVARIANT (a denied call must not spend the caller's budgets): the caller
// leg runs ONLY when the token verified AND the router leg is already allow.
// DecideToolCallBound is side-effecting — it atomically consumes the caller's
// single-use request-bound co-sign approvals and rate-limit tokens — and a
// call the router leg denies anyway must not burn them, or anyone able to keep
// the router leg denying (e.g. by exhausting the router's rate bucket) could
// drain a caller's pending approvals at will. AuthorizeDelegated checks the
// router leg first for the same reason: when the caller leg was skipped, its
// zero value must never be the reported denial cause.
func (f *Filter) applyDelegation(dec Decision, token, tool string, args json.RawMessage) (Decision, delegationAudit) {
	if token == "" {
		if f.delegRequired {
			return Decision{Outcome: OutcomeDeny, RuleID: -1, Reason: "router delegation required: no token presented"},
				delegationAudit{relevant: true}
		}
		return dec, delegationAudit{}
	}
	tok, err := f.delegVerifier.Check(token, f.caller.PeerKey, f.caller.Backend, tool, args)
	var callerDec Decision
	if err == nil && dec.Outcome == OutcomeAllow {
		// The ORIGINAL caller's identity for policy evaluation is the verified
		// token's caller claim (a WireGuard public key): rules match it via
		// pubkey:<key> / group membership.
		callerDec = f.eng.DecideToolCallBound(tok.Caller, tok.Caller, f.caller.Backend, tool, args, f.labelSnapshot())
	}
	return AuthorizeDelegated(callerDec, dec, err),
		delegationAudit{relevant: true, caller: tok.Caller, nonce: tok.Nonce}
}
