package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"time"
)

// capMetaKey is where a presented capability rides in a tools/call params._meta.
// It is stripped by the filter before the call reaches the backend, trace,
// audit, or secret injection.
const capMetaKey = "com.meshmcp/capability"

// maxCapLifetime bounds a capability's validity — enforced by both the issuer
// and the verifier so a token can never authorize for longer than a day.
const maxCapLifetime = 24 * time.Hour

// CapabilityClaims is an Ed25519-signed, short-lived grant. It authorizes
// tools/call only; non-tool methods stay governed by the policy DSL. The token
// binds to the caller's transport-proven WireGuard key (Subject), one backend
// (Audience), tool globs, and a validity window.
type CapabilityClaims struct {
	Version  int      `json:"v"`
	ID       string   `json:"id"`
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"` // caller WireGuard public key (as reported by the transport)
	Audience string   `json:"aud"` // backend name
	Tools    []string `json:"tools"`
	// Corpora optionally scopes a knowledge grant: which RAG corpora / KG
	// subgraphs this capability may query (globs; empty = no corpus restriction).
	// Auto-signed (signingBytes marshals the whole struct); a knowledge backend
	// checks it with AllowsCorpus in addition to the tool-glob check.
	Corpora   []string `json:"corpora,omitempty"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`
	ExpiresAt int64    `json:"exp"`
	PubKey    string   `json:"pubkey"` // hex authority key — a HINT; must be pinned by the verifier
	Sig       string   `json:"sig,omitempty"`
}

func (c CapabilityClaims) signingBytes() []byte {
	c.Sig = ""
	b, _ := json.Marshal(c)
	return b
}

// IssueCapability signs claims into a base64url token. It stamps version,
// issued-at, and the authority public key, generates an ID if absent, and
// refuses a lifetime over 24h. The caller sets Subject, Audience, Tools,
// ExpiresAt, and (optionally) NotBefore, Issuer, ID.
func (s *Signer) IssueCapability(claims CapabilityClaims, now time.Time) (string, error) {
	claims.Version = 1
	claims.IssuedAt = now.Unix()
	claims.PubKey = s.PubKeyHex()
	if claims.ID == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		claims.ID = "cap_" + hex.EncodeToString(b[:])
	}
	if claims.Subject == "" || claims.Audience == "" || len(claims.Tools) == 0 {
		return "", fmt.Errorf("capability needs subject, audience, and at least one tool")
	}
	// Reject a malformed glob at issue time; otherwise it silently never matches
	// and the authority mints a token that can never authorize anything.
	for _, p := range claims.Tools {
		if _, err := path.Match(p, ""); err != nil {
			return "", fmt.Errorf("capability tool pattern %q is not a valid glob: %w", p, err)
		}
	}
	if claims.ExpiresAt <= claims.IssuedAt {
		return "", fmt.Errorf("capability expiry must be in the future")
	}
	if claims.ExpiresAt-claims.IssuedAt > int64(maxCapLifetime/time.Second) {
		return "", fmt.Errorf("capability lifetime exceeds the 24h maximum")
	}
	claims.Sig = hex.EncodeToString(ed25519.Sign(s.priv, claims.signingBytes()))
	b, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// CapabilityVerifier verifies presented tokens against a pinned set of
// authority public keys. A token never supplies its own trust root: its
// embedded pubkey must be in the pinned set.
type CapabilityVerifier struct {
	trusted        map[string]ed25519.PublicKey
	now            func() time.Time
	revoked        func(id string) bool
	subjectRevoked func(sub string) bool
}

// NewCapabilityVerifier pins the given hex authority public keys.
func NewCapabilityVerifier(publicKeysHex []string, now func() time.Time) (*CapabilityVerifier, error) {
	if now == nil {
		now = time.Now
	}
	v := &CapabilityVerifier{trusted: map[string]ed25519.PublicKey{}, now: now}
	for _, h := range publicKeysHex {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid trusted capability key %q", short(h))
		}
		v.trusted[h] = ed25519.PublicKey(raw)
	}
	if len(v.trusted) == 0 {
		return nil, fmt.Errorf("capability verifier needs at least one trusted public key")
	}
	return v, nil
}

// WithRevocation adds an optional revocation predicate (by token ID).
func (v *CapabilityVerifier) WithRevocation(revoked func(id string) bool) *CapabilityVerifier {
	v.revoked = revoked
	return v
}

// WithSubjectRevocation adds an optional revocation predicate keyed by the
// capability's Subject (the peer's WireGuard public key). It is the lost-device
// kill-switch: revoking the subject invalidates every outstanding token minted
// for that identity, which per-token-id revocation cannot express (there is no
// registry of minted tokens to enumerate).
func (v *CapabilityVerifier) WithSubjectRevocation(revoked func(sub string) bool) *CapabilityVerifier {
	v.subjectRevoked = revoked
	return v
}

// Verify decodes and validates a token for a specific caller, backend, and
// tool. It fails closed: any decode, trust, signature, binding, time, or
// revocation problem returns an error and no claims.
func (v *CapabilityVerifier) Verify(token, peerKey, backend, tool string) (CapabilityClaims, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return CapabilityClaims{}, fmt.Errorf("capability is not valid base64url")
	}
	var c CapabilityClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return CapabilityClaims{}, fmt.Errorf("capability is not valid JSON")
	}
	if c.Version != 1 {
		return CapabilityClaims{}, fmt.Errorf("unsupported capability version %d", c.Version)
	}
	// Trust root: the embedded key MUST be pinned.
	key, ok := v.trusted[c.PubKey]
	if !ok {
		return CapabilityClaims{}, fmt.Errorf("capability signed by an unpinned authority")
	}
	sig, err := hex.DecodeString(c.Sig)
	if err != nil || !ed25519.Verify(key, c.signingBytes(), sig) {
		return CapabilityClaims{}, fmt.Errorf("capability signature does not verify")
	}
	// Bindings.
	if peerKey == "" || c.Subject != peerKey {
		return CapabilityClaims{}, fmt.Errorf("capability subject does not match the caller identity")
	}
	if c.Audience != backend {
		return CapabilityClaims{}, fmt.Errorf("capability audience %q does not match backend %q", c.Audience, backend)
	}
	if !matchAnyGlob(c.Tools, tool) {
		return CapabilityClaims{}, fmt.Errorf("capability does not cover tool %q", tool)
	}
	// Time window (verifier also enforces the 24h ceiling).
	now := v.now().Unix()
	if c.ExpiresAt-c.IssuedAt > int64(maxCapLifetime/time.Second) {
		return CapabilityClaims{}, fmt.Errorf("capability lifetime exceeds the 24h maximum")
	}
	if c.NotBefore != 0 && now < c.NotBefore {
		return CapabilityClaims{}, fmt.Errorf("capability is not yet valid")
	}
	if now >= c.ExpiresAt {
		return CapabilityClaims{}, fmt.Errorf("capability has expired")
	}
	if v.revoked != nil && v.revoked(c.ID) {
		return CapabilityClaims{}, fmt.Errorf("capability has been revoked")
	}
	if v.subjectRevoked != nil && v.subjectRevoked(c.Subject) {
		return CapabilityClaims{}, fmt.Errorf("capability subject (device) has been revoked")
	}
	return c, nil
}

// AllowsCorpus reports whether this capability may query the named corpus /
// subgraph. An empty Corpora list places no corpus restriction (the tool globs
// still apply). A knowledge backend calls this after Verify to gate a query.
func (c CapabilityClaims) AllowsCorpus(name string) bool {
	if len(c.Corpora) == 0 {
		return true
	}
	return matchAnyGlob(c.Corpora, name)
}

func matchAnyGlob(patterns []string, v string) bool {
	for _, p := range patterns {
		if p == "*" || p == v {
			return true
		}
		if ok, _ := path.Match(p, v); ok {
			return true
		}
	}
	return false
}

// SetCapabilityVerifier attaches a capability verifier to the filter. When
// required is true the backend is a capability-only surface: every tools/call
// must present a valid capability, regardless of policy.
func (f *Filter) SetCapabilityVerifier(v *CapabilityVerifier, required bool) {
	f.capVerifier = v
	f.capRequired = required
}

// applyCapability folds a presented capability into the policy decision:
//   - required + no valid token        → deny (capability-only surface);
//   - a presented but invalid token    → deny (fail closed);
//   - a valid token cannot override an explicit deny or a co-sign requirement;
//   - a valid token upgrades a policy-DEFAULT deny (RuleID -1) to allow, and
//     otherwise leaves an already-allowed call allowed.
func (f *Filter) applyCapability(dec Decision, token, tool string) Decision {
	if token == "" {
		if f.capRequired {
			return Decision{Outcome: OutcomeDeny, RuleID: dec.RuleID, Reason: "capability required but none presented"}
		}
		return dec
	}
	claims, err := f.capVerifier.Verify(token, f.caller.PeerKey, f.caller.Backend, tool)
	if err != nil {
		return Decision{Outcome: OutcomeDeny, RuleID: dec.RuleID, Reason: "invalid capability: " + err.Error()}
	}
	// A capability never bypasses an explicit deny or a required co-sign.
	if dec.Outcome == OutcomeCosign {
		return dec
	}
	if dec.Outcome == OutcomeDeny && dec.RuleID != -1 {
		return dec
	}
	// Grant: upgrade a default-deny, or keep an existing allow.
	return Decision{
		Allow:     true,
		Outcome:   OutcomeAllow,
		RuleID:    dec.RuleID,
		Reason:    "capability " + claims.ID + " (" + claims.Issuer + ")",
		AddLabels: dec.AddLabels,
	}
}

// stripCapability removes a presented capability token from a tools/call line's
// params._meta and returns the token plus the rewritten line. The token must
// never reach the backend, trace, audit, or secret injection. If no token is
// present the line is returned unchanged.
func stripCapability(line []byte) (token string, out []byte) {
	return stripMetaToken(line, capMetaKey)
}

// stripMetaToken removes the string-valued security token at the given
// params._meta key from a JSON-RPC line, returning the token plus the rewritten
// line. Shared by the capability and router-delegation strips: a presented
// token must never reach the backend, trace, audit, or secret injection. If no
// token is present the line is returned unchanged.
func stripMetaToken(line []byte, key string) (token string, out []byte) {
	var msg map[string]json.RawMessage
	if json.Unmarshal(line, &msg) != nil {
		return "", line
	}
	params, ok := msg["params"]
	if !ok {
		return "", line
	}
	var pm map[string]json.RawMessage
	if json.Unmarshal(params, &pm) != nil {
		return "", line
	}
	metaRaw, ok := pm["_meta"]
	if !ok {
		return "", line
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(metaRaw, &meta) != nil {
		return "", line
	}
	capRaw, ok := meta[key]
	if !ok {
		return "", line
	}
	_ = json.Unmarshal(capRaw, &token)
	delete(meta, key)
	if len(meta) == 0 {
		delete(pm, "_meta")
	} else {
		mb, _ := json.Marshal(meta)
		pm["_meta"] = mb
	}
	pb, _ := json.Marshal(pm)
	msg["params"] = pb
	ob, _ := json.Marshal(msg)
	return token, append(ob, '\n')
}
