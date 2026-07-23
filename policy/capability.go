package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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
	Corpora []string `json:"corpora,omitempty"`
	// SingleUse marks the grant one-shot: the verifier consumes the token's ID
	// (jti) on the first successful Verify and refuses any replay. Requires the
	// verifier to have a replay cache (WithReplayCache) — a SingleUse token
	// presented to a verifier without one fails closed. Omitempty, so existing
	// multi-use tokens are byte-identical and keep verifying.
	SingleUse bool   `json:"one,omitempty"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf,omitempty"`
	ExpiresAt int64  `json:"exp"`
	PubKey    string `json:"pubkey"` // hex authority key — a HINT; must be pinned by the verifier
	Sig       string `json:"sig,omitempty"`

	// DelegatePub authorizes the HOLDER of this capability to mint sub-grants:
	// it is the hex Ed25519 public key whose private half may sign a direct
	// child token (see DelegateCapability). Empty = this capability cannot be
	// delegated. Omitempty, so existing tokens are byte-identical.
	DelegatePub string `json:"delegate_pub,omitempty"`
	// Parent carries the ENCODED parent token of a sub-grant. The verifier
	// walks the chain root-first: the root must be signed by a pinned
	// authority, each child by its parent's DelegatePub key, and every hop
	// must be strictly narrower (tool/corpus subset, same audience, expiry no
	// later than the parent's). Empty = authority-issued root token.
	Parent string `json:"parent,omitempty"`
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
	if claims.Parent != "" {
		return "", fmt.Errorf("an authority-issued capability cannot carry a parent (sub-grants are minted with DelegateCapability)")
	}
	if err := validateDelegatePub(claims); err != nil {
		return "", err
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
	used           NonceStore // jti replay cache for SingleUse grants (nil = no single-use support, fail closed)
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

// WithReplayCache adds the jti replay cache that makes SingleUse grants
// enforceable: the first Consume of a SingleUse token burns its ID (retained
// until the token's own expiry, so retention is bounded by the 24h lifetime
// ceiling); any later presentation is refused. The store is consulted only
// after every other check passes — and, on the tools/call filter path, only
// once the call's final outcome is allow — so a failed or held call never
// burns the grant. MemNonceStore covers a single process; a multi-gateway HA
// deployment needs a shared store (e.g. a pgstore-backed NonceStore, the same
// seam as the delegation nonce store).
func (v *CapabilityVerifier) WithReplayCache(used NonceStore) *CapabilityVerifier {
	v.used = used
	return v
}

// Verify decodes and validates a token for a specific caller, backend, and
// tool, and — for a SingleUse token — consumes its jti. It fails closed: any
// decode, trust, signature, binding, time, or revocation problem returns an
// error and no claims, and a failed Verify never burns a single-use grant.
// Call sites where verification and execution are one step (edge, pubsub) use
// Verify directly; the tools/call filter instead verifies with verifyClaims
// and defers Consume until the call's final outcome is known, so a co-sign
// hold or a downstream deny does not burn the grant.
func (v *CapabilityVerifier) Verify(token, peerKey, backend, tool string) (CapabilityClaims, error) {
	c, err := v.verifyClaims(token, peerKey, backend, tool)
	if err != nil {
		return CapabilityClaims{}, err
	}
	if err := v.Consume(c); err != nil {
		return CapabilityClaims{}, err
	}
	return c, nil
}

// verifyClaims runs every check EXCEPT single-use consumption. A SingleUse
// token presented to a verifier without a replay cache still fails closed
// here, so it can never authorize anything by omission.
func (v *CapabilityVerifier) verifyClaims(token, peerKey, backend, tool string) (CapabilityClaims, error) {
	c, err := decodeCapability(token)
	if err != nil {
		return CapabilityClaims{}, err
	}
	// A sub-grant (Parent set) is verified by walking its chain — the root must
	// be authority-pinned and every hop strictly narrower. See capability_delegation.go.
	if c.Parent != "" {
		return v.verifyDelegated(c, peerKey, backend, tool)
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
	// No replay cache configured = fail closed: a SingleUse token cannot be
	// honored as multi-use by omission (consumption itself happens in Consume).
	if c.SingleUse && v.used == nil {
		return CapabilityClaims{}, fmt.Errorf("capability is single-use but this verifier has no replay cache (fail closed)")
	}
	return c, nil
}

// Consume burns a SingleUse grant's jti in the replay cache (retained until
// the token's own expiry, so retention is bounded by the 24h lifetime
// ceiling); a second Consume of the same jti fails. Multi-use claims are a
// no-op. Callers that split verification from execution (the tools/call
// filter) call this only once the call's final outcome is allow, so a held or
// denied call never burns the grant.
//
// A delegated leaf's replay key is derived from its SIGNATURE, not its ID: a
// sub-grant's ID is holder-chosen (a malicious delegate can hand-sign a token
// with any ID), so keying by ID would let a delegate mint a colliding ID and
// burn ANOTHER token's single-use grant. The Ed25519 signature is unique per
// token content, so re-presenting the same token still burns exactly once
// while distinct tokens can never collide. Authority-issued roots keep the
// jti key (the authority controls those IDs).
func (v *CapabilityVerifier) Consume(c CapabilityClaims) error {
	if !c.SingleUse {
		return nil
	}
	if v.used == nil {
		return fmt.Errorf("capability is single-use but this verifier has no replay cache (fail closed)")
	}
	key := "cap-jti:" + c.ID
	if c.Parent != "" {
		sum := sha256.Sum256([]byte(c.Sig))
		key = "cap-sig:" + hex.EncodeToString(sum[:])
	}
	if !v.used.Use(key, time.Unix(c.ExpiresAt, 0), v.now()) {
		return fmt.Errorf("capability %s has already been used (single-use)", c.ID)
	}
	return nil
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

// applyCapability folds a presented capability into the policy decision. It
// delegates to FoldCapability, the single shared implementation both the stdio
// filter and the Streamable-HTTP enforcer use (the ClassifyRPC precedent), so
// the two transports cannot drift on capability semantics.
//
// A SingleUse grant is NOT consumed here: the returned claims (non-nil only
// when the token was load-bearing) are consumed by handleToolCall once the
// call's final outcome is allow, so a co-sign hold or a downstream
// delegation/hook deny never burns the grant.
func (f *Filter) applyCapability(dec Decision, token, tool string) (Decision, *CapabilityClaims) {
	return FoldCapability(dec, f.capVerifier, f.capRequired, token, f.caller.PeerKey, f.caller.Backend, tool)
}

// FoldCapability folds a presented capability into the policy decision:
//   - required + no valid token        → deny (capability-only surface);
//   - a presented but invalid token    → deny (fail closed);
//   - a valid token cannot override an explicit deny or a co-sign requirement;
//   - a valid token upgrades a policy-DEFAULT deny (RuleID -1) to allow, and
//     otherwise leaves an already-allowed call allowed.
//
// It is the SHARED implementation used by the stdio filter and the
// Streamable-HTTP enforcer, so both transports make the same capability
// decision for the same (policy, token) input.
//
// A SingleUse grant is NOT consumed here: precedence runs first, and the
// returned claims (non-nil only when the token was load-bearing — it upgraded
// a default-deny, or the surface is capability-required) are consumed by the
// caller once the call's final outcome is allow. A co-sign hold, an explicit
// deny, a delegation/hook deny, or a call the policy allowed on its own never
// burns the grant — so a cosign-approved retry still has it.
func FoldCapability(dec Decision, v *CapabilityVerifier, required bool, token, peerKey, backend, tool string) (Decision, *CapabilityClaims) {
	if token == "" {
		if required {
			return Decision{Outcome: OutcomeDeny, RuleID: dec.RuleID, Reason: "capability required but none presented"}, nil
		}
		return dec, nil
	}
	if v == nil {
		// A token was presented but there is nothing pinned to verify it
		// against: fail closed rather than silently ignoring it.
		return Decision{Outcome: OutcomeDeny, RuleID: dec.RuleID, Reason: "invalid capability: no verifier configured"}, nil
	}
	claims, err := v.verifyClaims(token, peerKey, backend, tool)
	if err != nil {
		return Decision{Outcome: OutcomeDeny, RuleID: dec.RuleID, Reason: "invalid capability: " + err.Error()}, nil
	}
	// A capability never bypasses an explicit deny or a required co-sign —
	// checked BEFORE any consumption, so neither burns a single-use grant.
	if dec.Outcome == OutcomeCosign {
		return dec, nil
	}
	if dec.Outcome == OutcomeDeny && dec.RuleID != -1 {
		return dec, nil
	}
	loadBearing := claims.SingleUse && (required || dec.Outcome != OutcomeAllow)
	// Grant: upgrade a default-deny, or keep an existing allow.
	grant := Decision{
		Allow:     true,
		Outcome:   OutcomeAllow,
		RuleID:    dec.RuleID,
		Reason:    "capability " + claims.ID + " (" + claims.Issuer + ")",
		AddLabels: dec.AddLabels,
	}
	if !loadBearing {
		return grant, nil
	}
	c := claims
	return grant, &c
}

// stripCapability removes a presented capability token from a tools/call line's
// params._meta and returns the token plus the rewritten line. The token must
// never reach the backend, trace, audit, or secret injection. If no token is
// present the line is returned unchanged.
func stripCapability(line []byte) (token string, out []byte) {
	return stripMetaToken(line, capMetaKey)
}

// StripCapabilityToken is the exported form of stripCapability, shared with the
// Streamable-HTTP enforcer: it removes a presented capability token from a
// JSON-RPC body's params._meta and returns the token plus the rewritten body,
// so the token never reaches the backend, trace, or audit on ANY transport.
// Output framing follows input framing (a trailing newline is preserved, and
// never added to a body that had none).
func StripCapabilityToken(line []byte) (token string, out []byte) {
	return stripCapability(line)
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
	// Preserve the input's framing: a stdio line keeps its trailing newline,
	// while an HTTP body without one never gains one.
	if len(line) > 0 && line[len(line)-1] == '\n' {
		ob = append(ob, '\n')
	}
	return token, ob
}
