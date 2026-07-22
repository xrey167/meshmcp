package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// A plugin marketplace manifest is a signed, tamper-evident description of a
// plugin bundle (a policy pack, a tool backend, a decision hook, an audit
// sink, a prompt, an agent, a skill, an eval suite). It is the F14 admission
// primitive: publishing mints a signed manifest, discovery lists manifests,
// and "install" verifies a manifest against a pinned authority key and records
// an audited grant — the plugin CODE itself stays
// compiled in (meshmcp never loads code at runtime; a manifest governs
// distribution and attribution, not execution). The signing/verification shape
// deliberately mirrors CapabilityClaims so the same trust root and fail-closed
// discipline apply.

// ManifestKind enumerates the extension seams a bundle can target. Anything
// outside this set is refused at issue time — a manifest can only describe a
// kind the gateway actually knows how to admit.
const (
	ManifestPolicyPack   = "policy-pack"
	ManifestToolBackend  = "tool-backend"
	ManifestDecisionHook = "decision-hook"
	ManifestAuditSink    = "audit-sink"
	ManifestPrompt       = "prompt"
	ManifestAgent        = "agent"
	ManifestSkill        = "skill"
	ManifestEvalSuite    = "eval-suite"
)

func validManifestKind(k string) bool {
	switch k {
	case ManifestPolicyPack, ManifestToolBackend, ManifestDecisionHook, ManifestAuditSink,
		ManifestPrompt, ManifestAgent, ManifestSkill, ManifestEvalSuite:
		return true
	}
	return false
}

// ManifestClaims is the signed body of a marketplace manifest. ContentHash
// binds the manifest to the exact bundle bytes, so a tampered bundle fails
// verification even under a valid signature.
type ManifestClaims struct {
	Version       int    `json:"v"`
	ID            string `json:"id"`
	Issuer        string `json:"iss"`
	Name          string `json:"name"`           // logical bundle name (marketplace key)
	Kind          string `json:"kind"`           // one of the ManifestKind constants
	BundleVersion string `json:"bundle_version"` // publisher's semantic version string
	ContentHash   string `json:"content_hash"`   // hex sha256 of the bundle bytes
	Summary       string `json:"summary,omitempty"`
	Cost          int    `json:"cost,omitempty"` // metering units charged per install (F29)
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp,omitempty"` // 0 = no expiry (manifests are long-lived)
	PubKey        string `json:"pubkey"`        // hex authority key — a HINT; must be pinned
	Sig           string `json:"sig,omitempty"`
}

// signingBytes is the canonical payload signed/verified — the whole struct with
// Sig cleared (identical idiom to CapabilityClaims.signingBytes).
func (c ManifestClaims) signingBytes() []byte {
	c.Sig = ""
	b, _ := json.Marshal(c)
	return b
}

// HashBundle is the content hash a manifest binds to: hex sha256 of the bundle
// bytes. Publishers hash the bundle, verifiers re-hash and compare.
func HashBundle(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// IssueManifest signs claims into a base64url token. It stamps version, issued
// time, an id, and the signer's public key hint, then validates the required
// fields before signing. Mirrors Signer.IssueCapability.
func (s *Signer) IssueManifest(claims ManifestClaims, now time.Time) (string, error) {
	claims.Version = 1
	claims.IssuedAt = now.Unix()
	claims.PubKey = s.PubKeyHex()
	if claims.ID == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		claims.ID = "mkt_" + hex.EncodeToString(b[:])
	}
	if claims.Name == "" {
		return "", fmt.Errorf("manifest needs a bundle name")
	}
	if !validManifestKind(claims.Kind) {
		return "", fmt.Errorf("manifest kind %q is not one of policy-pack, tool-backend, decision-hook, audit-sink, prompt, agent, skill, eval-suite", claims.Kind)
	}
	if !isHex64(claims.ContentHash) {
		return "", fmt.Errorf("manifest needs a hex sha256 content_hash (64 chars); got %q", claims.ContentHash)
	}
	if claims.Cost < 0 {
		return "", fmt.Errorf("manifest cost must not be negative")
	}
	if claims.ExpiresAt != 0 && claims.ExpiresAt <= now.Unix() {
		return "", fmt.Errorf("manifest expiry must be in the future")
	}
	claims.Sig = hex.EncodeToString(ed25519.Sign(s.priv, claims.signingBytes()))
	b, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ManifestVerifier admits manifests signed by a pinned set of authority keys.
// Verification is fail-closed and mirrors CapabilityVerifier.
type ManifestVerifier struct {
	trusted map[string]ed25519.PublicKey
	now     func() time.Time
	revoked func(id string) bool
}

// NewManifestVerifier pins the hex authority keys a manifest must be signed by.
// At least one key is required (an empty trust root would admit anyone).
func NewManifestVerifier(publicKeysHex []string, now func() time.Time) (*ManifestVerifier, error) {
	if len(publicKeysHex) == 0 {
		return nil, fmt.Errorf("manifest verifier needs at least one trusted authority key")
	}
	trusted := make(map[string]ed25519.PublicKey, len(publicKeysHex))
	for _, h := range publicKeysHex {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid trusted authority key %q", h)
		}
		trusted[h] = ed25519.PublicKey(raw)
	}
	if now == nil {
		now = time.Now
	}
	return &ManifestVerifier{trusted: trusted, now: now}, nil
}

// WithRevocation attaches a predicate consulted after signature + time checks,
// so a published manifest can be pulled from the marketplace by id.
func (v *ManifestVerifier) WithRevocation(revoked func(id string) bool) *ManifestVerifier {
	v.revoked = revoked
	return v
}

// Verify decodes and fully validates a manifest token: pinned trust root,
// Ed25519 signature, expiry, and revocation — returning the claims only on
// success. It does NOT check the content hash (the caller re-hashes the actual
// bundle and calls claims.VerifyContent), so a manifest with no bundle in hand
// can still be listed/inspected but never installed against wrong bytes.
func (v *ManifestVerifier) Verify(token string) (ManifestClaims, error) {
	var zero ManifestClaims
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return zero, fmt.Errorf("manifest is not valid base64url: %w", err)
	}
	var c ManifestClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return zero, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	if c.Version != 1 {
		return zero, fmt.Errorf("unsupported manifest version %d", c.Version)
	}
	key, ok := v.trusted[c.PubKey]
	if !ok {
		return zero, fmt.Errorf("manifest signed by an untrusted authority key")
	}
	sig, err := hex.DecodeString(c.Sig)
	if err != nil || !ed25519.Verify(key, c.signingBytes(), sig) {
		return zero, fmt.Errorf("manifest signature is invalid")
	}
	if !validManifestKind(c.Kind) {
		return zero, fmt.Errorf("manifest kind %q is not admissible", c.Kind)
	}
	now := v.now().Unix()
	if c.ExpiresAt != 0 && now >= c.ExpiresAt {
		return zero, fmt.Errorf("manifest expired")
	}
	if v.revoked != nil && v.revoked(c.ID) {
		return zero, fmt.Errorf("manifest %s is revoked", c.ID)
	}
	return c, nil
}

// VerifyContent binds a verified manifest to bundle bytes in hand: the actual
// hex sha256 must equal the signed content_hash, else the bundle was tampered.
func (c ManifestClaims) VerifyContent(actualHash string) error {
	if c.ContentHash != actualHash {
		return fmt.Errorf("bundle content hash mismatch: manifest pins %s, bundle is %s", short(c.ContentHash), short(actualHash))
	}
	return nil
}

// isHex64 reports whether s is a 64-char hex string.
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
