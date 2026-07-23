package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Capability sub-grants (S57): a capability whose DelegatePub names a holder
// key can be narrowed and re-granted WITHOUT the authority — the holder signs
// a child token that embeds the parent token verbatim. Verification walks the
// chain root-first and fails closed on any ambiguity:
//
//   - the root must be signed by a pinned authority key (as ever);
//   - each child must be signed by the Ed25519 key its parent's DelegatePub
//     binds;
//   - each hop must be STRICTLY within scope: same audience, expiry no later
//     than the parent's, tools a subset of the parent's, corpora no wider;
//   - the chain is bounded at maxDelegationChain tokens;
//   - revoking ANY ancestor (by id or by subject/device) kills every
//     descendant;
//   - a single-use capability can never delegate.

// maxDelegationChain bounds a chain to the root plus two sub-grants. Deeper
// chains fail closed.
const maxDelegationChain = 3

// decodeCapability decodes a base64url token into claims without verifying
// anything but the wire format and version.
func decodeCapability(token string) (CapabilityClaims, error) {
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
	return c, nil
}

// DecodeCapabilityClaims decodes a token WITHOUT verifying it — for display
// and for holder-side convenience (e.g. reading the parent's audience before
// delegating). Never authorization: only CapabilityVerifier verifies.
func DecodeCapabilityClaims(token string) (CapabilityClaims, error) {
	return decodeCapability(token)
}

// validateDelegatePub checks the delegation-related claim shape shared by the
// authority issuer and the holder delegation path.
func validateDelegatePub(c CapabilityClaims) error {
	if c.DelegatePub == "" {
		return nil
	}
	raw, err := hex.DecodeString(c.DelegatePub)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("delegate_pub is not a valid hex Ed25519 public key")
	}
	if c.SingleUse {
		return fmt.Errorf("a single-use capability cannot authorize delegation")
	}
	return nil
}

// globChars are the path.Match metacharacters. A child scope entry containing
// any of them must be inherited verbatim from the parent — proving one glob a
// subset of another is ambiguous, and ambiguity denies.
const globChars = `*?[\`

// withinScope reports whether one child scope entry is provably covered by the
// parent's entries: either it appears verbatim in the parent list, or it is a
// literal name (no glob metacharacters) matched by a parent glob.
func withinScope(entry string, parent []string) bool {
	for _, p := range parent {
		if p == entry {
			return true
		}
	}
	if strings.ContainsAny(entry, globChars) {
		return false
	}
	return matchAnyGlob(parent, entry)
}

// scopeSubset reports whether every child entry is provably within the parent
// scope. An empty child list is NOT a subset here (empty means "unrestricted"
// in both Tools and Corpora semantics, which would widen the grant).
func scopeSubset(child, parent []string) bool {
	if len(child) == 0 {
		return false
	}
	for _, e := range child {
		if !withinScope(e, parent) {
			return false
		}
	}
	return true
}

// checkNarrower enforces that a child token is strictly within its parent's
// scope: same audience, expiry no later, tools a subset, corpora no wider.
// Shared by the holder-side issuer (fail early) and the verifier (authoritative).
func checkNarrower(child, parent CapabilityClaims) error {
	if parent.SingleUse {
		return fmt.Errorf("a single-use capability cannot delegate")
	}
	if parent.DelegatePub == "" {
		return fmt.Errorf("parent capability does not authorize delegation (no delegate_pub)")
	}
	if child.Audience != parent.Audience {
		return fmt.Errorf("sub-grant audience %q does not match parent audience %q", child.Audience, parent.Audience)
	}
	if child.ExpiresAt > parent.ExpiresAt {
		return fmt.Errorf("sub-grant expires after its parent")
	}
	if !scopeSubset(child.Tools, parent.Tools) {
		return fmt.Errorf("sub-grant tools are not a provable subset of the parent's (globs must be inherited verbatim)")
	}
	// Corpora: an empty parent list means unrestricted, so the child is free.
	// A restricted parent requires a non-empty, provably narrower child list —
	// an empty child list would mean unrestricted, i.e. WIDER (fail closed).
	if len(parent.Corpora) > 0 && !scopeSubset(child.Corpora, parent.Corpora) {
		return fmt.Errorf("sub-grant corpora are not a provable subset of the parent's")
	}
	return nil
}

// DelegateCapability mints a sub-grant: the holder of parentToken (whose
// DelegatePub pins delegate's public key) signs child into a new token bound
// to a new subject with a scope no wider than the parent's. The parent token
// is embedded verbatim, so a verifier needs nothing beyond its pinned
// authority keys to validate the whole chain. All narrowing rules are checked
// here to fail early, and re-checked authoritatively at verification.
func DelegateCapability(parentToken string, delegate *Signer, child CapabilityClaims, now time.Time) (string, error) {
	if delegate == nil {
		return "", fmt.Errorf("delegation needs the holder's delegate key")
	}
	parent, err := decodeCapability(parentToken)
	if err != nil {
		return "", fmt.Errorf("parent: %w", err)
	}
	if delegate.PubKeyHex() != parent.DelegatePub {
		return "", fmt.Errorf("delegate key does not match the parent's delegate_pub")
	}
	// Depth: the new token extends the parent's chain by one; the whole chain
	// (root + sub-grants) is bounded at maxDelegationChain tokens.
	depth := 1
	for cur := parent; cur.Parent != ""; {
		cur, err = decodeCapability(cur.Parent)
		if err != nil {
			return "", fmt.Errorf("ancestor: %w", err)
		}
		depth++
		if depth >= maxDelegationChain {
			return "", fmt.Errorf("delegation chain exceeds the maximum depth of %d", maxDelegationChain)
		}
	}

	child.Version = 1
	child.IssuedAt = now.Unix()
	child.Parent = parentToken
	child.PubKey = delegate.PubKeyHex()
	// The sub-grant's ID is ALWAYS generated here, never caller-chosen: the ID
	// keys revocation, and a holder-picked ID could alias another token's (so
	// revoking one collaterally revokes the other). Single-use replay is keyed
	// by the token's signature (see Consume), so even a hand-signed child that
	// bypasses this check cannot burn another token's grant.
	if child.ID != "" {
		return "", fmt.Errorf("sub-grant id is generated, not caller-supplied (ids key revocation)")
	}
	var idb [16]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return "", err
	}
	child.ID = "cap_" + hex.EncodeToString(idb[:])
	if child.Subject == "" || child.Audience == "" || len(child.Tools) == 0 {
		return "", fmt.Errorf("sub-grant needs subject, audience, and at least one tool")
	}
	if err := validateDelegatePub(child); err != nil {
		return "", err
	}
	if child.ExpiresAt <= child.IssuedAt {
		return "", fmt.Errorf("sub-grant expiry must be in the future")
	}
	if child.ExpiresAt-child.IssuedAt > int64(maxCapLifetime/time.Second) {
		return "", fmt.Errorf("sub-grant lifetime exceeds the 24h maximum")
	}
	if err := checkNarrower(child, parent); err != nil {
		return "", err
	}
	child.Sig = hex.EncodeToString(ed25519.Sign(delegate.priv, child.signingBytes()))
	b, _ := json.Marshal(child)
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// verifyDelegated validates a sub-grant by walking its embedded chain. The
// returned claims are the LEAF's (the presented token), so single-use
// consumption and corpus checks apply to the narrowest grant.
func (v *CapabilityVerifier) verifyDelegated(leaf CapabilityClaims, peerKey, backend, tool string) (CapabilityClaims, error) {
	// Collect leaf → root, bounding the depth before any crypto.
	chain := []CapabilityClaims{leaf}
	for cur := leaf; cur.Parent != ""; {
		if len(chain) >= maxDelegationChain {
			return CapabilityClaims{}, fmt.Errorf("capability delegation chain exceeds the maximum depth of %d", maxDelegationChain)
		}
		p, err := decodeCapability(cur.Parent)
		if err != nil {
			return CapabilityClaims{}, fmt.Errorf("capability chain: %w", err)
		}
		chain = append(chain, p)
		cur = p
	}
	// Root: must be authority-issued and pinned.
	root := chain[len(chain)-1]
	key, ok := v.trusted[root.PubKey]
	if !ok {
		return CapabilityClaims{}, fmt.Errorf("capability chain root signed by an unpinned authority")
	}
	sig, err := hex.DecodeString(root.Sig)
	if err != nil || !ed25519.Verify(key, root.signingBytes(), sig) {
		return CapabilityClaims{}, fmt.Errorf("capability chain root signature does not verify")
	}
	// Each hop, root-first: the child must be signed by the parent's delegate
	// key and be strictly narrower.
	for i := len(chain) - 2; i >= 0; i-- {
		parent, child := chain[i+1], chain[i]
		if err := checkNarrower(child, parent); err != nil {
			return CapabilityClaims{}, fmt.Errorf("capability chain: %w", err)
		}
		rawPub, err := hex.DecodeString(parent.DelegatePub)
		if err != nil || len(rawPub) != ed25519.PublicKeySize {
			return CapabilityClaims{}, fmt.Errorf("capability chain: parent delegate_pub is not a valid key")
		}
		if child.PubKey != parent.DelegatePub {
			return CapabilityClaims{}, fmt.Errorf("capability chain: sub-grant not signed under the parent's delegate key")
		}
		csig, err := hex.DecodeString(child.Sig)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(rawPub), child.signingBytes(), csig) {
			return CapabilityClaims{}, fmt.Errorf("capability chain: sub-grant signature does not verify")
		}
	}
	// Every token in the chain must be currently valid and unrevoked —
	// revoking any ancestor (by id or by device/subject) cascades to all
	// descendants.
	now := v.now().Unix()
	for _, c := range chain {
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
			return CapabilityClaims{}, fmt.Errorf("capability (or an ancestor) has been revoked")
		}
		if v.subjectRevoked != nil && v.subjectRevoked(c.Subject) {
			return CapabilityClaims{}, fmt.Errorf("capability subject (device) in the chain has been revoked")
		}
	}
	// Leaf bindings: the presented grant authorizes exactly this caller,
	// backend, and tool.
	if peerKey == "" || leaf.Subject != peerKey {
		return CapabilityClaims{}, fmt.Errorf("capability subject does not match the caller identity")
	}
	if leaf.Audience != backend {
		return CapabilityClaims{}, fmt.Errorf("capability audience %q does not match backend %q", leaf.Audience, backend)
	}
	if !matchAnyGlob(leaf.Tools, tool) {
		return CapabilityClaims{}, fmt.Errorf("capability does not cover tool %q", tool)
	}
	if leaf.SingleUse && v.used == nil {
		return CapabilityClaims{}, fmt.Errorf("capability is single-use but this verifier has no replay cache (fail closed)")
	}
	return leaf, nil
}
