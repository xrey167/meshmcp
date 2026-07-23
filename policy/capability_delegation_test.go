package policy

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// delegationFixture wires an authority, a holder delegate key, and a verifier
// pinning only the authority.
type delegationFixture struct {
	authority *Signer
	delegate  *Signer
	verifier  *CapabilityVerifier
	now       time.Time
}

func newDelegationFixture(t *testing.T) *delegationFixture {
	t.Helper()
	authority, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	delegate, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	v, err := NewCapabilityVerifier([]string{authority.PubKeyHex()}, func() time.Time { return now.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	return &delegationFixture{authority: authority, delegate: delegate, verifier: v, now: now}
}

// issueRoot mints an authority root grant for device A that may delegate.
func (f *delegationFixture) issueRoot(t *testing.T, mutate func(*CapabilityClaims)) string {
	t.Helper()
	claims := CapabilityClaims{
		Issuer:      "authority",
		Subject:     "wg-device-A",
		Audience:    "files",
		Tools:       []string{"read_*", "list_files"},
		DelegatePub: f.delegate.PubKeyHex(),
		ExpiresAt:   f.now.Add(time.Hour).Unix(),
	}
	if mutate != nil {
		mutate(&claims)
	}
	tok, err := f.authority.IssueCapability(claims, f.now)
	if err != nil {
		t.Fatalf("issue root: %v", err)
	}
	return tok
}

// resign re-signs tampered child claims with the given key and re-encodes the
// token — used to craft tokens that DelegateCapability would refuse to mint.
func resign(t *testing.T, c CapabilityClaims, s *Signer) string {
	t.Helper()
	c.Sig = hex.EncodeToString(ed25519.Sign(s.priv, c.signingBytes()))
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestDelegatedCapabilityVerifies(t *testing.T) {
	f := newDelegationFixture(t)
	root := f.issueRoot(t, nil)
	child, err := DelegateCapability(root, f.delegate, CapabilityClaims{
		Subject:   "wg-device-B",
		Audience:  "files",
		Tools:     []string{"read_file"},
		ExpiresAt: f.now.Add(30 * time.Minute).Unix(),
	}, f.now)
	if err != nil {
		t.Fatalf("delegate: %v", err)
	}
	got, err := f.verifier.Verify(child, "wg-device-B", "files", "read_file")
	if err != nil {
		t.Fatalf("verify sub-grant: %v", err)
	}
	if got.Subject != "wg-device-B" {
		t.Fatalf("verified claims are not the leaf's: %+v", got)
	}
	// The sub-grant must not cover tools outside its own (narrower) list, even
	// though the parent's glob would.
	if _, err := f.verifier.Verify(child, "wg-device-B", "files", "read_secrets"); err == nil {
		t.Fatal("sub-grant authorized a tool outside its narrowed list")
	}
	// And it binds the new subject, not the original holder.
	if _, err := f.verifier.Verify(child, "wg-device-A", "files", "read_file"); err == nil {
		t.Fatal("sub-grant verified for the wrong subject")
	}
}

func TestDelegationRefusesWiderScope(t *testing.T) {
	f := newDelegationFixture(t)
	root := f.issueRoot(t, nil)

	// Issue-time refusal: a tool the parent does not grant.
	if _, err := DelegateCapability(root, f.delegate, CapabilityClaims{
		Subject: "wg-device-B", Audience: "files",
		Tools:     []string{"delete_everything"},
		ExpiresAt: f.now.Add(10 * time.Minute).Unix(),
	}, f.now); err == nil {
		t.Fatal("delegation minted a WIDER grant (tool not in parent scope)")
	}
	// A fresh child glob is ambiguous — must fail even though every match of
	// "read_f*" is within "read_*".
	if _, err := DelegateCapability(root, f.delegate, CapabilityClaims{
		Subject: "wg-device-B", Audience: "files",
		Tools:     []string{"read_f*"},
		ExpiresAt: f.now.Add(10 * time.Minute).Unix(),
	}, f.now); err == nil {
		t.Fatal("delegation accepted a non-verbatim child glob (ambiguous subset)")
	}
	// A parent pattern inherited VERBATIM is fine.
	if _, err := DelegateCapability(root, f.delegate, CapabilityClaims{
		Subject: "wg-device-B", Audience: "files",
		Tools:     []string{"read_*"},
		ExpiresAt: f.now.Add(10 * time.Minute).Unix(),
	}, f.now); err != nil {
		t.Fatalf("verbatim-inherited pattern refused: %v", err)
	}

	// Verify-time refusal: hand-sign a wider child under the real delegate key
	// (bypassing DelegateCapability's checks) — the verifier must still deny.
	parent, _ := decodeCapability(root)
	wide := CapabilityClaims{
		Version: 1, ID: "cap_wide", Subject: "wg-device-B", Audience: "files",
		Tools: []string{"delete_everything"}, IssuedAt: f.now.Unix(),
		ExpiresAt: f.now.Add(10 * time.Minute).Unix(),
		PubKey:    parent.DelegatePub, Parent: root,
	}
	tok := resign(t, wide, f.delegate)
	if _, err := f.verifier.Verify(tok, "wg-device-B", "files", "delete_everything"); err == nil {
		t.Fatal("verifier accepted a hand-signed WIDER sub-grant")
	}
}

func TestDelegationRefusesLongerExpiryAndOtherAudience(t *testing.T) {
	f := newDelegationFixture(t)
	root := f.issueRoot(t, nil)
	parent, _ := decodeCapability(root)

	// Expiry beyond the parent's: refused at issue time…
	if _, err := DelegateCapability(root, f.delegate, CapabilityClaims{
		Subject: "wg-device-B", Audience: "files",
		Tools: []string{"read_file"}, ExpiresAt: parent.ExpiresAt + 60,
	}, f.now); err == nil {
		t.Fatal("delegation accepted an expiry beyond the parent's")
	}
	// …and at verify time for a hand-signed token.
	late := CapabilityClaims{
		Version: 1, ID: "cap_late", Subject: "wg-device-B", Audience: "files",
		Tools: []string{"read_file"}, IssuedAt: f.now.Unix(),
		ExpiresAt: parent.ExpiresAt + 60, PubKey: parent.DelegatePub, Parent: root,
	}
	if _, err := f.verifier.Verify(resign(t, late, f.delegate), "wg-device-B", "files", "read_file"); err == nil {
		t.Fatal("verifier accepted a sub-grant outliving its parent")
	}

	// Audience swap: refused.
	other := CapabilityClaims{
		Version: 1, ID: "cap_aud", Subject: "wg-device-B", Audience: "secrets",
		Tools: []string{"read_file"}, IssuedAt: f.now.Unix(),
		ExpiresAt: f.now.Add(10 * time.Minute).Unix(), PubKey: parent.DelegatePub, Parent: root,
	}
	if _, err := f.verifier.Verify(resign(t, other, f.delegate), "wg-device-B", "secrets", "read_file"); err == nil {
		t.Fatal("verifier accepted a sub-grant for a different audience")
	}
}

func TestDelegationSignerMustMatchDelegatePub(t *testing.T) {
	f := newDelegationFixture(t)
	root := f.issueRoot(t, nil)
	rogue, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	// DelegateCapability refuses the wrong key outright.
	if _, err := DelegateCapability(root, rogue, CapabilityClaims{
		Subject: "wg-device-B", Audience: "files",
		Tools: []string{"read_file"}, ExpiresAt: f.now.Add(10 * time.Minute).Unix(),
	}, f.now); err == nil {
		t.Fatal("delegation accepted a key that is not the parent's delegate_pub")
	}
	// A hand-signed child claiming the rogue key as its PubKey fails the
	// delegate binding; one claiming the real delegate_pub fails the signature.
	parent, _ := decodeCapability(root)
	forged := CapabilityClaims{
		Version: 1, ID: "cap_forged", Subject: "wg-device-B", Audience: "files",
		Tools: []string{"read_file"}, IssuedAt: f.now.Unix(),
		ExpiresAt: f.now.Add(10 * time.Minute).Unix(), PubKey: rogue.PubKeyHex(), Parent: root,
	}
	if _, err := f.verifier.Verify(resign(t, forged, rogue), "wg-device-B", "files", "read_file"); err == nil {
		t.Fatal("verifier accepted a sub-grant signed by a non-delegate key")
	}
	forged.PubKey = parent.DelegatePub
	if _, err := f.verifier.Verify(resign(t, forged, rogue), "wg-device-B", "files", "read_file"); err == nil {
		t.Fatal("verifier accepted a forged signature under the claimed delegate key")
	}
}

func TestDelegationDepthCap(t *testing.T) {
	f := newDelegationFixture(t)
	root := f.issueRoot(t, nil)

	// Hop 1: A delegates to B, allowing B to delegate further.
	d2, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	c1, err := DelegateCapability(root, f.delegate, CapabilityClaims{
		Subject: "wg-device-B", Audience: "files",
		Tools: []string{"read_file", "list_files"}, DelegatePub: d2.PubKeyHex(),
		ExpiresAt: f.now.Add(30 * time.Minute).Unix(),
	}, f.now)
	if err != nil {
		t.Fatalf("hop 1: %v", err)
	}
	// Hop 2: B delegates to C — chain length 3, still allowed.
	d3, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := DelegateCapability(c1, d2, CapabilityClaims{
		Subject: "wg-device-C", Audience: "files",
		Tools: []string{"read_file"}, DelegatePub: d3.PubKeyHex(),
		ExpiresAt: f.now.Add(20 * time.Minute).Unix(),
	}, f.now)
	if err != nil {
		t.Fatalf("hop 2: %v", err)
	}
	if _, err := f.verifier.Verify(c2, "wg-device-C", "files", "read_file"); err != nil {
		t.Fatalf("depth-2 sub-grant should verify: %v", err)
	}
	// Hop 3: chain length 4 — refused at issue time…
	if _, err := DelegateCapability(c2, d3, CapabilityClaims{
		Subject: "wg-device-D", Audience: "files",
		Tools: []string{"read_file"}, ExpiresAt: f.now.Add(10 * time.Minute).Unix(),
	}, f.now); err == nil || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("expected a depth error at issue time, got %v", err)
	}
	// …and at verify time for a hand-signed hop.
	leaf2, _ := decodeCapability(c2)
	deep := CapabilityClaims{
		Version: 1, ID: "cap_deep", Subject: "wg-device-D", Audience: "files",
		Tools: []string{"read_file"}, IssuedAt: f.now.Unix(),
		ExpiresAt: f.now.Add(10 * time.Minute).Unix(), PubKey: leaf2.DelegatePub, Parent: c2,
	}
	if _, err := f.verifier.Verify(resign(t, deep, d3), "wg-device-D", "files", "read_file"); err == nil {
		t.Fatal("verifier accepted a chain beyond the depth cap")
	}
}

func TestDelegationRevocationCascades(t *testing.T) {
	f := newDelegationFixture(t)
	root := f.issueRoot(t, func(c *CapabilityClaims) { c.ID = "cap_root" })
	child, err := DelegateCapability(root, f.delegate, CapabilityClaims{
		Subject: "wg-device-B", Audience: "files",
		Tools: []string{"read_file"}, ExpiresAt: f.now.Add(30 * time.Minute).Unix(),
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	// Revoking the ROOT id kills the child.
	f.verifier.WithRevocation(func(id string) bool { return id == "cap_root" })
	if _, err := f.verifier.Verify(child, "wg-device-B", "files", "read_file"); err == nil {
		t.Fatal("revoking the root did not cascade to the sub-grant")
	}
	// Subject-revoking the ROOT's device (the lost-laptop kill switch) also
	// kills everything it delegated.
	f.verifier.WithRevocation(nil)
	f.verifier.WithSubjectRevocation(func(sub string) bool { return sub == "wg-device-A" })
	if _, err := f.verifier.Verify(child, "wg-device-B", "files", "read_file"); err == nil {
		t.Fatal("subject-revoking the delegating device did not cascade")
	}
	// Clearing revocation restores the grant (sanity: the denials above were
	// the revocation, not something else).
	f.verifier.WithSubjectRevocation(nil)
	if _, err := f.verifier.Verify(child, "wg-device-B", "files", "read_file"); err != nil {
		t.Fatalf("sub-grant should verify once revocation is cleared: %v", err)
	}
}

func TestDelegationSingleUseAndCorporaRules(t *testing.T) {
	f := newDelegationFixture(t)

	// The authority refuses a single-use + delegable grant outright.
	if _, err := f.authority.IssueCapability(CapabilityClaims{
		Subject: "wg-device-A", Audience: "files", Tools: []string{"read_*"},
		SingleUse: true, DelegatePub: f.delegate.PubKeyHex(),
		ExpiresAt: f.now.Add(time.Hour).Unix(),
	}, f.now); err == nil {
		t.Fatal("authority issued a single-use capability that can delegate")
	}

	// Corpora: a corpus-restricted parent requires a non-empty, narrower child
	// list — an empty child list would widen the grant.
	root := f.issueRoot(t, func(c *CapabilityClaims) { c.Corpora = []string{"eng-*"} })
	if _, err := DelegateCapability(root, f.delegate, CapabilityClaims{
		Subject: "wg-device-B", Audience: "files",
		Tools: []string{"read_file"}, ExpiresAt: f.now.Add(10 * time.Minute).Unix(),
	}, f.now); err == nil {
		t.Fatal("delegation dropped the parent's corpus restriction (empty child corpora)")
	}
	child, err := DelegateCapability(root, f.delegate, CapabilityClaims{
		Subject: "wg-device-B", Audience: "files",
		Tools: []string{"read_file"}, Corpora: []string{"eng-docs"},
		ExpiresAt: f.now.Add(10 * time.Minute).Unix(),
	}, f.now)
	if err != nil {
		t.Fatalf("narrower corpora refused: %v", err)
	}
	got, err := f.verifier.Verify(child, "wg-device-B", "files", "read_file")
	if err != nil {
		t.Fatal(err)
	}
	if got.AllowsCorpus("eng-secrets") || !got.AllowsCorpus("eng-docs") {
		t.Fatalf("leaf corpus scope wrong: %v", got.Corpora)
	}

	// A single-use LEAF works and is consumed exactly once.
	f2 := newDelegationFixture(t)
	root2 := f2.issueRoot(t, nil)
	one, err := DelegateCapability(root2, f2.delegate, CapabilityClaims{
		Subject: "wg-device-B", Audience: "files",
		Tools: []string{"read_file"}, SingleUse: true,
		ExpiresAt: f2.now.Add(10 * time.Minute).Unix(),
	}, f2.now)
	if err != nil {
		t.Fatal(err)
	}
	// Without a replay cache the single-use leaf fails closed.
	if _, err := f2.verifier.Verify(one, "wg-device-B", "files", "read_file"); err == nil {
		t.Fatal("single-use sub-grant verified without a replay cache")
	}
	f2.verifier.WithReplayCache(NewMemNonceStore())
	if _, err := f2.verifier.Verify(one, "wg-device-B", "files", "read_file"); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := f2.verifier.Verify(one, "wg-device-B", "files", "read_file"); err == nil {
		t.Fatal("single-use sub-grant replayed")
	}
}

func TestDelegationIDIsServerGeneratedAndCannotBurnOtherTokens(t *testing.T) {
	f := newDelegationFixture(t)
	root := f.issueRoot(t, nil)

	// A caller-supplied sub-grant ID is refused outright: IDs key revocation,
	// and a holder-picked ID could alias another token's.
	if _, err := DelegateCapability(root, f.delegate, CapabilityClaims{
		ID: "cap_victim", Subject: "wg-device-B", Audience: "files",
		Tools: []string{"read_file"}, ExpiresAt: f.now.Add(10 * time.Minute).Unix(),
	}, f.now); err == nil || !strings.Contains(err.Error(), "generated") {
		t.Fatalf("expected caller-supplied sub-grant id to be refused, got %v", err)
	}

	// Targeted-burn attempt: the authority issues a single-use token cap_victim
	// for device V; a malicious delegate HAND-SIGNS a single-use sub-grant that
	// claims the same ID and uses it first. The victim's token must still work:
	// delegated replay keys are signature-derived, not ID-derived.
	victim, err := f.authority.IssueCapability(CapabilityClaims{
		ID: "cap_victim", Subject: "wg-device-V", Audience: "files",
		Tools: []string{"read_file"}, SingleUse: true,
		ExpiresAt: f.now.Add(time.Hour).Unix(),
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	parent, _ := decodeCapability(root)
	imposter := CapabilityClaims{
		Version: 1, ID: "cap_victim", Subject: "wg-device-B", Audience: "files",
		Tools: []string{"read_file"}, SingleUse: true, IssuedAt: f.now.Unix(),
		ExpiresAt: f.now.Add(10 * time.Minute).Unix(),
		PubKey:    parent.DelegatePub, Parent: root,
	}
	tok := resign(t, imposter, f.delegate)
	f.verifier.WithReplayCache(NewMemNonceStore())
	if _, err := f.verifier.Verify(tok, "wg-device-B", "files", "read_file"); err != nil {
		t.Fatalf("imposter leaf should verify on first use (it is in scope): %v", err)
	}
	// The imposter's consumption must NOT have burned the victim's jti.
	if _, err := f.verifier.Verify(victim, "wg-device-V", "files", "read_file"); err != nil {
		t.Fatalf("victim's single-use token was burned by an ID-colliding sub-grant: %v", err)
	}
	// And each token is still single-use on its own.
	if _, err := f.verifier.Verify(tok, "wg-device-B", "files", "read_file"); err == nil {
		t.Fatal("imposter leaf replayed")
	}
	if _, err := f.verifier.Verify(victim, "wg-device-V", "files", "read_file"); err == nil {
		t.Fatal("victim token replayed")
	}
}

func TestPlainCapabilityStillVerifiesAndUnpinnedRootDenied(t *testing.T) {
	f := newDelegationFixture(t)
	// Regression: a plain (non-delegated) token keeps working through the same
	// dispatch path.
	plain, err := f.authority.IssueCapability(CapabilityClaims{
		Subject: "wg-device-A", Audience: "files", Tools: []string{"read_*"},
		ExpiresAt: f.now.Add(time.Hour).Unix(),
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.verifier.Verify(plain, "wg-device-A", "files", "read_file"); err != nil {
		t.Fatalf("plain capability broke: %v", err)
	}
	// A chain whose root is signed by an UNPINNED authority is denied even if
	// every hop is internally consistent.
	rogueAuthority, _ := GenerateSigner()
	rogueRootClaims := CapabilityClaims{
		Version: 1, ID: "cap_rogue_root", Subject: "wg-device-A", Audience: "files",
		Tools: []string{"read_*"}, DelegatePub: f.delegate.PubKeyHex(),
		IssuedAt: f.now.Unix(), ExpiresAt: f.now.Add(time.Hour).Unix(),
		PubKey: rogueAuthority.PubKeyHex(),
	}
	rogueRoot := resign(t, rogueRootClaims, rogueAuthority)
	child, err := DelegateCapability(rogueRoot, f.delegate, CapabilityClaims{
		Subject: "wg-device-B", Audience: "files",
		Tools: []string{"read_file"}, ExpiresAt: f.now.Add(10 * time.Minute).Unix(),
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.verifier.Verify(child, "wg-device-B", "files", "read_file"); err == nil {
		t.Fatal("verifier accepted a chain rooted in an unpinned authority")
	}
}
