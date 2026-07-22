package policy

import (
	"testing"
	"time"
)

func fixedClock() func() time.Time {
	base := time.Unix(1_800_000_000, 0)
	return func() time.Time { return base }
}

func mkManifest(t *testing.T, s *Signer, name, kind, content string) string {
	t.Helper()
	tok, err := s.IssueManifest(ManifestClaims{
		Name: name, Kind: kind, BundleVersion: "1.2.0",
		ContentHash: content, Summary: "a bundle", Cost: 3,
	}, fixedClock()())
	if err != nil {
		t.Fatalf("IssueManifest: %v", err)
	}
	return tok
}

func TestManifestIssueAndVerify(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte("policy-pack: default-deny, rate limits, taint")
	hash := HashBundle(bundle)

	v, err := NewManifestVerifier([]string{s.PubKeyHex()}, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	tok := mkManifest(t, s, "least-privilege", ManifestPolicyPack, hash)

	c, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("happy-path verify failed: %v", err)
	}
	if c.Name != "least-privilege" || c.Kind != ManifestPolicyPack || c.Cost != 3 {
		t.Fatalf("claims not round-tripped: %+v", c)
	}
	// Content binding: the real bundle passes, a tampered one is refused.
	if err := c.VerifyContent(hash); err != nil {
		t.Fatalf("content of the real bundle should verify: %v", err)
	}
	if err := c.VerifyContent(HashBundle([]byte("tampered"))); err == nil {
		t.Fatalf("tampered bundle must fail content verification")
	}
}

func TestManifestRejectsUntrustedAuthority(t *testing.T) {
	issuer, _ := GenerateSigner()
	attacker, _ := GenerateSigner()
	// Verifier pins only the legitimate issuer.
	v, _ := NewManifestVerifier([]string{issuer.PubKeyHex()}, fixedClock())

	// A manifest signed by an unpinned key must be refused even though its own
	// signature is internally valid.
	tok, err := attacker.IssueManifest(ManifestClaims{
		Name: "evil", Kind: ManifestToolBackend, ContentHash: HashBundle([]byte("x")),
	}, fixedClock()())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tok); err == nil {
		t.Fatalf("manifest from an untrusted authority must be rejected")
	}
}

func TestManifestRejectsBadKindAndContentAtIssue(t *testing.T) {
	s, _ := GenerateSigner()
	if _, err := s.IssueManifest(ManifestClaims{Name: "x", Kind: "wat", ContentHash: HashBundle(nil)}, fixedClock()()); err == nil {
		t.Fatalf("unknown kind must be refused at issue")
	}
	if _, err := s.IssueManifest(ManifestClaims{Name: "x", Kind: ManifestPolicyPack, ContentHash: "short"}, fixedClock()()); err == nil {
		t.Fatalf("non-sha256 content_hash must be refused at issue")
	}
	if _, err := s.IssueManifest(ManifestClaims{Kind: ManifestPolicyPack, ContentHash: HashBundle(nil)}, fixedClock()()); err == nil {
		t.Fatalf("missing name must be refused at issue")
	}
}

func TestManifestContentKindsIssueAndVerify(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewManifestVerifier([]string{s.PubKeyHex()}, fixedClock())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{ManifestPrompt, ManifestAgent, ManifestSkill, ManifestEvalSuite} {
		tok := mkManifest(t, s, "bundle-"+kind, kind, HashBundle([]byte(kind)))
		c, err := v.Verify(tok)
		if err != nil {
			t.Fatalf("verify of kind %q failed: %v", kind, err)
		}
		if c.Kind != kind || c.Name != "bundle-"+kind {
			t.Fatalf("claims not round-tripped for kind %q: %+v", kind, c)
		}
	}
	// An unknown kind is still refused at issue.
	if _, err := s.IssueManifest(ManifestClaims{Name: "x", Kind: "workflow", ContentHash: HashBundle(nil)}, fixedClock()()); err == nil {
		t.Fatalf("unknown kind must still be refused at issue")
	}
}

func TestManifestExpiryAndRevocation(t *testing.T) {
	s, _ := GenerateSigner()
	now := fixedClock()
	base := now()

	// Expired manifest (exp in the past relative to the verifier clock).
	expTok, err := s.IssueManifest(ManifestClaims{
		Name: "old", Kind: ManifestAuditSink, ContentHash: HashBundle([]byte("a")),
		ExpiresAt: base.Add(-time.Hour).Unix(),
	}, base.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	v, _ := NewManifestVerifier([]string{s.PubKeyHex()}, now)
	if _, err := v.Verify(expTok); err == nil {
		t.Fatalf("expired manifest must be rejected")
	}

	// Revocation predicate pulls a live manifest by id.
	tok := mkManifest(t, s, "hook-pack", ManifestDecisionHook, HashBundle([]byte("h")))
	c, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("pre-revocation verify: %v", err)
	}
	vr, _ := NewManifestVerifier([]string{s.PubKeyHex()}, now)
	vr = vr.WithRevocation(func(id string) bool { return id == c.ID })
	if _, err := vr.Verify(tok); err == nil {
		t.Fatalf("revoked manifest must be rejected")
	}
}
