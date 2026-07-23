package policy

import (
	"testing"
	"time"
)

// TestSubjectRevocationKillsOutstandingTokens proves the lost-device
// kill-switch: a valid, unexpired capability minted for an identity fails
// verification once that identity's SUBJECT is revoked — no token id needed.
func TestSubjectRevocationKillsOutstandingTokens(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := signer.IssueCapability(CapabilityClaims{
		Subject: "stolen-laptop-key", Audience: "kb", Tools: []string{"read_*"},
		ExpiresAt: now.Add(time.Hour).Unix(),
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	rev, err := NewFileRevocation(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewCapabilityVerifier([]string{signer.PubKeyHex()}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	v = v.WithRevocation(rev.IsRevoked).WithSubjectRevocation(rev.IsSubjectRevoked)

	// Before revocation the token verifies.
	if _, err := v.Verify(tok, "stolen-laptop-key", "kb", "read_doc"); err != nil {
		t.Fatalf("token should verify before revocation: %v", err)
	}

	// Revoke the SUBJECT — every outstanding token for the identity dies.
	if err := rev.RevokeSubject("stolen-laptop-key"); err != nil {
		t.Fatalf("revoke subject: %v", err)
	}
	if _, err := v.Verify(tok, "stolen-laptop-key", "kb", "read_doc"); err == nil {
		t.Fatal("token verified after its subject was revoked")
	}

	// Another identity's tokens are unaffected.
	tok2, err := signer.IssueCapability(CapabilityClaims{
		Subject: "other-key", Audience: "kb", Tools: []string{"read_*"},
		ExpiresAt: now.Add(time.Hour).Unix(),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tok2, "other-key", "kb", "read_doc"); err != nil {
		t.Fatalf("unrelated identity's token must keep verifying: %v", err)
	}
}

// TestIsSubjectRevokedFailsClosed pins the fail-closed contract: empty subject
// and an unreachable store both count as revoked; idempotent re-revocation; a
// base64 WireGuard key with path characters is stored safely.
func TestIsSubjectRevokedFailsClosed(t *testing.T) {
	rev, err := NewFileRevocation(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !rev.IsSubjectRevoked("") {
		t.Error("empty subject must fail closed")
	}
	if rev.IsSubjectRevoked("some-key") {
		t.Error("reachable store with no marker must report not-revoked")
	}
	if err := rev.RevokeSubject("some-key"); err != nil {
		t.Fatal(err)
	}
	if err := rev.RevokeSubject("some-key"); err != nil {
		t.Fatalf("re-revocation must be idempotent: %v", err)
	}
	if !rev.IsSubjectRevoked("some-key") {
		t.Error("marker present must report revoked")
	}
	// A WireGuard-shaped base64 key (with '/' and '+') must be path-safe.
	weird := "abc/DEF+ghi=jkl/MNO+pqr=stu/VWX+yz0="
	if err := rev.RevokeSubject(weird); err != nil {
		t.Fatalf("base64 key with path characters: %v", err)
	}
	if !rev.IsSubjectRevoked(weird) {
		t.Error("base64 key marker not found after revocation")
	}
	// Lost store fails closed.
	lost := FileRevocation{Dir: "/nonexistent/path/for/sure"}
	if !lost.IsSubjectRevoked("some-key") {
		t.Error("unreachable store must fail closed")
	}
}
