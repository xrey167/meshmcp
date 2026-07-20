package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestFileRevocationFailsClosedInVerifier proves a revoked capability id is
// rejected by the verifier even while the token is otherwise valid (F21).
func TestFileRevocationFailsClosedInVerifier(t *testing.T) {
	dir := t.TempDir()
	rev := FileRevocation{Dir: dir}

	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, err := signer.IssueCapability(CapabilityClaims{
		Subject:   "peer-key",
		Audience:  "b",
		Tools:     []string{"read_*"},
		ExpiresAt: now.Add(time.Hour).Unix(),
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewCapabilityVerifier([]string{signer.PubKeyHex()}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	v = v.WithRevocation(rev.IsRevoked)

	// Valid before revocation.
	claims, err := v.Verify(token, "peer-key", "b", "read_invoice")
	if err != nil {
		t.Fatalf("token should verify before revocation: %v", err)
	}

	// Revoke it, then the same token must fail closed.
	if err := rev.Revoke(claims.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(token, "peer-key", "b", "read_invoice"); err == nil {
		t.Fatal("revoked capability still verified")
	}

	ids, _ := rev.List()
	if len(ids) != 1 || ids[0] != claims.ID {
		t.Fatalf("List() = %v, want [%s]", ids, claims.ID)
	}
}

// TestRevocationFailsClosedWhenStoreUnavailable is the Phase-9.2 regression:
// when the revocation store cannot be reached, a capability must NOT be allowed
// to widen a default deny — IsRevoked fails closed (treats the id as revoked).
func TestRevocationFailsClosedWhenStoreUnavailable(t *testing.T) {
	// 1) A store directory that does not exist (lost/unavailable) → fail closed.
	missing := FileRevocation{Dir: filepath.Join(t.TempDir(), "does-not-exist")}
	if !missing.IsRevoked("cap_abc123") {
		t.Fatal("a missing revocation store must fail closed (treat as revoked)")
	}

	// 2) A store path that is a FILE, not a directory (corrupt) → fail closed.
	f := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt := FileRevocation{Dir: f}
	if !corrupt.IsRevoked("cap_abc123") {
		t.Fatal("a corrupt (non-directory) revocation store must fail closed")
	}

	// 3) A reachable, empty store → NOT revoked (the normal case still works).
	ok, err := NewFileRevocation(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if ok.IsRevoked("cap_abc123") {
		t.Fatal("a reachable empty store must report not-revoked")
	}
	// A malformed id always fails closed.
	if !ok.IsRevoked("../escape") {
		t.Fatal("a malformed id must fail closed")
	}
}

// TestRevocationVerifierFailsClosedOnUnavailableStore proves the end-to-end
// effect: a capability that would widen a default deny is rejected when its
// revocation store is unavailable.
func TestRevocationVerifierFailsClosedOnUnavailableStore(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, err := signer.IssueCapability(CapabilityClaims{
		Subject: "peer-key", Audience: "b", Tools: []string{"read_*"},
		ExpiresAt: now.Add(time.Hour).Unix(),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewCapabilityVerifier([]string{signer.PubKeyHex()}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	// Point revocation at an unavailable store.
	rev := FileRevocation{Dir: filepath.Join(t.TempDir(), "gone")}
	v = v.WithRevocation(rev.IsRevoked)

	if _, err := v.Verify(token, "peer-key", "b", "read_invoice"); err == nil {
		t.Fatal("capability must be rejected when the revocation store is unavailable")
	}
}
