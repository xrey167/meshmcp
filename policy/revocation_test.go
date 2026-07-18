package policy

import (
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
