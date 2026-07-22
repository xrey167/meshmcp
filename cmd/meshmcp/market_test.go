package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

func TestManifestStorePublishAndList(t *testing.T) {
	dir := t.TempDir()
	s, _ := policy.GenerateSigner()
	tok, err := s.IssueManifest(policy.ManifestClaims{
		Name: "dlp-pack", Kind: policy.ManifestDecisionHook,
		BundleVersion: "2.1.0", ContentHash: policy.HashBundle([]byte("hook code")), Cost: 5,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	store, err := newManifestStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Publish("dlp-pack", tok); err != nil {
		t.Fatal(err)
	}
	toks, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 {
		t.Fatalf("want 1 published manifest, got %d", len(toks))
	}
	c, err := decodeManifestUnverified(toks[0])
	if err != nil {
		t.Fatalf("decode listed manifest: %v", err)
	}
	if c.Name != "dlp-pack" || c.Kind != policy.ManifestDecisionHook || c.Cost != 5 {
		t.Fatalf("listed manifest wrong: %+v", c)
	}
}

func TestMarketInstallIsAuditedMeteredAndChained(t *testing.T) {
	s, _ := policy.GenerateSigner()
	bundle := []byte("tool backend v3")
	c, err := verifyIssued(t, s, policy.ManifestClaims{
		Name: "vault-tool", Kind: policy.ManifestToolBackend,
		BundleVersion: "3.0.0", ContentHash: policy.HashBundle(bundle), Cost: 7,
	})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	log := policy.NewAuditLog(&buf, func() string { return "T" })
	if err := recordInstall(log, "alice.mesh", "pubkeyAAA", c); err != nil {
		t.Fatalf("recordInstall: %v", err)
	}

	as := buf.String()
	// The grant is a proper audited crossing.
	if !strings.Contains(as, `"method":"market/install"`) {
		t.Fatalf("install not audited as market/install: %s", as)
	}
	if !strings.Contains(as, `"tool":"vault-tool"`) || !strings.Contains(as, `"cost":7`) {
		t.Fatalf("install grant missing tool/cost metering: %s", as)
	}
	if !strings.Contains(as, `"peer":"alice.mesh"`) {
		t.Fatalf("install grant not attributed to the installer: %s", as)
	}
	// The tamper-evident chain over the ledger validates.
	res, err := policy.VerifyChain(strings.NewReader(as))
	if err != nil || !res.OK {
		t.Fatalf("audit chain over install grants did not verify: %+v (err %v)", res, err)
	}
}

// verifyIssued issues a manifest with s and verifies it against s's pinned key,
// returning the verified claims (the sign→verify round-trip the CLI performs).
func verifyIssued(t *testing.T, s *policy.Signer, claims policy.ManifestClaims) (policy.ManifestClaims, error) {
	t.Helper()
	tok, err := s.IssueManifest(claims, time.Now())
	if err != nil {
		return policy.ManifestClaims{}, err
	}
	v, err := policy.NewManifestVerifier([]string{s.PubKeyHex()}, time.Now)
	if err != nil {
		return policy.ManifestClaims{}, err
	}
	return v.Verify(tok)
}
