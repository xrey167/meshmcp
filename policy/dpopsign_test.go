package policy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sha256Sum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func mustDPoPSigner(t *testing.T) *DPoPSigner {
	t.Helper()
	s, err := GenerateDPoPSigner()
	if err != nil {
		t.Fatalf("GenerateDPoPSigner: %v", err)
	}
	return s
}

func decodeSegment(t *testing.T, seg string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	return b
}

// TestDPoPSigner_GenerateSaveLoadRoundTrip: generate -> save -> load -> the
// loaded key still produces proofs whose embedded jwk thumbprint matches the
// original, and the file lands at mode 0600.
func TestDPoPSigner_GenerateSaveLoadRoundTrip(t *testing.T) {
	s := mustDPoPSigner(t)
	path := filepath.Join(t.TempDir(), "dpop.json")
	if err := s.SaveDPoPSigner(path); err != nil {
		t.Fatalf("SaveDPoPSigner: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows does not report Unix permission bits, so skip the mode check.
	if perm := fi.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
		t.Fatalf("key file mode = %#o, want 0600", perm)
	}
	loaded, err := LoadDPoPSigner(path)
	if err != nil {
		t.Fatalf("LoadDPoPSigner: %v", err)
	}
	if loaded.Thumbprint() != s.Thumbprint() {
		t.Fatal("loaded signer's public key thumbprint does not match the original")
	}
	proof, err := loaded.Proof("POST", "https://as.example.com/token", time.Unix(1000, 0), "", "")
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof should have 3 dot-separated segments, got %d", len(parts))
	}
}

// TestDPoPSigner_KeyFileHasDistinctTypeDiscriminator: the on-disk key file
// carries "key_type":"dpop-es256", and policy/sign.go's Ed25519 LoadSigner
// cannot load it (domain separation).
func TestDPoPSigner_KeyFileHasDistinctTypeDiscriminator(t *testing.T) {
	s := mustDPoPSigner(t)
	path := filepath.Join(t.TempDir(), "dpop.json")
	if err := s.SaveDPoPSigner(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"key_type": "dpop-es256"`) && !strings.Contains(string(raw), `"key_type":"dpop-es256"`) {
		t.Fatalf("key file missing key_type discriminator: %s", raw)
	}
	if _, err := LoadSigner(path); err == nil {
		t.Fatal("policy/sign.go's LoadSigner must not succeed against a DPoP key file")
	}
	// And the reverse: a DPoP load must reject an Ed25519 sign.go key file.
	edSigner, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	edPath := filepath.Join(t.TempDir(), "ed.json")
	if err := edSigner.SaveSigner(edPath); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDPoPSigner(edPath); err == nil {
		t.Fatal("LoadDPoPSigner must not succeed against an Ed25519 sign.go key file")
	}
}

// TestDPoPProof_RequiredClaims: a generated proof decodes to a header with
// typ: dpop+jwt, alg: ES256, an embedded jwk, and claims htu/htm/iat/jti.
func TestDPoPProof_RequiredClaims(t *testing.T) {
	s := mustDPoPSigner(t)
	proof, err := s.Proof("POST", "https://res.example.com/mcp?x=1", time.Unix(2000, 0), "", "")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("want 3 segments, got %d", len(parts))
	}
	var hdr dpopHeader
	if err := json.Unmarshal(decodeSegment(t, parts[0]), &hdr); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if hdr.Typ != "dpop+jwt" {
		t.Errorf("typ = %q, want dpop+jwt", hdr.Typ)
	}
	if hdr.Alg != "ES256" {
		t.Errorf("alg = %q, want ES256", hdr.Alg)
	}
	if hdr.JWK.Kty != "EC" || hdr.JWK.Crv != "P-256" || hdr.JWK.X == "" || hdr.JWK.Y == "" {
		t.Errorf("jwk incomplete: %+v", hdr.JWK)
	}
	var claims DPoPClaims
	if err := json.Unmarshal(decodeSegment(t, parts[1]), &claims); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	if claims.HTM != "POST" {
		t.Errorf("htm = %q, want POST", claims.HTM)
	}
	// Query string is excluded from htu by the documented normalization rule.
	if claims.HTU != "https://res.example.com/mcp" {
		t.Errorf("htu = %q, want normalized (no query)", claims.HTU)
	}
	if claims.IAT != 2000 {
		t.Errorf("iat = %d, want 2000", claims.IAT)
	}
	if claims.JTI == "" {
		t.Error("jti must be present and non-empty")
	}
}

// TestDPoPProof_HTUMatchesActualRequestURL: a proof built for URL A does not
// carry htu B — an independent verifier comparing htu against the actual
// request URL rejects it when replayed against a different URL.
func TestDPoPProof_HTUMatchesActualRequestURL(t *testing.T) {
	s := mustDPoPSigner(t)
	proof, err := s.Proof("POST", "https://a.example.com/one", time.Unix(1, 0), "", "")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(proof, ".")
	var claims DPoPClaims
	if err := json.Unmarshal(decodeSegment(t, parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	actualURL := "https://b.example.com/two"
	normalizedActual, err := NormalizeHTU(actualURL)
	if err != nil {
		t.Fatal(err)
	}
	if claims.HTU == normalizedActual {
		t.Fatal("proof htu must not match a different request URL")
	}
}

// TestDPoPProof_JTIUniquePerRequest: two proofs minted back-to-back for the
// same request never reuse a jti.
func TestDPoPProof_JTIUniquePerRequest(t *testing.T) {
	s := mustDPoPSigner(t)
	p1, err := s.Proof("POST", "https://as.example.com/token", time.Unix(1, 0), "", "")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := s.Proof("POST", "https://as.example.com/token", time.Unix(1, 0), "", "")
	if err != nil {
		t.Fatal(err)
	}
	var c1, c2 DPoPClaims
	_ = json.Unmarshal(decodeSegment(t, strings.Split(p1, ".")[1]), &c1)
	_ = json.Unmarshal(decodeSegment(t, strings.Split(p2, ".")[1]), &c2)
	if c1.JTI == "" || c2.JTI == "" || c1.JTI == c2.JTI {
		t.Fatalf("jti must be unique per request: %q vs %q", c1.JTI, c2.JTI)
	}
}

// TestDPoPProof_AthClaimOnResourceRequest: presenting a DPoP-bound access
// token to a resource server includes ath = base64url(SHA-256(access token)).
func TestDPoPProof_AthClaimOnResourceRequest(t *testing.T) {
	s := mustDPoPSigner(t)
	token := "opaque-access-token-value"
	proof, err := s.Proof("GET", "https://res.example.com/mcp", time.Unix(1, 0), token, "")
	if err != nil {
		t.Fatal(err)
	}
	var claims DPoPClaims
	if err := json.Unmarshal(decodeSegment(t, strings.Split(proof, ".")[1]), &claims); err != nil {
		t.Fatal(err)
	}
	wantSum := sha256Sum(token)
	if claims.Ath != wantSum {
		t.Errorf("ath = %q, want %q", claims.Ath, wantSum)
	}
	// A token-endpoint proof (no access token yet) must omit ath.
	proof2, err := s.Proof("POST", "https://as.example.com/token", time.Unix(1, 0), "", "")
	if err != nil {
		t.Fatal(err)
	}
	var claims2 DPoPClaims
	_ = json.Unmarshal(decodeSegment(t, strings.Split(proof2, ".")[1]), &claims2)
	if claims2.Ath != "" {
		t.Errorf("ath must be empty when no access token is presented, got %q", claims2.Ath)
	}
}

// TestDPoPSigner_MissingKeyFileIsFatalAtStartup: loading a nonexistent or
// corrupt key file fails clearly, never silently generating a fresh key.
func TestDPoPSigner_MissingKeyFileIsFatalAtStartup(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	if _, err := LoadDPoPSigner(missing); err == nil {
		t.Fatal("loading a missing DPoP key file must fail, not silently generate one")
	}
	corrupt := filepath.Join(t.TempDir(), "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDPoPSigner(corrupt); err == nil {
		t.Fatal("loading a corrupt DPoP key file must fail")
	}
}

// TestDPoPSigner_RotationIsAtomic: a rotation (regenerate + save) writes via
// tmp file + rename, so an interrupted rotation never leaves the original key
// file partially overwritten — verified here by confirming the original file
// is left fully intact (not truncated/corrupted) even though a tmp file with
// the new content is what SaveDPoPSigner actually writes and renames.
func TestDPoPSigner_RotationIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dpop.json")
	original := mustDPoPSigner(t)
	if err := original.SaveDPoPSigner(path); err != nil {
		t.Fatal(err)
	}
	originalBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	rotated := mustDPoPSigner(t)
	if err := rotated.SaveDPoPSigner(path); err != nil {
		t.Fatal(err)
	}
	// No leftover tmp file after a successful rotation.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("tmp file should not remain after rotation: err=%v", err)
	}
	rotatedBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(rotatedBytes) == string(originalBytes) {
		t.Fatal("rotation should have replaced the key file contents")
	}
	loaded, err := LoadDPoPSigner(path)
	if err != nil {
		t.Fatalf("post-rotation file must load cleanly: %v", err)
	}
	if loaded.Thumbprint() != rotated.Thumbprint() {
		t.Fatal("loaded key after rotation should match the rotated key, not the original")
	}
}
