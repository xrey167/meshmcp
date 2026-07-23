package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fwd makes a path YAML/Windows-safe (forward slashes are accepted by os on
// both platforms and avoid YAML backslash-escape surprises).
func fwd(p string) string { return strings.ReplaceAll(p, "\\", "/") }

func writeECJWKS(t *testing.T, kid string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	doc, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{
		"kty": "EC", "kid": kid, "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(ssoPad32(key.X.Bytes())),
		"y": base64.RawURLEncoding.EncodeToString(ssoPad32(key.Y.Bytes())),
	}}})
	p := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(p, doc, 0o600); err != nil {
		t.Fatalf("write jwks: %v", err)
	}
	return p
}

func writeECPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	p := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
	return p
}

func TestOIDCConfig_ValidJWKSLoads(t *testing.T) {
	jwks := writeECJWKS(t, "k1")
	cfg, err := loadConfig(writeConfig(t, `
control:
  port: 9600
  allow: ["pubkey:opkey"]
oidc:
  audience: "https://meshmcp.test"
  issuers:
    - issuer: "https://idp.test.example"
      alg: "ES256"
      jwks_file: "`+fwd(jwks)+`"
backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
`))
	if err != nil {
		t.Fatalf("valid oidc config should load: %v", err)
	}
	if cfg.OIDC == nil || cfg.OIDC.resolved == nil {
		t.Fatal("oidc issuers should be resolved at load")
	}
	iss := cfg.OIDC.resolved["https://idp.test.example"]
	if iss == nil || iss.Alg != "ES256" || len(iss.Keys) != 1 {
		t.Fatalf("resolved issuer = %+v, want ES256 with 1 key", iss)
	}
	if cfg.OIDC.bindTTL != time.Hour {
		t.Fatalf("default bindTTL = %s, want 1h", cfg.OIDC.bindTTL)
	}
}

func TestOIDCConfig_PEMKeyLoads(t *testing.T) {
	pemPath := writeECPEM(t)
	cfg, err := loadConfig(writeConfig(t, `
control:
  port: 9600
  allow: ["pubkey:opkey"]
oidc:
  audience: "https://meshmcp.test"
  bind_ttl_max: 600
  issuers:
    - issuer: "https://idp.pem.example"
      alg: "ES256"
      key_file: "`+fwd(pemPath)+`"
backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
`))
	if err != nil {
		t.Fatalf("valid PEM oidc config should load: %v", err)
	}
	if cfg.OIDC.bindTTL != 600*time.Second {
		t.Fatalf("bindTTL = %s, want 600s", cfg.OIDC.bindTTL)
	}
	if iss := cfg.OIDC.resolved["https://idp.pem.example"]; iss == nil || len(iss.Keys) != 1 {
		t.Fatalf("PEM issuer not resolved: %+v", iss)
	}
}

func TestOIDCConfig_NoOIDCStaysNil(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, `
backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
`))
	if err != nil {
		t.Fatalf("config without oidc must load: %v", err)
	}
	if cfg.OIDC != nil {
		t.Fatal("no oidc stanza must leave cfg.OIDC nil (byte-identical to today)")
	}
}

func TestOIDCConfig_Rejections(t *testing.T) {
	jwks := writeECJWKS(t, "k1")
	pemPath := writeECPEM(t)
	cases := []struct {
		name string
		oidc string
		want string
	}{
		{
			name: "jwks_uri is a v2 feature",
			oidc: `
oidc:
  audience: "https://meshmcp.test"
  issuers:
    - issuer: "https://idp.test.example"
      alg: "ES256"
      jwks_uri: "https://idp.test.example/jwks"`,
			want: "jwks_uri",
		},
		{
			name: "unknown alg",
			oidc: `
oidc:
  audience: "https://meshmcp.test"
  issuers:
    - issuer: "https://idp.test.example"
      alg: "HS256"
      jwks_file: "` + fwd(jwks) + `"`,
			want: "alg",
		},
		{
			name: "missing audience",
			oidc: `
oidc:
  issuers:
    - issuer: "https://idp.test.example"
      alg: "ES256"
      jwks_file: "` + fwd(jwks) + `"`,
			want: "audience",
		},
		{
			name: "both jwks_file and key_file",
			oidc: `
oidc:
  audience: "https://meshmcp.test"
  issuers:
    - issuer: "https://idp.test.example"
      alg: "ES256"
      jwks_file: "` + fwd(jwks) + `"
      key_file: "` + fwd(pemPath) + `"`,
			want: "exactly one",
		},
		{
			name: "alg/key type mismatch (RS256 over an EC JWKS)",
			oidc: `
oidc:
  audience: "https://meshmcp.test"
  issuers:
    - issuer: "https://idp.test.example"
      alg: "RS256"
      jwks_file: "` + fwd(jwks) + `"`,
			want: "RSA public key",
		},
		{
			name: "no issuers",
			oidc: `
oidc:
  audience: "https://meshmcp.test"
  issuers: []`,
			want: "issuer",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig(writeConfig(t, `
control:
  port: 9600
  allow: ["pubkey:opkey"]`+tc.oidc+`
backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
`))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestOIDCConfig_RequiresControlPort(t *testing.T) {
	jwks := writeECJWKS(t, "k1")
	// oidc set but NO control endpoint — the /v1/sso/attest surface has nowhere
	// to mount, so load must fail closed.
	_, err := loadConfig(writeConfig(t, `
oidc:
  audience: "https://meshmcp.test"
  issuers:
    - issuer: "https://idp.test.example"
      alg: "ES256"
      jwks_file: "`+fwd(jwks)+`"
backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
`))
	if err == nil || !strings.Contains(err.Error(), "control.port") {
		t.Fatalf("oidc without control.port must be rejected, got %v", err)
	}
}
