package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "meshmcp.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfigCapabilitiesValidation(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string // substring; "" means it must load
	}{
		{
			name: "required with keys, no policy: ok (capability-only surface)",
			body: `
backends:
  - name: fs
    port: 9001
    stdio: ["echo"]
    capabilities:
      required: true
      trusted_public_keys: ["04f9f6e4dfefca3cb23d93db44427e44e5b90a81661690b15f0ac47847c7796c"]
`,
		},
		{
			name: "not required needs a policy",
			body: `
backends:
  - name: fs
    port: 9001
    stdio: ["echo"]
    capabilities:
      required: false
      trusted_public_keys: ["04f9f6e4dfefca3cb23d93db44427e44e5b90a81661690b15f0ac47847c7796c"]
`,
			wantErr: "need a deny-by-default policy",
		},
		{
			name: "malformed hex key is rejected at load",
			body: `
backends:
  - name: fs
    port: 9001
    stdio: ["echo"]
    capabilities:
      required: true
      trusted_public_keys: ["deadbeef"]
`,
			wantErr: "hex Ed25519 key",
		},
		{
			name: "required:false with a default-allow policy is rejected",
			body: `
backends:
  - name: fs
    port: 9001
    stdio: ["echo"]
    capabilities:
      required: false
      trusted_public_keys: ["04f9f6e4dfefca3cb23d93db44427e44e5b90a81661690b15f0ac47847c7796c"]
    policy:
      default_allow: true
`,
			wantErr: "deny-by-default policy",
		},
		{
			name: "required:false with a deny-by-default policy: ok",
			body: `
backends:
  - name: fs
    port: 9001
    stdio: ["echo"]
    capabilities:
      required: false
      trusted_public_keys: ["04f9f6e4dfefca3cb23d93db44427e44e5b90a81661690b15f0ac47847c7796c"]
    policy:
      default_allow: false
      rules:
        - { peers: ["*"], tools: ["read_*"], allow: true }
`,
		},
		{
			name: "no trusted keys is rejected",
			body: `
backends:
  - name: fs
    port: 9001
    stdio: ["echo"]
    capabilities:
      required: true
      trusted_public_keys: []
`,
			wantErr: "at least one trusted_public_keys",
		},
		{
			name: "capabilities need stdio, not http",
			body: `
backends:
  - name: web
    port: 9001
    http: "http://127.0.0.1:8080"
    capabilities:
      required: true
      trusted_public_keys: ["04f9f6e4dfefca3cb23d93db44427e44e5b90a81661690b15f0ac47847c7796c"]
`,
			wantErr: "only valid for stdio",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadConfig(writeConfig(t, c.body))
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("expected load to succeed, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("expected error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}
