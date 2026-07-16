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
      trusted_public_keys: ["deadbeef"]
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
      trusted_public_keys: ["deadbeef"]
`,
			wantErr: "need a deny-by-default policy",
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
      trusted_public_keys: ["deadbeef"]
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
