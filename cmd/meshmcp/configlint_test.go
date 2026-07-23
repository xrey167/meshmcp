package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lintYAML(t *testing.T, yaml string) []string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "meshmcp.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(p)
	if err != nil {
		t.Fatalf("test config must be valid: %v", err)
	}
	return lintConfig(cfg)
}

func TestLintConfig(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string // substrings expected among warnings
		none bool     // expect zero warnings
	}{
		{
			name: "clean config",
			yaml: `
audit_log: audit.jsonl
backends:
  - name: fs
    port: 9101
    stdio: [server]
    policy:
      default_allow: false
      rules:
        - peers: ["pubkey:K1"]
          tools: [read_file]
          allow: true
          rate: {max: 10, per: 1m}
`,
			none: true,
		},
		{
			name: "default allow",
			yaml: `
backends:
  - name: fs
    port: 9101
    stdio: [server]
    policy:
      default_allow: true
`,
			want: []string{"default_allow: true"},
		},
		{
			name: "allow-all rule",
			yaml: `
backends:
  - name: fs
    port: 9101
    stdio: [server]
    policy:
      rules:
        - tools: ["*"]
          allow: true
`,
			want: []string{"allows every peer every tool"},
		},
		{
			name: "wildcard tools for one peer",
			yaml: `
backends:
  - name: fs
    port: 9101
    stdio: [server]
    policy:
      rules:
        - peers: ["pubkey:K1"]
          tools: ["*"]
          allow: true
`,
			want: []string{"bare wildcard tool match"},
		},
		{
			name: "egress tool without rate",
			yaml: `
backends:
  - name: fs
    port: 9101
    stdio: [server]
    policy:
      rules:
        - peers: ["pubkey:K1"]
          tools: [post_message]
          allow: true
`,
			want: []string{"egress-looking tool", "no rate limit"},
		},
		{
			name: "cosign without store and without audit file",
			yaml: `
backends:
  - name: pay
    port: 9101
    stdio: [server]
    policy:
      rules:
        - peers: ["pubkey:K1"]
          tools: [transfer]
          allow: true
          require_cosign: true
`,
			want: []string{"no cosign_store", "audit goes to stderr"},
		},
		{
			name: "cosign with ambient grants",
			yaml: `
audit_log: audit.jsonl
backends:
  - name: pay
    port: 9101
    stdio: [server]
    cosign_store: approvals
    policy:
      rules:
        - peers: ["pubkey:K1"]
          tools: [transfer]
          allow: true
          require_cosign: true
`,
			want: []string{"ambient (peer, tool) grants"},
		},
		{
			name: "shadowed rule",
			yaml: `
audit_log: audit.jsonl
backends:
  - name: fs
    port: 9101
    stdio: [server]
    policy:
      rules:
        - peers: ["*"]
          tools: ["read_*"]
          allow: true
          rate: {max: 5, per: 1m}
        - peers: ["pubkey:K1"]
          tools: [read_file]
          allow: false
`,
			want: []string{"rule #2 is shadowed by broader rule #1"},
		},
		{
			name: "secret grant to glob",
			yaml: `
audit_log: audit.jsonl
backends:
  - name: fs
    port: 9101
    stdio: [server]
    policy:
      rules:
        - peers: ["pubkey:K1"]
          tools: [read_file]
          allow: true
          rate: {max: 5, per: 1m}
    secrets:
      file: secrets.json
      grants:
        - peers: ["agent-*.mesh"]
          secrets: [API_KEY]
`,
			want: []string{"secret grant #1", "is a glob"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warns := lintYAML(t, tc.yaml)
			if tc.none {
				if len(warns) != 0 {
					t.Fatalf("expected no warnings, got %v", warns)
				}
				return
			}
			joined := strings.Join(warns, "\n")
			for _, w := range tc.want {
				if !strings.Contains(joined, w) {
					t.Errorf("expected a warning containing %q, got:\n%s", w, joined)
				}
			}
		})
	}
}

// A hold-everything-for-approval rule (tools: "*" with require_cosign) is a
// deliberate posture STRICTER than deny-by-default — every call needs a human
// co-sign — so neither wildcard warning may fire on it, or --strict would fail
// CI on a hardened config.
func TestLintCosignEverythingIsNotAWildcardWarning(t *testing.T) {
	warns := lintYAML(t, `
audit_log: audit.jsonl
backends:
  - name: pay
    port: 9101
    stdio: [server]
    cosign_store: approvals
    approval_signing_key: approver.pub
    policy:
      rules:
        - peers: ["*"]
          tools: ["*"]
          allow: true
          require_cosign: true
`)
	for _, w := range warns {
		if strings.Contains(w, "wildcard") || strings.Contains(w, "allows every peer every tool") {
			t.Fatalf("cosign-everything must not trip the wildcard lints: %v", warns)
		}
	}
}

func TestLintTimeScopedRuleDoesNotShadow(t *testing.T) {
	warns := lintYAML(t, `
audit_log: audit.jsonl
backends:
  - name: fs
    port: 9101
    stdio: [server]
    policy:
      rules:
        - peers: ["*"]
          tools: ["read_*"]
          allow: true
          rate: {max: 5, per: 1m}
          when: {days: [mon], hours: "09:00-17:00"}
        - peers: ["pubkey:K1"]
          tools: [read_file]
          allow: true
          rate: {max: 5, per: 1m}
`)
	for _, w := range warns {
		if strings.Contains(w, "shadowed") {
			t.Fatalf("a when-scoped rule must not count as shadowing: %v", warns)
		}
	}
}
