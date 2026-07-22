package main

import (
	"bytes"
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

// TestConfigStrictRejectsSecurityTypos is the Phase-9.1 regression: a misspelled
// or misplaced SECURITY field must fail startup, not be silently ignored (which
// would fail open — the control the operator meant to enable never fires).
func TestConfigStrictRejectsSecurityTypos(t *testing.T) {
	base := `backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
    policy:
      default_allow: false
      rules:
        - peers: ["*"]
          tools: ["read_*"]
          allow: true
`
	// Sanity: the base config is valid.
	if err := writeAndLoad(t, base); err != nil {
		t.Fatalf("base config should load: %v", err)
	}

	cases := map[string]string{
		"audit_fail_closed typo (top level)": base + "audit_fail_clsoed: true\n",
		"default_allow typo (policy)": `backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
    policy:
      defualt_allow: false
`,
		"require_cosign typo (rule)": `backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
    policy:
      default_allow: false
      rules:
        - peers: ["*"]
          tools: ["pay"]
          require_cosgin: true
`,
		"taint_guard typo (rule)": `backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
    policy:
      default_allow: false
      rules:
        - peers: ["*"]
          tools: ["deploy"]
          taint_gaurd: true
`,
	}
	for name, cfg := range cases {
		if err := writeAndLoad(t, cfg); err == nil {
			t.Fatalf("%s: expected strict-decode to reject the typo, but it loaded", name)
		}
	}
}

// TestConfigApprovalKeyRequiresCosignStore is the F-P3.2 config guard: enabling
// request-bound approvals (approval_signing_key) without the shared cosign_store
// the approver writes to is a security-config error and must fail startup, not
// silently fall back to the weaker ambient co-sign.
func TestConfigApprovalKeyRequiresCosignStore(t *testing.T) {
	// approval_signing_key with no cosign_store → error.
	bad := `backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
    approval_signing_key: "/tmp/approval.key"
    policy:
      default_allow: false
`
	if err := writeAndLoad(t, bad); err == nil || !strings.Contains(err.Error(), "cosign_store") {
		t.Fatalf("approval_signing_key without cosign_store must fail startup, got %v", err)
	}
	// With a cosign_store → the pairing is accepted at config time.
	good := `backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
    cosign_store: "./cosign"
    approval_signing_key: "/tmp/approval.key"
    policy:
      default_allow: false
`
	if err := writeAndLoad(t, good); err != nil {
		t.Fatalf("approval_signing_key with cosign_store should validate: %v", err)
	}
}

// TestConfigControlRequiresAllowList is the Air-control default-deny guard: the
// session list/steer endpoint is privileged, so enabling it (control.port) with
// no control.allow must fail startup rather than silently admit any mesh peer.
func TestConfigControlRequiresAllowList(t *testing.T) {
	base := `backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
`
	// control enabled, no allow list → error.
	noAllow := base + `control:
  port: 9700
`
	if err := writeAndLoad(t, noAllow); err == nil || !strings.Contains(err.Error(), "allow list") {
		t.Fatalf("control endpoint without allow list must fail startup, got %v", err)
	}
	// control enabled with an allow list → loads.
	withAllow := base + `control:
  port: 9700
  allow: ["pubkey:KEY"]
`
	if err := writeAndLoad(t, withAllow); err != nil {
		t.Fatalf("control endpoint with an allow list should load: %v", err)
	}
}

func writeAndLoad(t *testing.T, body string) error {
	t.Helper()
	f := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadConfig(f)
	return err
}

// TestExampleGatewayConfigsLoadStrictly guards that enabling strict decoding did
// not break any real gateway config (every example with a top-level backends:).
func TestExampleGatewayConfigsLoadStrictly(t *testing.T) {
	files, _ := filepath.Glob("examples/*.yaml")
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil || !bytes.Contains(data, []byte("\nbackends:")) && !bytes.HasPrefix(data, []byte("backends:")) {
			continue // not a gateway config
		}
		if _, err := loadConfig(f); err != nil {
			t.Errorf("gateway example %s no longer loads under strict decode: %v", filepath.Base(f), err)
		}
	}
}
