package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/air"
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

func TestConfigComponentCardIdentity(t *testing.T) {
	valid, err := loadConfig(writeConfig(t, `
backends:
  - name: knowledge
    id: com.example.meshmcp.knowledge
    version: 2.3.1
    port: 9101
    stdio: ["echo"]
`))
	if err != nil {
		t.Fatalf("component card config should load: %v", err)
	}
	if valid.Backends[0].ID != "com.example.meshmcp.knowledge" || valid.Backends[0].Version != "2.3.1" {
		t.Fatalf("component identity was not retained: %+v", valid.Backends[0])
	}

	cases := []struct {
		name, body, want string
	}{
		{"invalid id", `
backends:
  - name: fs
    id: com.example/fs
    port: 9101
    stdio: ["echo"]
`, "component id"},
		{"duplicate id", `
backends:
  - name: fs
    id: com.example.shared
    port: 9101
    stdio: ["echo"]
  - name: kg
    id: com.example.shared
    port: 9102
    stdio: ["echo"]
`, "already used"},
		{"duplicate name", `
backends:
  - name: " fs "
    port: 9101
    stdio: ["echo"]
  - name: fs
    port: 9102
    stdio: ["echo"]
`, "name is already used"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig(writeConfig(t, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
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
	files, _ := filepath.Glob("../../examples/*.yaml")
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

// TestConfigGroupsValidation pins the load-time bounds of the top-level
// `groups:` map, which feeds BOTH policy `group:` peers (F17) and the
// /v1/groups fan-out roster: names must fit the `group:<name>` selector
// grammar (no ":", bounded, control-free) and every member pattern must be a
// usable acl pattern. A defined-but-EMPTY pattern list stays legal — the loud
// no-op lives at fan-out time, not at load time.
func TestConfigGroupsValidation(t *testing.T) {
	base := `
backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
`
	if err := writeAndLoad(t, base+`
groups:
  oncall: ["pubkey:KEY-A", "*.lab.mesh"]
  quiet: []
`); err != nil {
		t.Fatalf("valid groups (including a defined-but-empty one) must load: %v", err)
	}

	cases := []struct{ name, yaml, want string }{
		{"colon in name", `
groups:
  "on:call": ["*"]
`, `":"`},
		{"control char in name", "\ngroups:\n  \"on\tcall\": [\"*\"]\n", "control"},
		{"padded name", `
groups:
  " oncall ": ["*"]
`, "surrounding whitespace"},
		{"name over bound", `
groups:
  ` + strings.Repeat("g", 65) + `: ["*"]
`, "at most"},
		{"empty member pattern", `
groups:
  oncall: ["pubkey:KEY-A", "  "]
`, "pattern #2: group pattern must be non-empty"},
		{"pubkey pattern without a key", `
groups:
  oncall: ["pubkey:  "]
`, "requires a key"},
		{"pattern over bound", `
groups:
  oncall: ["` + strings.Repeat("p", 257) + `"]
`, "at most 256 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := writeAndLoad(t, base+tc.yaml); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// TestValidateGroupsBounds covers the map-level caps directly (a YAML fixture
// with 257 groups would only obscure the rule).
func TestValidateGroupsBounds(t *testing.T) {
	many := map[string][]string{}
	for i := 0; i < maxGroups; i++ {
		many[fmt.Sprintf("g%03d", i)] = []string{"*"}
	}
	if err := validateGroups(many); err != nil {
		t.Fatalf("%d groups must be accepted: %v", maxGroups, err)
	}
	many["one-more"] = []string{"*"}
	if err := validateGroups(many); err == nil || !strings.Contains(err.Error(), "max is 256") {
		t.Fatalf("group-count cap = %v", err)
	}

	patterns := make([]string, maxGroupMembers)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("node-%02d.mesh", i)
	}
	if err := validateGroups(map[string][]string{"wide": patterns}); err != nil {
		t.Fatalf("%d member patterns must be accepted: %v", maxGroupMembers, err)
	}
	if err := validateGroups(map[string][]string{"wide": append(patterns, "extra.mesh")}); err == nil || !strings.Contains(err.Error(), "max is 64") {
		t.Fatalf("member-pattern cap = %v", err)
	}

	// The pattern caps alias the air envelope bounds, so config and wire can
	// never skew.
	if maxGroupMembers != air.MaxFanoutMembers {
		t.Fatalf("maxGroupMembers (%d) must alias air.MaxFanoutMembers (%d)", maxGroupMembers, air.MaxFanoutMembers)
	}
	if maxGroupPatternBytes != air.MaxGroupPatternBytes {
		t.Fatalf("maxGroupPatternBytes (%d) must alias air.MaxGroupPatternBytes (%d)", maxGroupPatternBytes, air.MaxGroupPatternBytes)
	}

	// A C1 control character (multi-byte in UTF-8, invisible in most terminals)
	// must be rejected exactly like a C0 one: the envelope's unmatched echo
	// rejects it, so the loader must never accept it.
	if err := validateGroups(map[string][]string{"oncall": {"gh\u0085ost.*"}}); err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("C1-control pattern = %v, want control-character rejection", err)
	}
}
