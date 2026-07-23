package main

import (
	"os"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// TestReloadPoliciesHotSwapsRules proves a SIGHUP-style reload picks up edited
// policy rules for a running backend's Engine without a restart, matched by
// backend name.
func TestReloadPoliciesHotSwapsRules(t *testing.T) {
	// A backend that denies "search" (deny-by-default, no rules).
	path := writeConfig(t, `
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
    policy:
      default_allow: false
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(cfg.Backends[0].Policy, func() time.Time { return time.Unix(0, 0) }, nil)
	engines := map[string]*policy.Engine{"kb": eng}

	if d := eng.DecideToolCall("peer.example", "k", "search", nil); d.Allow {
		t.Fatalf("initial policy should deny search, got %+v", d)
	}

	// Edit the config on disk to permit "search", then reload.
	edited := `
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
    policy:
      default_allow: false
      rules:
        - peers: ["*"]
          tools: ["search"]
          allow: true
`
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	reloadPolicies(path, engines)

	if d := eng.DecideToolCall("peer.example", "k", "search", nil); !d.Allow {
		t.Fatalf("after reload, search should be allowed, got %+v", d)
	}
}

// TestReloadPoliciesFailSafeOnBadConfig proves a config that no longer parses
// leaves every running policy untouched — a typo can never disarm the gateway.
func TestReloadPoliciesFailSafeOnBadConfig(t *testing.T) {
	path := writeConfig(t, `
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
    policy:
      default_allow: false
      rules:
        - peers: ["*"]
          tools: ["search"]
          allow: true
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	eng := policy.NewEngine(cfg.Backends[0].Policy, func() time.Time { return time.Unix(0, 0) }, nil)
	engines := map[string]*policy.Engine{"kb": eng}

	if d := eng.DecideToolCall("peer.example", "k", "search", nil); !d.Allow {
		t.Fatalf("precondition: search should be allowed, got %+v", d)
	}

	// Corrupt the config, then reload — the running policy must be unchanged.
	if err := os.WriteFile(path, []byte("this: is: not: valid: yaml: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	reloadPolicies(path, engines)

	if d := eng.DecideToolCall("peer.example", "k", "search", nil); !d.Allow {
		t.Fatalf("after a bad reload, the running policy must be unchanged (still allow), got %+v", d)
	}
}
