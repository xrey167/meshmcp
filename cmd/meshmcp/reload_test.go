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
	reloadPolicies(path, engines, nil, acl{}, acl{})

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
	reloadPolicies(path, engines, nil, acl{}, acl{})

	if d := eng.DecideToolCall("peer.example", "k", "search", nil); !d.Allow {
		t.Fatalf("after a bad reload, the running policy must be unchanged (still allow), got %+v", d)
	}
}

// TestACLCopiesShareSwaps pins the mechanism ACL hot-reload rests on: every
// COPY of an acl (accept loops capture copies at startup) observes a later
// swap through any other copy, because the pattern list is behind one shared
// atomic pointer.
func TestACLCopiesShareSwaps(t *testing.T) {
	original := newACL([]string{"pubkey:OLD"})
	captured := original // what an accept loop closes over

	if !captured.allows("OLD", "x.mesh") || captured.allows("NEW", "x.mesh") {
		t.Fatal("precondition: only OLD admitted")
	}
	original.swap([]string{"pubkey:NEW"})
	if captured.allows("OLD", "x.mesh") {
		t.Error("captured copy still admits the removed identity after swap")
	}
	if !captured.allows("NEW", "x.mesh") {
		t.Error("captured copy does not admit the added identity after swap")
	}
	// The zero acl ignores swaps and stays fail-open-for-identified /
	// fail-closed-for-anonymous, unchanged.
	var zero acl
	zero.swap([]string{"pubkey:X"})
	if !zero.allows("anyone", "a.mesh") || zero.allows("", "") {
		t.Error("zero acl semantics changed")
	}
}

// TestReloadPoliciesSwapsACLs proves a SIGHUP-path reload applies an edited
// backend allow list and control allow list to the RUNNING handles — a peer
// denied at startup is admitted after the config edit + reload, with no
// restart and no re-plumbed accept loop.
func TestReloadPoliciesSwapsACLs(t *testing.T) {
	path := writeConfig(t, `
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
    allow: ["pubkey:ALICE"]
control:
  port: 9600
  allow: ["pubkey:ALICE"]
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Simulate cmdServe's startup wiring: install the live handles and hand
	// copies to "accept loops".
	b := cfg.Backends[0]
	b.allowACL = newACL(b.Allow)
	backends := map[string]*Backend{b.Name: b}
	backendChecker := b.peerACL() // captured copy
	controlAllow := newACL(append(append([]string(nil), cfg.Control.Allow...), operatorPatterns(cfg.Operators)...))
	controlChecker := controlAllow

	if backendChecker.allows("BOB", "bob.mesh") || controlChecker.allows("BOB", "bob.mesh") {
		t.Fatal("precondition: BOB must be denied everywhere")
	}

	edited := `
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
    allow: ["pubkey:ALICE", "pubkey:BOB"]
control:
  port: 9600
  allow: ["pubkey:ALICE"]
operators:
  - pubkey: BOB
`
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	reloadPolicies(path, map[string]*policy.Engine{}, backends, controlAllow, acl{})

	if !backendChecker.allows("BOB", "bob.mesh") {
		t.Error("backend checker did not pick up the widened allow list")
	}
	if !backendChecker.allows("ALICE", "alice.mesh") {
		t.Error("existing identity lost admission on reload")
	}
	// BOB became an operator — the control surface admits him via operatorPatterns.
	if !controlChecker.allows("BOB", "bob.mesh") {
		t.Error("control checker did not pick up the new operator")
	}

	// Fail-safe: a broken config leaves the running ACLs untouched.
	if err := os.WriteFile(path, []byte("not: valid: yaml: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	reloadPolicies(path, map[string]*policy.Engine{}, backends, controlAllow, acl{})
	if !backendChecker.allows("BOB", "bob.mesh") {
		t.Error("a bad reload must not change the running ACLs")
	}
}
