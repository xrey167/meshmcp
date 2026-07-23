package main

import (
	"os"
	"strings"
	"testing"
)

// TestOperatorsRecognizedOnControlACL proves a configured operator is admitted
// by the same acl the control/steer and pairing-approver surface gate on, so a
// second operator can approve and pair without being in control.allow.
func TestOperatorsRecognizedOnControlACL(t *testing.T) {
	ops := []OperatorConfig{
		{PubKey: "OPKEY1", FQDN: "alice.netbird.cloud"},
		{FQDN: "ops-*.netbird.cloud"},
	}
	a := newACL(append([]string{"pubkey:PRIMARY"}, operatorPatterns(ops)...))

	// Operator by pubkey.
	if !a.allows("OPKEY1", "alice.netbird.cloud") {
		t.Errorf("operator pubkey not recognized")
	}
	// Operator by FQDN glob.
	if !a.allows("ZZZ", "ops-7.netbird.cloud") {
		t.Errorf("operator fqdn glob not recognized")
	}
	// A non-operator, non-allowed peer is still denied.
	if a.allows("STRANGER", "random.netbird.cloud") {
		t.Errorf("a stranger was admitted")
	}
}

// TestConfigOperatorsSatisfyControlDefaultDeny proves the control endpoint is
// valid with operators but no control.allow (operators count as allowed
// identities), and that an empty-identity operator is rejected.
func TestConfigOperatorsSatisfyControlDefaultDeny(t *testing.T) {
	okCfg := writeConfig(t, `
operators:
  - pubkey: OPKEY1
    fqdn: alice.netbird.cloud
control:
  port: 9600
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
`)
	if _, err := loadConfig(okCfg); err != nil {
		t.Fatalf("operators-only control config should load: %v", err)
	}

	badCfg := writeConfig(t, `
operators:
  - roles: ["admin"]
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
`)
	if _, err := loadConfig(badCfg); err == nil {
		t.Fatalf("an operator with no pubkey/fqdn must be rejected")
	}
}

// TestAirOperatorAddRemovePreservesFile proves the operator mutator adds and
// removes entries, rejects duplicates, and leaves an untouched comment in place
// (surgical YAML edit, not a full re-render).
func TestAirOperatorAddRemovePreservesFile(t *testing.T) {
	cfg := writeConfig(t, `# my gateway
control:
  port: 9600
  allow: ["pubkey:PRIMARY"]
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
`)

	if err := cmdAirOperator([]string{"add", "--config", cfg, "--pubkey", "OP1", "--fqdn", "bob.netbird.cloud"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	loaded, err := loadConfig(cfg)
	if err != nil {
		t.Fatalf("reload after add: %v", err)
	}
	if len(loaded.Operators) != 1 || loaded.Operators[0].PubKey != "OP1" || loaded.Operators[0].FQDN != "bob.netbird.cloud" {
		t.Fatalf("operator not added correctly: %+v", loaded.Operators)
	}
	// The hand-authored comment survives the surgical edit.
	raw, _ := os.ReadFile(cfg)
	if !strings.Contains(string(raw), "# my gateway") {
		t.Errorf("surgical edit dropped the file's comment:\n%s", raw)
	}

	// Duplicate add is refused.
	if err := cmdAirOperator([]string{"add", "--config", cfg, "--pubkey", "OP1"}); err == nil {
		t.Errorf("duplicate operator add should fail")
	}

	// Remove drops it.
	if err := cmdAirOperator([]string{"remove", "--config", cfg, "--pubkey", "OP1"}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	loaded, err = loadConfig(cfg)
	if err != nil {
		t.Fatalf("reload after remove: %v", err)
	}
	if len(loaded.Operators) != 0 {
		t.Errorf("operator not removed: %+v", loaded.Operators)
	}

	// Removing a missing operator errors.
	if err := cmdAirOperator([]string{"remove", "--config", cfg, "--pubkey", "OP1"}); err == nil {
		t.Errorf("removing a non-operator should fail")
	}
}

// TestResolveApproverBindsToOperators proves the approve CLI stops self-asserting
// identity: with a config carrying operators, --approver is required and must
// match one; without operators it falls back to a clearly-unverified os: label.
func TestResolveApproverBindsToOperators(t *testing.T) {
	cfg := writeConfig(t, `
operators:
  - pubkey: OP1
    fqdn: bob.netbird.cloud
control:
  port: 9600
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
`)

	// A matching operator is accepted.
	if who, err := resolveApprover("OP1", cfg); err != nil || who != "OP1" {
		t.Errorf("matching operator: who=%q err=%v", who, err)
	}
	// Matching by FQDN is accepted too.
	if who, err := resolveApprover("bob.netbird.cloud", cfg); err != nil || who != "bob.netbird.cloud" {
		t.Errorf("matching operator fqdn: who=%q err=%v", who, err)
	}
	// A non-operator is refused.
	if _, err := resolveApprover("STRANGER", cfg); err == nil {
		t.Errorf("a non-operator approver must be refused")
	}
	// A missing approver against a configured operators list is refused.
	if _, err := resolveApprover("", cfg); err == nil {
		t.Errorf("missing --approver with operators configured must be refused")
	}

	// With no config/operators, the OS fallback is an explicitly-unverified label.
	t.Setenv("USER", "dana")
	who, err := resolveApprover("", "")
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	if who != "os:dana" {
		t.Errorf("unverified fallback = %q, want os:dana", who)
	}
}
