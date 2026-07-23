package main

import (
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

// TestConfigTrustDomainValidation covers Feature A's local trust_domain
// setting: a valid domain loads (strict decode included) and is plumbed to
// every backend; a malformed domain is a startup error; and omitting it is
// valid and leaves the plumbed value empty, so no label is ever derived and
// audit records stay byte-identical to a pre-Feature-A deployment.
func TestConfigTrustDomainValidation(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, `
trust_domain: mesh.example.org
backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
  - name: kg
    port: 9102
    stdio: ["echo"]
`))
	if err != nil {
		t.Fatalf("valid trust_domain should load: %v", err)
	}
	if cfg.TrustDomain != "mesh.example.org" {
		t.Fatalf("TrustDomain = %q, want mesh.example.org", cfg.TrustDomain)
	}
	for _, b := range cfg.Backends {
		if b.trustDomain != "mesh.example.org" {
			t.Fatalf("backend %q trustDomain = %q, want mesh.example.org", b.Name, b.trustDomain)
		}
	}

	for _, bad := range []string{"Mesh.Example.Org", "spiffe://mesh.example.org", "mesh example.org"} {
		_, err := loadConfig(writeConfig(t, `
trust_domain: "`+bad+`"
backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
`))
		if err == nil || !strings.Contains(err.Error(), "trust_domain") {
			t.Fatalf("trust_domain %q should be rejected at load, got %v", bad, err)
		}
	}

	cfg, err = loadConfig(writeConfig(t, `
backends:
  - name: fs
    port: 9101
    stdio: ["echo"]
`))
	if err != nil {
		t.Fatalf("config without trust_domain must stay valid: %v", err)
	}
	if cfg.TrustDomain != "" || cfg.Backends[0].trustDomain != "" {
		t.Fatalf("unset trust_domain should plumb empty, got %q / %q", cfg.TrustDomain, cfg.Backends[0].trustDomain)
	}
	// Empty trust domain ⇒ derivation yields "" ⇒ omitempty elides the field:
	// the exact off-switch serve.go relies on.
	if got := policy.SpiffeID(cfg.TrustDomain, "76SpfHTmmNI0CvRjH/y2ntoe0zdzeACvkl+IKrHlqYA="); got != "" {
		t.Fatalf("unset trust_domain must derive no label, got %q", got)
	}
}

// TestHTTPEnforcerRecordCarriesSpiffeID keeps the HTTP/remote audit path at
// parity with the stdio filter: with a trust domain the record carries the
// derived label; without one (or with no stable key) the field stays empty
// and omitempty elides it.
func TestHTTPEnforcerRecordCarriesSpiffeID(t *testing.T) {
	const key = "76SpfHTmmNI0CvRjH/y2ntoe0zdzeACvkl+IKrHlqYA="
	on := &httpEnforcer{backend: "kg", trustDomain: "mesh.example.org"}
	rec := on.record("tools/call", "search", "1", policy.Decision{RuleID: -1}, "agent.mesh", key)
	if want := policy.SpiffeID("mesh.example.org", key); rec.PeerSpiffeID != want || want == "" {
		t.Fatalf("PeerSpiffeID = %q, want %q", rec.PeerSpiffeID, want)
	}
	off := &httpEnforcer{backend: "kg"}
	if rec := off.record("tools/call", "search", "1", policy.Decision{RuleID: -1}, "agent.mesh", key); rec.PeerSpiffeID != "" {
		t.Fatalf("no trust domain must mean no label, got %q", rec.PeerSpiffeID)
	}
	if rec := on.record("tools/call", "search", "1", policy.Decision{RuleID: -1}, "agent.mesh", ""); rec.PeerSpiffeID != "" {
		t.Fatalf("no peer key must mean no label, got %q", rec.PeerSpiffeID)
	}
}
