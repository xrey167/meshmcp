package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
)

// TestRevokeDeviceOneShot proves the lost-device flow severs every local trust
// surface in one command: pairing recognition, written grants, outstanding
// capabilities (subject revocation), and the operator surface — with each
// action recorded on the gateway's tamper-evident ledger.
func TestRevokeDeviceOneShot(t *testing.T) {
	t.Setenv("MESHMCP_HOME", t.TempDir())
	t.Setenv("NB_API_TOKEN", "")
	dir := t.TempDir()
	stolen := "STOLEN-KEY"

	// A paired peer.
	pairPath := filepath.Join(dir, "paired.json")
	ps, err := air.OpenPairedStore(pairPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	if _, _, err := ps.Request(air.VerifiedIdentity{PublicKey: stolen}, "laptop", now); err != nil {
		t.Fatal(err)
	}
	if _, err := ps.Approve(stolen, "op", now); err != nil {
		t.Fatal(err)
	}

	// A written grant + a pending opportunity.
	grantPath := filepath.Join(dir, "grants.json")
	gs, err := air.OpenGrantStore(grantPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gs.Add(stolen, "kg", "corpus/*", false, "op", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := gs.Record(stolen, "kg", "secret/*", now); err != nil {
		t.Fatal(err)
	}

	// A capability revocation store on a backend.
	revDir := filepath.Join(dir, "rev")
	auditPath := filepath.Join(dir, "audit.jsonl")

	cfg := writeConfig(t, `
mesh:
  device_name: gw
audit_log: `+auditPath+`
operators:
  - pubkey: STOLEN-KEY
  - pubkey: KEEP-KEY
control:
  port: 9600
  allow: ["pubkey:STOLEN-KEY", "pubkey:KEEP-KEY"]
  pair_store: `+pairPath+`
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
    policy:
      default_allow: false
    capabilities:
      trusted_public_keys: ["`+strings.Repeat("ab", 32)+`"]
      revocation_store: `+revDir+`
`)

	if err := cmdRevokeDevice([]string{"--config", cfg, "--grant-store", grantPath, stolen}); err != nil {
		t.Fatalf("revoke-device: %v", err)
	}

	// Pairing recognition is gone.
	ps2, err := air.OpenPairedStore(pairPath)
	if err != nil {
		t.Fatal(err)
	}
	if ps2.Recognized(stolen, "") {
		t.Error("identity still recognized after revoke-device")
	}

	// Grants and the pending opportunity are gone.
	gs2, err := air.OpenGrantStore(grantPath)
	if err != nil {
		t.Fatal(err)
	}
	if gs2.Check(stolen, "kg", "corpus/*") {
		t.Error("grant survived revoke-device")
	}
	for _, p := range gs2.Pending() {
		if p.Identity == stolen {
			t.Error("pending grant opportunity survived revoke-device")
		}
	}

	// The identity is subject-revoked in the capability store.
	rev := policy.FileRevocation{Dir: revDir}
	if !rev.IsSubjectRevoked(stolen) {
		t.Error("identity not subject-revoked in the capability store")
	}

	// The operator surface no longer carries the identity — but keeps the other
	// operator (revoking one device must not lock everyone out).
	loaded, err := loadConfig(cfg)
	if err != nil {
		t.Fatalf("config after revoke: %v", err)
	}
	for _, o := range loaded.Operators {
		if o.PubKey == stolen {
			t.Error("identity still an operator after revoke-device")
		}
	}
	if len(loaded.Operators) != 1 || loaded.Operators[0].PubKey != "KEEP-KEY" {
		t.Errorf("other operator was disturbed: %+v", loaded.Operators)
	}
	for _, a := range loaded.Control.Allow {
		if a == "pubkey:"+stolen {
			t.Error("identity still in control.allow after revoke-device")
		}
	}

	// Every action landed on the tamper-evident ledger and the chain verifies.
	b, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"revoke-device/pairing", "revoke-device/grants", "revoke-device/capabilities", "revoke-device/operators"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("audit ledger missing %q", want)
		}
	}
	if res, err := policy.VerifyChain(strings.NewReader(string(b))); err != nil || !res.OK {
		t.Fatalf("revocation audit chain must verify: %+v err=%v", res, err)
	}
}

// TestRevokeDeviceRefusesLockout proves that revoking the ONLY allowed control
// identity is refused (the mutated config would fail validation), leaving the
// original config intact rather than locking every operator out.
func TestRevokeDeviceRefusesLockout(t *testing.T) {
	t.Setenv("MESHMCP_HOME", t.TempDir())
	t.Setenv("NB_API_TOKEN", "")
	cfg := writeConfig(t, `
mesh:
  device_name: gw
control:
  port: 9600
  allow: ["pubkey:ONLY-KEY"]
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
`)
	// The command reports the failed step and exits non-zero…
	if err := cmdRevokeDevice([]string{"--config", cfg, "ONLY-KEY"}); err == nil {
		t.Fatal("expected an error when revocation would lock out every operator")
	}
	// …and the config is unchanged (still loads, still names the identity).
	loaded, err := loadConfig(cfg)
	if err != nil {
		t.Fatalf("config must remain valid: %v", err)
	}
	if len(loaded.Control.Allow) != 1 || loaded.Control.Allow[0] != "pubkey:ONLY-KEY" {
		t.Errorf("config was mutated despite the refusal: %+v", loaded.Control.Allow)
	}
}
