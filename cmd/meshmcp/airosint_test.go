package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
)

// A config whose backend Allow is broad but whose secret grant is narrow — the
// projection must key secret exposure off the grant, not the allow.
const secretsConfigYAML = `
mesh:
  device_name: ml-gw
backends:
  - name: payments
    port: 9101
    stdio: ["python", "pay.py"]
    allow: ["laptop-*.netbird.cloud"]
    audit_log: "/tmp/pay-audit.jsonl"
    policy:
      default_allow: false
      rules:
        - peers: ["pubkey:ADMIN"]
          tools: ["charge"]
          allow: true
    secrets:
      file: "/tmp/secrets.json"
      grants:
        - peers: ["pubkey:ADMIN"]
          secrets: ["STRIPE_KEY"]
          tools: ["charge"]
`

func TestProjectExposure_ReadsAllowSecretsPolicyAudit(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, secretsConfigYAML))
	if err != nil {
		t.Fatal(err)
	}
	m := projectExposure(cfg)
	if len(m.Backends) != 1 {
		t.Fatalf("backends = %d, want 1", len(m.Backends))
	}
	b := m.Backends[0]
	if b.Name != "payments" || b.Transport != "stdio" {
		t.Errorf("backend = %+v", b)
	}
	if !b.Audited {
		t.Error("backend has an audit_log; should be Audited")
	}
	if b.DefaultAllow {
		t.Error("policy is default-deny; DefaultAllow should be false")
	}
	if len(b.SecretGrants) != 1 || b.SecretGrants[0].Secrets[0] != "STRIPE_KEY" {
		t.Errorf("secret grants = %+v", b.SecretGrants)
	}
	if b.SecretGrants[0].Peers[0] != "pubkey:ADMIN" {
		t.Errorf("grant peers = %v, want the grant's own peers", b.SecretGrants[0].Peers)
	}
}

func TestProjectExposure_SecretExposureKeysOffGrantPeers(t *testing.T) {
	cfg, err := loadConfig(writeConfig(t, secretsConfigYAML))
	if err != nil {
		t.Fatal(err)
	}
	m := projectExposure(cfg)

	// laptop-3 passes the backend allow but is NOT in the grant peers → no secret.
	laptop := air.ReachabilityFor(m, "laptop-3.netbird.cloud")
	if len(laptop.Backends) != 1 {
		t.Fatalf("laptop should reach payments via allow, got %v", laptop.Backends)
	}
	if len(laptop.Secrets) != 0 {
		t.Errorf("laptop secrets = %v, want none (keyed off grant peers, not allow)", laptop.Secrets)
	}
	// ADMIN is in the grant peers but does NOT match the FQDN allow → cannot reach
	// the backend at all, so also no secret. This proves the grant, not the allow,
	// is the secret gate.
	admin := air.ReachabilityFor(m, "pubkey:ADMIN")
	if len(admin.Backends) != 0 {
		t.Errorf("admin does not match the FQDN allow; reach = %v, want none", admin.Backends)
	}
}

func TestGrantIsCosigned_CorrelatesToAuthorizingRule(t *testing.T) {
	// The rule that authorizes the injecting tool requires cosign → cosigned.
	polCosign := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"pubkey:X"}, Tools: []string{"charge"}, Allow: true, RequireCosign: true},
	}}
	if !grantIsCosigned(polCosign, []string{"charge"}) {
		t.Error("grant should be cosigned when the authorizing rule requires cosign")
	}
	// No cosign on the authorizing rule → not cosigned.
	polNo := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"pubkey:X"}, Tools: []string{"charge"}, Allow: true},
	}}
	if grantIsCosigned(polNo, []string{"charge"}) {
		t.Error("grant must not be cosigned when the authorizing rule does not require it")
	}
	// Default-allow policy: an unmatched call falls through un-cosigned.
	if grantIsCosigned(&policy.Policy{DefaultAllow: true}, []string{"charge"}) {
		t.Error("default-allow policy is never cosigned")
	}
}

func TestCmdAirOsint_RefusesRemoteTarget(t *testing.T) {
	// A positional target is refused outright.
	if err := cmdAirOsint([]string{"--config", "x.yaml", "100.64.0.2:9443"}); err == nil || !strings.Contains(err.Error(), "not a remote target") {
		t.Errorf("positional target: err = %v, want a self-scope refusal", err)
	}
	// A URL as --config is refused.
	if err := cmdAirOsint([]string{"--config", "https://evil.example/gw.yaml"}); err == nil || !strings.Contains(err.Error(), "LOCAL config") {
		t.Errorf("url config: err = %v, want a self-scope refusal", err)
	}
	// A host:port as --config is refused.
	if err := cmdAirOsint([]string{"--config", "100.64.0.2:9443"}); err == nil {
		t.Error("host:port config should be refused")
	}
}

func TestIsRemoteConfigTarget(t *testing.T) {
	remote := []string{"https://x/y.yaml", "http://x", "100.64.0.2:9443", "example.com:443"}
	local := []string{"gateway.yaml", "./cfg/gw.yaml", "/etc/meshmcp/gw.yaml", `C:\cfg\gw.yaml`}
	for _, p := range remote {
		if !isRemoteConfigTarget(p) {
			t.Errorf("%q should be treated as a remote target", p)
		}
	}
	for _, p := range local {
		if isRemoteConfigTarget(p) {
			t.Errorf("%q should be treated as a local path", p)
		}
	}
}

func TestVerifySelfGateway_RefusesForeign(t *testing.T) {
	if err := verifySelfGateway("attacker-gw.netbird.cloud", "my-gw.netbird.cloud"); err == nil {
		t.Error("a foreign gateway identity must be refused in --live")
	}
	if err := verifySelfGateway("my-gw.netbird.cloud", "my-gw.netbird.cloud"); err != nil {
		t.Errorf("own gateway should pass, got %v", err)
	}
	if err := verifySelfGateway("", "my-gw.netbird.cloud"); err != nil {
		t.Errorf("empty live identity should pass (target derived from local id), got %v", err)
	}
}

func TestEnsureSeparateLedger_RefusesGatewayOwnLog(t *testing.T) {
	cfg := &Config{
		AuditLog: "/tmp/gateway-audit.jsonl",
		Backends: []*Backend{{Name: "a", AuditLog: "/tmp/backend-audit.jsonl"}},
	}
	if err := ensureSeparateLedger("/tmp/gateway-audit.jsonl", cfg); err == nil {
		t.Error("must refuse the gateway-wide audit_log")
	}
	if err := ensureSeparateLedger("/tmp/backend-audit.jsonl", cfg); err == nil {
		t.Error("must refuse a backend's audit_log")
	}
	if err := ensureSeparateLedger("/tmp/osint-ledger.jsonl", cfg); err != nil {
		t.Errorf("a separate ledger must be accepted, got %v", err)
	}
}

func TestCmdAirOsint_EmitsAllowRecord_NotDeny(t *testing.T) {
	// A config with a critical finding (secrets, no cosign) still records the run
	// as Decision:allow — a report is not a policy denial.
	cfgYAML := `
mesh:
  device_name: ml-gw
backends:
  - name: payments
    port: 9101
    stdio: ["python", "pay.py"]
    allow: ["*"]
    policy:
      default_allow: false
      rules:
        - peers: ["*"]
          tools: ["charge"]
          allow: true
    secrets:
      file: "/tmp/secrets.json"
      grants:
        - peers: ["*"]
          secrets: ["STRIPE_KEY"]
`
	cfgPath := writeConfig(t, cfgYAML)
	ledger := filepath.Join(t.TempDir(), "osint.jsonl")
	if err := cmdAirOsint([]string{"--config", cfgPath, "--audit-log", ledger, "--json"}); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	data, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatalf("ledger not written: %v", err)
	}
	var rec policy.AuditRecord
	line := bytes.TrimSpace(bytes.Split(data, []byte("\n"))[0])
	if err := json.Unmarshal(line, &rec); err != nil {
		t.Fatalf("bad record: %v", err)
	}
	if rec.Method != "air/osint" {
		t.Errorf("method = %q, want air/osint", rec.Method)
	}
	if rec.Decision != "allow" {
		t.Errorf("decision = %q, want allow (a report is never a deny)", rec.Decision)
	}
	if !strings.Contains(rec.Reason, "grade=F") {
		t.Errorf("reason = %q, want grade carried in reason", rec.Reason)
	}
	// The chain must verify.
	if res, err := policy.VerifyChain(bytes.NewReader(data)); err != nil || !res.OK {
		t.Errorf("osint ledger chain does not verify: ok=%v err=%v", res.OK, err)
	}
}

func TestCmdAirOsint_FailOn_ExitCode(t *testing.T) {
	cfgYAML := `
mesh:
  device_name: gw
backends:
  - name: scratch
    port: 9101
    stdio: ["cat"]
    allow: ["pubkey:X"]
`
	cfgPath := writeConfig(t, cfgYAML)
	// This backend has no audit and no policy → high findings. --fail-on high must
	// return a non-nil error (non-zero exit).
	if err := cmdAirOsint([]string{"--config", cfgPath, "--fail-on", "high", "--json"}); err == nil {
		t.Error("--fail-on high should fail on a high-severity surface")
	}
	// --fail-on critical passes (no criticals here).
	if err := cmdAirOsint([]string{"--config", cfgPath, "--fail-on", "critical", "--json"}); err != nil {
		t.Errorf("--fail-on critical should pass with no criticals, got %v", err)
	}
}

func TestCmdAirOsint_SnapshotBaselineThenDiff(t *testing.T) {
	cfgYAML := `
mesh:
  device_name: gw
backends:
  - name: a
    port: 9101
    stdio: ["cat"]
    allow: ["pubkey:X"]
    audit_log: "/tmp/a.jsonl"
    policy:
      default_allow: false
      rules:
        - peers: ["pubkey:X"]
          tools: ["*"]
          allow: true
`
	cfgPath := writeConfig(t, cfgYAML)
	snap := filepath.Join(t.TempDir(), "osint.json")
	// First run: baseline saved, file created.
	if err := cmdAirOsint([]string{"--config", cfgPath, "--snapshot", snap, "--json"}); err != nil {
		t.Fatalf("baseline run: %v", err)
	}
	if _, err := os.Stat(snap); err != nil {
		t.Fatalf("baseline snapshot not written: %v", err)
	}
	// Second run against the same config: no drift, still succeeds.
	if err := cmdAirOsint([]string{"--config", cfgPath, "--snapshot", snap, "--json"}); err != nil {
		t.Fatalf("diff run: %v", err)
	}
}

func TestRenderOsintReport_ShowsGradeAndFindings(t *testing.T) {
	m := air.MeshExposure{
		Gateway: "ml-gw",
		Backends: []air.BackendExposure{{
			Name: "payments", Transport: "stdio", Allow: []string{"*"},
			SecretGrants: []air.SecretGrantExposure{{Secrets: []string{"STRIPE_KEY"}, Peers: []string{"*"}, Cosigned: false}},
		}},
	}
	report := air.BuildReport(m, func() string { return "2026-07-22T00:00:00Z" })
	var buf bytes.Buffer
	renderOsintReport(&buf, report, 3)
	out := buf.String()
	if !strings.Contains(out, "Privacy Report") || !strings.Contains(out, "grade F") {
		t.Errorf("render missing header/grade:\n%s", out)
	}
	if !strings.Contains(out, "secrets-no-cosign") {
		t.Errorf("render missing the critical finding:\n%s", out)
	}
}
