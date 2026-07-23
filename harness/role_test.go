package harness

import (
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

// TestCompilePolicyMatrix asserts the compiled role policy is default-deny and
// that each canonical role's allow/deny footprint matches its capability set —
// the "role capability sets → allowlist policy docs" mapping.
func TestCompilePolicyMatrix(t *testing.T) {
	pol := CompilePolicy(nil)
	if pol.DefaultAllow {
		t.Fatal("compiled policy must be default-deny")
	}
	eng := policy.NewEngine(pol, nil, nil)

	// (role, tool, wantAllow) cases. FQDN follows the "<role>--<run>--<n>"
	// convention that "<role>--*" rules match.
	cases := []struct {
		role  Role
		tool  string
		allow bool
	}{
		{RoleExplorer, "grep", true},
		{RoleExplorer, "edit", false}, // read-only role cannot write code
		{RoleExplorer, "interactive_bash", false},
		{RoleExecutor, "edit", true},
		{RoleExecutor, "ast_grep_replace", true},
		{RoleArchitect, "edit", false}, // read-only reviewer
		{RoleArchitect, "review_work", true},
		{RolePlanner, "plan", true},
		{RolePlanner, "edit", false},
		{RoleOrchestrator, "task", true},
		{RoleOrchestrator, "edit", false}, // delegates instead of writing
		{RoleLooker, "look_at", true},
		{RoleLibrarian, "session_search", true},
	}
	for _, c := range cases {
		fqdn := string(c.role) + "--run1--0"
		d := eng.DecideToolCall(fqdn, "k-"+string(c.role), c.tool, nil)
		got := d.Outcome == policy.OutcomeAllow
		if got != c.allow {
			t.Errorf("role %s tool %q: got allow=%v (outcome=%s), want %v", c.role, c.tool, got, d.Outcome, c.allow)
		}
	}
}

// TestCompilePolicyCosign asserts a co-sign tool is held as OutcomeCosign until
// approved, proving the require_cosign rule is compiled ahead of the plain allow.
func TestCompilePolicyCosign(t *testing.T) {
	pol := CompilePolicy(nil)
	cos := policy.NewMemCosign()
	eng := policy.NewEngine(pol, nil, cos)

	fqdn := string(RoleOrchestrator) + "--run1--0"
	d := eng.DecideToolCall(fqdn, "k", "market", nil)
	if d.Outcome != policy.OutcomeCosign {
		t.Fatalf("market should need co-sign, got %s", d.Outcome)
	}
	cos.Approve(policy.CosignKey(fqdn, "market"))
	d = eng.DecideToolCall(fqdn, "k", "market", nil)
	if d.Outcome != policy.OutcomeAllow {
		t.Fatalf("market should be allowed after co-sign, got %s", d.Outcome)
	}
}

// TestUnknownRoleDenied asserts an identity whose FQDN matches no role rule is
// denied by the default-deny posture.
func TestUnknownRoleDenied(t *testing.T) {
	eng := policy.NewEngine(CompilePolicy(nil), nil, nil)
	d := eng.DecideToolCall("attacker.example", "k", "edit", nil)
	if d.Outcome == policy.OutcomeAllow {
		t.Fatal("an unmatched identity must be denied")
	}
}
