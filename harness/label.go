package harness

// Data-flow / capability labels. Every governed action carries a set of these
// labels; a role's policy either permits them or does not. They double as the
// policy.Rule EmitLabels/BlockLabels vocabulary (data-flow taint) and as the
// coarse capability names used when compiling roles to policy (role.go).
//
// The names mirror the four source harnesses' capability surface so an agent
// prompt written against those projects ports over unchanged.
const (
	// Code intelligence.
	LabelCodeRead  = "code.read"  // grep/glob/lsp read/ast search
	LabelCodeWrite = "code.write" // edit/lsp_rename/ast_grep_replace
	LabelSearch    = "search"     // web/library/public-code search

	// Delegation & orchestration.
	LabelDelegateSpawn   = "delegate.spawn"   // mint a worker / start a run
	LabelDelegateRead    = "delegate.read"    // read background job output
	LabelDelegateControl = "delegate.control" // cancel/steer a job

	// Planning & verification.
	LabelPlanRead   = "plan.read"
	LabelPlanWrite  = "plan.write"
	LabelVerifyRead = "verify.read"

	// Sessions & tasks.
	LabelSessionRead  = "session.read"
	LabelSessionWrite = "session.write"
	LabelTaskRead     = "task.read"
	LabelTaskWrite    = "task.write"

	// Execution & environment.
	LabelExecShell    = "exec.shell"
	LabelNetEgress    = "net.egress"
	LabelBrowserCtl   = "browser.control"
	LabelCanvasWrite  = "canvas.write"
	LabelControlNodes = "control.nodes"
	LabelControlCron  = "control.cron"
	LabelMediaRead    = "media.read"

	// Skills, market, secrets, federation.
	LabelSkillRun    = "skill.run"
	LabelSkillMCP    = "skill.mcp"
	LabelMarket      = "market"
	LabelMarketInst  = "market.install"
	LabelSecretRef   = "secrets.ref"
	LabelFederate    = "federate"
	LabelChannelSend = "channel.send"

	// Taint: a session that has ingested untrusted data carries this; egress
	// tools with a taint guard are then denied (prompt-injection defense at the
	// network layer, via policy.Rule.TaintGuard).
	LabelTainted = "tainted"
)

// highRiskLabels are the labels that, by default, require a human co-sign when
// they apply to a protected scope. Compiled into require_cosign policy rules.
var highRiskLabels = map[string]bool{
	LabelSecretRef:  true,
	LabelMarketInst: true,
	LabelFederate:   true,
}

// IsHighRisk reports whether any of labels defaults to needing co-sign.
func IsHighRisk(labels ...string) bool {
	for _, l := range labels {
		if highRiskLabels[l] {
			return true
		}
	}
	return false
}

// labelSet turns a label slice into the map form the policy engine consumes.
func labelSet(labels []string) map[string]bool {
	if len(labels) == 0 {
		return nil
	}
	m := make(map[string]bool, len(labels))
	for _, l := range labels {
		m[l] = true
	}
	return m
}
