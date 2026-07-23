package harness

import (
	"sort"

	"github.com/xrey167/meshmcp/policy"
)

// Role is a canonical capability role. It is the union of the source harnesses'
// role agents (Sisyphus, Prometheus, Atlas, Oracle, Librarian, Explore, Metis,
// Momus, Hephaestus, Multimodal-Looker; executor/architect/planner/critic),
// de-duplicated. A role is a POLICY SUBJECT: its capability set is not enforced
// in the harness but compiled to an agent-firewall policy document (CompilePolicy)
// and enforced by policy.Engine.
type Role string

const (
	RoleOrchestrator Role = "orchestrator"  // Sisyphus / team lead: delegates, does not write code
	RoleDeepWorker   Role = "deep-worker"   // Hephaestus: autonomous end-to-end in a sandbox
	RoleExecutor     Role = "executor"      // Atlas / executor: implements, writes code
	RolePlanner      Role = "planner"       // Prometheus / planner: interview + plan
	RolePreAnalyst   Role = "pre-analyst"   // Metis: gap/ambiguity finder
	RolePlanReviewer Role = "plan-reviewer" // Momus / critic: validates plans
	RoleArchitect    Role = "architect"     // Oracle / architect: read-only design review
	RoleLibrarian    Role = "librarian"     // multi-repo/doc search
	RoleExplorer     Role = "explorer"      // fast grep/context
	RoleLooker       Role = "looker"        // image/PDF/diagram vision
	RoleJunior       Role = "junior"        // category-spawned executor
)

// RoleSpec is a role's default capability set, expressed as the policy tool
// globs it may call, the labels it may emit, and which of its tools require a
// human co-sign. ReadOnly is a documentation/summary flag (a read-only role
// lists no code.write tools); it does not itself enforce anything.
type RoleSpec struct {
	Role        Role
	AllowTools  []string // policy tool-name globs this role may call
	CosignTools []string // subset that additionally requires a co-sign
	EmitLabels  []string // data-flow labels an allowed call adds to the session
	ReadOnly    bool
	Summary     string
}

// canonicalRoles is the fixed registry. Tool globs use the orchestrator tool
// catalog names (mcp/orchestrator) plus the coarse capability pseudo-tools the
// Governor authorizes (e.g. "delegate.spawn"). Everything not listed is denied
// by the default-deny posture of the compiled policy.
var canonicalRoles = map[Role]RoleSpec{
	RoleOrchestrator: {
		Role:        RoleOrchestrator,
		AllowTools:  []string{"task", "call_agent", "background_*", "plan", "plan_review", "interview", "start_work", "handoff", "review_work", "ultragoal_check", "synthesize", "route", "session_*", "task_*", "grep", "glob", "look_at", "delegate.*", "plan.*", "verify.*", "skill", "market"},
		CosignTools: []string{"market"},
		EmitLabels:  []string{LabelDelegateSpawn},
		ReadOnly:    true,
		Summary:     "delegating team lead; delegates work, does not write code itself",
	},
	RoleDeepWorker: {
		Role:        RoleDeepWorker,
		AllowTools:  []string{"grep", "glob", "edit", "lsp_*", "ast_grep_*", "interactive_bash", "session_read", "task_*", "look_at", "skill", "code.*", "exec.shell"},
		CosignTools: []string{"interactive_bash"},
		EmitLabels:  []string{LabelCodeWrite, LabelExecShell},
		Summary:     "autonomous end-to-end worker; runs in a sandbox",
	},
	RoleExecutor: {
		Role:        RoleExecutor,
		AllowTools:  []string{"grep", "glob", "edit", "lsp_diagnostics", "lsp_prepare_rename", "lsp_rename", "lsp_goto_definition", "lsp_find_references", "lsp_symbols", "ast_grep_search", "ast_grep_replace", "interactive_bash", "task_*", "code.*", "exec.shell"},
		CosignTools: []string{"interactive_bash"},
		EmitLabels:  []string{LabelCodeWrite, LabelExecShell},
		Summary:     "implements a plan; writes code",
	},
	RolePlanner: {
		Role:       RolePlanner,
		AllowTools: []string{"grep", "glob", "lsp_diagnostics", "lsp_goto_definition", "lsp_find_references", "lsp_symbols", "ast_grep_search", "session_read", "session_search", "interview", "plan", "look_at", "code.read", "plan.*", "search"},
		ReadOnly:   true,
		Summary:    "interviews and produces a plan; read-only over code",
	},
	RolePreAnalyst: {
		Role:       RolePreAnalyst,
		AllowTools: []string{"grep", "glob", "lsp_*", "ast_grep_search", "plan_review", "session_read", "code.read", "plan.read"},
		ReadOnly:   true,
		Summary:    "finds gaps and ambiguities in a plan",
	},
	RolePlanReviewer: {
		Role:       RolePlanReviewer,
		AllowTools: []string{"grep", "glob", "lsp_*", "ast_grep_search", "plan_review", "code.read", "plan.read"},
		ReadOnly:   true,
		Summary:    "validates a plan; emits pass/revise",
	},
	RoleArchitect: {
		Role:       RoleArchitect,
		AllowTools: []string{"grep", "glob", "lsp_goto_definition", "lsp_find_references", "lsp_symbols", "review_work", "code.read"},
		ReadOnly:   true,
		Summary:    "read-only design review",
	},
	RoleLibrarian: {
		Role:       RoleLibrarian,
		AllowTools: []string{"grep", "glob", "session_search", "market", "code.read", "search"},
		ReadOnly:   true,
		Summary:    "multi-repo/doc search",
	},
	RoleExplorer: {
		Role:       RoleExplorer,
		AllowTools: []string{"grep", "glob", "lsp_symbols", "ast_grep_search", "code.read", "search"},
		ReadOnly:   true,
		Summary:    "fast grep/context gathering",
	},
	RoleLooker: {
		Role:       RoleLooker,
		AllowTools: []string{"look_at", "media.read", "grep", "glob", "code.read"},
		ReadOnly:   true,
		Summary:    "image/PDF/diagram vision",
	},
	RoleJunior: {
		Role:       RoleJunior,
		AllowTools: []string{"grep", "glob", "edit", "lsp_diagnostics", "ast_grep_search", "ast_grep_replace", "task_*", "code.*"},
		EmitLabels: []string{LabelCodeWrite},
		Summary:    "category-spawned executor for a bounded task",
	},
}

// Roles returns the canonical role specs in a stable order.
func Roles() []RoleSpec {
	out := make([]RoleSpec, 0, len(canonicalRoles))
	for _, s := range canonicalRoles {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Role < out[j].Role })
	return out
}

// SpecFor returns the canonical spec for role and whether it is known.
func SpecFor(role Role) (RoleSpec, bool) {
	s, ok := canonicalRoles[role]
	return s, ok
}

// KnownRole reports whether role is in the canonical registry.
func KnownRole(role Role) bool {
	_, ok := canonicalRoles[role]
	return ok
}

// CompilePolicy turns the canonical role registry (optionally overlaid with
// overrides) into a default-deny policy.Policy that policy.Engine enforces. For
// each role it emits, in order:
//
//  1. a co-sign rule matching the role's CosignTools (Allow + RequireCosign),
//     placed first so a co-sign tool is never silently allowed by the plain
//     allow rule below it;
//  2. an allow rule matching the role's AllowTools, carrying EmitLabels;
//  3. a taint guard on net.egress-bearing calls (block when the session is
//     tainted) — prompt-injection defense at the network layer.
//
// Peers are matched by the "<role>--*" FQDN glob (see Identity). The policy's
// DefaultAllow is false, so anything unlisted is denied. This is the concrete
// "role capability sets -> allowlist policy docs" mapping from the spec.
func CompilePolicy(overrides map[Role]RoleSpec) *policy.Policy {
	specs := make([]RoleSpec, 0, len(canonicalRoles))
	for role, s := range canonicalRoles {
		if ov, ok := overrides[role]; ok {
			specs = append(specs, ov)
		} else {
			specs = append(specs, s)
		}
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].Role < specs[j].Role })

	pol := &policy.Policy{DefaultAllow: false}
	for _, s := range specs {
		peer := string(s.Role) + "--*"
		if len(s.CosignTools) > 0 {
			pol.Rules = append(pol.Rules, policy.Rule{
				Peers:         []string{peer},
				Tools:         s.CosignTools,
				Allow:         true,
				RequireCosign: true,
				EmitLabels:    s.EmitLabels,
			})
		}
		if len(s.AllowTools) > 0 {
			pol.Rules = append(pol.Rules, policy.Rule{
				Peers:      []string{peer},
				Tools:      s.AllowTools,
				Allow:      true,
				EmitLabels: s.EmitLabels,
			})
		}
	}
	return pol
}
