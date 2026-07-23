package harness

import (
	"context"
	"fmt"
	"strings"

	"github.com/xrey167/meshmcp/harness/provider"
	"github.com/xrey167/meshmcp/harness/sandbox"
)

// This file exposes the engine's per-phase helpers as standalone, governed
// operations so the MCP orchestrator tools (plan, interview, review_work,
// ultragoal_check, synthesize, call_agent) can drive one phase without opening a
// full run. Each is attributed to the passed actor; the MCP layer authorizes the
// tool call itself before these run.

// ProviderAnswer is one provider's answer in a synthesize.
type ProviderAnswer struct {
	Provider  string `json:"provider"`
	Class     string `json:"class"`
	Answer    string `json:"answer"`
	TokensIn  int    `json:"tokens_in"`
	TokensOut int    `json:"tokens_out"`
}

// DoInterview runs the interview phase for goal (the `interview` tool).
func (e *Engine) DoInterview(ctx context.Context, goal string, rounds int) (Requirements, error) {
	return e.planner.Interview(ctx, "gpt-medium", goal, rounds)
}

// MakePlan produces a plan and its review verdict for goal (the `plan` +
// `plan_review` tools). style is prometheus|ralplan|team.
func (e *Engine) MakePlan(ctx context.Context, goal, style string) (Plan, PlanVerdict, error) {
	plan, err := e.planner.Plan(ctx, "gpt-medium", goal, style, newRunID(), nil)
	if err != nil {
		return Plan{}, PlanVerdict{}, err
	}
	v, err := e.planner.Review(ctx, "gpt-high", plan)
	if err != nil {
		return plan, PlanVerdict{}, err
	}
	plan.Verdict = &v
	return plan, v, nil
}

// DoReviewWork runs the review_work N-reviewer fan-out over a scope.
func (e *Engine) DoReviewWork(ctx context.Context, scope string, reviewers int) ([]Finding, string, error) {
	return e.verifier.ReviewWork(ctx, "adhoc", "gpt-medium", scope, reviewers)
}

// DoUltragoal runs the durable goal check.
func (e *Engine) DoUltragoal(ctx context.Context, goal string, evidence []string) (bool, []string, error) {
	return e.verifier.UltragoalCheck(ctx, "gpt-high", goal, evidence)
}

// DoSynthesize runs prompt across the given classes (or a sensible default set)
// and returns each answer plus a merged concatenation.
func (e *Engine) DoSynthesize(ctx context.Context, prompt string, classes []string) (string, []ProviderAnswer, error) {
	if len(classes) == 0 {
		classes = []string{"gpt-medium", "opus-class", "gemini-class"}
	}
	var answers []ProviderAnswer
	var merged strings.Builder
	for _, c := range classes {
		p, err := e.reg.Resolve(ctx, c)
		if err != nil {
			continue
		}
		comp, err := p.Invoke(ctx, provider.Prompt{System: "Answer the task.", User: prompt})
		if err != nil {
			continue
		}
		answers = append(answers, ProviderAnswer{
			Provider: p.Name(), Class: c, Answer: comp.Text,
			TokensIn: comp.TokensIn, TokensOut: comp.TokensOut,
		})
		fmt.Fprintf(&merged, "== %s (%s) ==\n%s\n\n", p.Name(), c, comp.Text)
	}
	if len(answers) == 0 {
		return "", nil, fmt.Errorf("synthesize: no provider produced an answer")
	}
	return strings.TrimSpace(merged.String()), answers, nil
}

// CallAgent mints a worker of role, runs it once on prompt in a local sandbox,
// retires it, and returns the result. The spawn is audited for attribution; the
// MCP layer authorizes the call_agent tool before this runs.
func (e *Engine) CallAgent(ctx context.Context, actor Identity, role Role, prompt string) (JobResult, error) {
	if !KnownRole(role) {
		return JobResult{}, fmt.Errorf("unknown role %q", role)
	}
	run := newRunID()
	e.gov.Guard(GovernedAction{
		Actor: actor, Kind: KindSpawn, Target: "call_agent",
		Labels: []string{LabelDelegateSpawn}, RunID: string(run), Provider: string(role),
	}, nil)
	id, err := e.minter.Mint(string(run), role, 0)
	if err != nil {
		return JobResult{}, err
	}
	defer e.minter.Retire(id)

	route := e.table.Route(CatUnspecifiedHigh)
	w := &roleWorker{id: id, role: role, class: route.ModelClass, reg: e.reg, sb: sandbox.NewLocal("."), jobID: string(run)}
	return w.Run(ctx, Task{ID: "t1", RunID: run, Title: prompt, Status: TaskOpen})
}

// Roles lists the canonical role registry (for the call_agent tool's schema/docs).
func (e *Engine) RoleNames() []string {
	specs := Roles()
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		out = append(out, string(s.Role))
	}
	return out
}
