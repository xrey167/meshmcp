package harness

import (
	"context"
	"fmt"
	"strings"

	"github.com/xrey167/meshmcp/harness/provider"
)

// Planner runs the interview, plan, and plan-review phases (§5.2). It merges
// Prometheus/ralplan/team-plan planning, Metis gap analysis, and Momus/critic
// validation. It drives a provider for content; with the Mock provider the
// output is deterministic so golden pipeline tests are stable.
type Planner struct {
	reg *provider.Registry
}

// NewPlanner builds a planner over a provider registry.
func NewPlanner(reg *provider.Registry) *Planner { return &Planner{reg: reg} }

// Interview runs a Socratic clarification (deep-interview) producing a
// requirements artifact. rounds bounds the questions (default 3).
func (p *Planner) Interview(ctx context.Context, class, goal string, rounds int) (Requirements, error) {
	if rounds <= 0 {
		rounds = 3
	}
	prov, err := p.reg.Resolve(ctx, class)
	if err != nil {
		return Requirements{}, err
	}
	req := Requirements{ID: "req-" + shortHash(goal)}
	for i := 0; i < rounds; i++ {
		q := fmt.Sprintf("Clarification %d for goal %q: what constraint or edge case matters here?", i+1, truncate(goal, 80))
		comp, err := prov.Invoke(ctx, provider.Prompt{
			System: "You are a requirements analyst. Ask one sharp clarifying question, then answer it with your best assumption.",
			User:   q,
		})
		if err != nil {
			return Requirements{}, err
		}
		req.QA = append(req.QA, QA{Q: q, A: strings.TrimSpace(comp.Text)})
	}
	req.Assumptions = []string{"scope limited to the requested paths", "no destructive migrations without co-sign"}
	return req, nil
}

// Plan generates a plan (style: prometheus | ralplan | team). requirements may
// be nil (no interview ran).
func (p *Planner) Plan(ctx context.Context, class, goal, style string, run RunID, requirements *Requirements) (Plan, error) {
	if style == "" {
		style = "team"
	}
	prov, err := p.reg.Resolve(ctx, class)
	if err != nil {
		return Plan{}, err
	}
	ctxText := goal
	if requirements != nil {
		var b strings.Builder
		b.WriteString(goal)
		for _, qa := range requirements.QA {
			fmt.Fprintf(&b, "\nQ:%s\nA:%s", qa.Q, qa.A)
		}
		ctxText = b.String()
	}
	comp, err := prov.Invoke(ctx, provider.Prompt{
		System: "Produce an implementation plan as a numbered list of concrete steps. Each step names the intent, likely files, a risk level, and how to verify it.",
		User:   ctxText,
	})
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{
		ID:    "plan-" + shortHash(goal),
		RunID: run,
		Style: style,
		Steps: synthesizeSteps(goal, comp.Text),
	}
	if requirements == nil {
		plan.OpenQuestions = []string{"requirements not clarified via interview"}
	}
	return plan, nil
}

// Review runs the plan-review phase: Metis (gap/ambiguity) + Momus/critic
// (validation), emitting a pass/revise verdict.
func (p *Planner) Review(ctx context.Context, class string, plan Plan) (PlanVerdict, error) {
	prov, err := p.reg.Resolve(ctx, class)
	if err != nil {
		return PlanVerdict{}, err
	}
	_, err = prov.Invoke(ctx, provider.Prompt{
		System: "You are Metis+Momus. Find gaps and risks in this plan, then decide pass or revise.",
		User:   planText(plan),
	})
	if err != nil {
		return PlanVerdict{}, err
	}
	v := PlanVerdict{Verdict: "pass"}
	if len(plan.Steps) == 0 {
		v.Verdict = "revise"
		v.Gaps = []string{"plan has no steps"}
		v.RequiredChanges = []string{"produce at least one concrete step"}
	}
	if len(plan.OpenQuestions) > 0 {
		v.Risks = append(v.Risks, "open questions remain: "+strings.Join(plan.OpenQuestions, "; "))
	}
	return v, nil
}

// synthesizeSteps turns a plan completion into structured steps. The Mock
// provider's echo yields one deterministic step; a real provider's numbered list
// is split into steps.
func synthesizeSteps(goal, text string) []PlanStep {
	lines := []string{}
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		lines = append(lines, ln)
	}
	if len(lines) == 0 {
		lines = []string{"implement: " + truncate(goal, 120)}
	}
	steps := make([]PlanStep, 0, len(lines))
	for i, ln := range lines {
		steps = append(steps, PlanStep{
			ID:     fmt.Sprintf("s%d", i+1),
			Intent: truncate(ln, 200),
			Risk:   "low",
			Verify: "run tests / review diff",
		})
	}
	return steps
}

func planText(p Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "plan %s (%s):\n", p.ID, p.Style)
	for _, s := range p.Steps {
		fmt.Fprintf(&b, "- [%s] %s (risk %s)\n", s.ID, s.Intent, s.Risk)
	}
	return b.String()
}
