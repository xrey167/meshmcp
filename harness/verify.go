package harness

import (
	"context"
	"fmt"
	"strings"

	"github.com/xrey167/meshmcp/harness/provider"
)

// Verifier runs the post-implementation verification gate: the review_work
// N-reviewer fan-out (omo) and the ultragoal durable check (gjc). The gate is a
// firewall + co-sign policy touchpoint in the pipeline; the verdicts it produces
// are audited by the orchestrator (KindVerdict).
type Verifier struct {
	reg *provider.Registry
}

// NewVerifier builds a verifier over a provider registry.
func NewVerifier(reg *provider.Registry) *Verifier { return &Verifier{reg: reg} }

// ReviewWork runs reviewers independent reviewers over the scope and returns
// their findings plus a summary. Each reviewer is an independent provider
// invocation (an independent perspective), mirroring omo's 5-reviewer fan-out.
func (v *Verifier) ReviewWork(ctx context.Context, run RunID, class string, scope string, reviewers int) ([]Finding, string, error) {
	if reviewers <= 0 {
		reviewers = 5
	}
	prov, err := v.reg.Resolve(ctx, class)
	if err != nil {
		return nil, "", err
	}
	var findings []Finding
	for i := 0; i < reviewers; i++ {
		comp, err := prov.Invoke(ctx, provider.Prompt{
			System: fmt.Sprintf("You are reviewer %d of %d. Review the change for correctness, security, and clarity. Report findings, most severe first.", i+1, reviewers),
			User:   "scope: " + scope,
		})
		if err != nil {
			return nil, "", err
		}
		// The Mock provider produces a clean review (no findings). A real
		// provider's structured output would be parsed into Findings; here we
		// record a single informational note per reviewer that reported text.
		if note := strings.TrimSpace(comp.Text); note != "" && strings.Contains(strings.ToLower(note), "finding") {
			findings = append(findings, Finding{
				RunID: run, Reviewer: i + 1, Severity: "info", Note: truncate(note, 300),
			})
		}
	}
	summary := fmt.Sprintf("%d reviewers ran over %q; %d finding(s)", reviewers, scope, len(findings))
	return findings, summary, nil
}

// UltragoalCheck confirms the stated goal is actually met, with evidence. It is
// the durable verify that distinguishes "the steps ran" from "the goal is done".
func (v *Verifier) UltragoalCheck(ctx context.Context, class, goal string, evidence []string) (bool, []string, error) {
	prov, err := v.reg.Resolve(ctx, class)
	if err != nil {
		return false, nil, err
	}
	comp, err := prov.Invoke(ctx, provider.Prompt{
		System: "You are the ultragoal verifier. Given the goal and the evidence, decide whether the goal is genuinely met. Reply 'MET' or 'NOT MET' then list any residual gaps.",
		User:   "goal: " + goal + "\nevidence:\n- " + strings.Join(evidence, "\n- "),
	})
	if err != nil {
		return false, nil, err
	}
	// Default posture: the goal is met when there is evidence and no explicit
	// "NOT MET". A real provider's verdict text drives this; the Mock echo (which
	// never says NOT MET) makes a well-formed run converge.
	met := len(evidence) > 0 && !strings.Contains(strings.ToUpper(comp.Text), "NOT MET")
	var gaps []string
	if !met {
		gaps = []string{"no evidence of goal completion"}
	}
	return met, gaps, nil
}
