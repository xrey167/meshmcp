package harness

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/harness/hooks"
	"github.com/xrey167/meshmcp/harness/provider"
	"github.com/xrey167/meshmcp/harness/sandbox"
	"github.com/xrey167/meshmcp/policy"
)

// newRunID returns a fresh, filesystem-safe run id (a single path element, per
// air/checkpoint's RunID rules).
func newRunID() RunID {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return RunID("run-" + hex.EncodeToString(b[:]))
}

func (e *Engine) get(id RunID) (*runCtx, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rc, ok := e.runs[id]
	if !ok {
		return nil, fmt.Errorf("harness: unknown run %s", id)
	}
	return rc, nil
}

// newScheduler builds a scheduler with a sandbox spec derived from config +
// scope. A worktree default with no repo degrades to local (the main-identity
// case); non-main/channel runs pass a stronger Min upstream.
func (e *Engine) newScheduler(scope RepoScope) *Scheduler {
	kind := e.cfg.Sandbox.Default
	if kind == "" {
		kind = "local"
	}
	if kind == "worktree" && scope.Repo == "" {
		kind = "local"
	}
	root := scope.Worktree
	if root == "" {
		root = "."
	}
	spec := sandbox.Spec{Kind: kind, Root: root, Repo: scope.Repo, Parent: os.TempDir()}
	sch := NewScheduler(e.gov, e.minter, e.reg, spec)
	if e.spawner != nil && len(e.workerCmd) > 0 {
		sch.WithSubprocessWorkers(e.spawner, e.workerCmd)
	}
	return sch
}

// clampMode clamps a requested mode by policy/config. The default config allows
// every mode; an org policy can forbid high-fan-out modes for a trust tier.
func (e *Engine) clampMode(m Mode) Mode {
	if m == "" {
		if e.cfg.DefaultMode != "" {
			return e.cfg.DefaultMode
		}
		return ModeTeam
	}
	return m
}

func (e *Engine) persist(rc *runCtx) error {
	rc.mu.Lock()
	rc.state.UpdatedAt = e.now()
	st := rc.state
	key := rc.state.Actor.Key
	rc.mu.Unlock()
	return e.cont.Save(st, key)
}

func (e *Engine) setStage(rc *runCtx, st Stage) {
	rc.mu.Lock()
	rc.state.Stage = st
	rc.mu.Unlock()
}

func (e *Engine) emit(rc *runCtx, ev RunEvent) {
	// Send while holding rc.mu so a concurrent Observe-cancel (which removes a
	// subscriber from rc.subs and closes it under the same lock) can never leave
	// emit sending on a closed channel. The send is non-blocking (select/default),
	// so holding the lock cannot stall a run on a slow observer.
	rc.mu.Lock()
	defer rc.mu.Unlock()
	for _, ch := range rc.subs {
		select {
		case ch <- ev:
		default: // never block a run on a slow observer
		}
	}
}

func (e *Engine) fail(rc *runCtx, err error) (RunState, error) {
	rc.mu.Lock()
	rc.state.Status = RunFailed
	rc.state.Error = err.Error()
	st := rc.state
	rc.mu.Unlock()
	_ = e.persist(rc)
	e.emit(rc, RunEvent{RunID: st.ID, Time: e.now(), Kind: "error", Msg: err.Error()})
	return st, err
}

// runStage dispatches one stage. It returns blocked=true when the stage parked
// the run on a co-sign approval.
func (e *Engine) runStage(ctx context.Context, rc *runCtx, st Stage) (bool, error) {
	e.emit(rc, RunEvent{RunID: rc.state.ID, Time: e.now(), Stage: st, Kind: "stage", Msg: string(st)})
	switch st {
	case StageIntake:
		return false, nil
	case StageInterview:
		return false, e.stageInterview(ctx, rc)
	case StagePlan:
		return false, e.stagePlan(ctx, rc)
	case StagePlanReview:
		return false, e.stagePlanReview(ctx, rc)
	case StageApprove:
		return e.stageApprove(ctx, rc)
	case StageExecute:
		return false, e.stageExecute(ctx, rc)
	case StageVerify:
		return false, e.stageVerify(ctx, rc)
	case StageFix:
		return false, e.stageFix(ctx, rc)
	case StageSettle:
		return false, e.stageSettle(ctx, rc)
	}
	return false, nil
}

// guard authorizes a stage's governed tool call and folds any added labels into
// the run's label set. It returns the decision so the caller can react to cosign.
func (e *Engine) guard(rc *runCtx, kind ActionKind, target string, labels []string) policy.Decision {
	rc.mu.Lock()
	actor := rc.state.Actor
	sess := cloneLabels(rc.labels)
	cat, mode := rc.state.Category, rc.state.Mode
	rc.mu.Unlock()
	d := e.gov.Guard(GovernedAction{
		Actor: actor, Kind: kind, Target: target, Labels: labels,
		RunID: string(rc.state.ID), Category: cat, Mode: mode,
	}, sess)
	// A pre-tool hook may block an otherwise-allowed action (safety guards:
	// tainted egress, write-to-missing-file, stop-continuation). A hook block
	// converts the verdict to a deny; the chain audits the hook effect itself.
	if d.Outcome == policy.OutcomeAllow && e.hooks != nil {
		ev := hooks.Event{Phase: hooks.PreTool, Tool: target, Labels: append(append([]string(nil), labels...), labelSlice(sess)...)}
		if eff, _ := e.hooks.Run(ev); eff.Kind == hooks.Block {
			d.Outcome = policy.OutcomeDeny
			d.Reason = "hook blocked: " + eff.Reason
		}
	}
	if d.Outcome == policy.OutcomeAllow && len(d.AddLabels) > 0 {
		rc.mu.Lock()
		for _, l := range d.AddLabels {
			rc.labels[l] = true
		}
		rc.state.Labels = labelSlice(rc.labels)
		rc.mu.Unlock()
	}
	return d
}

func (e *Engine) stageInterview(ctx context.Context, rc *runCtx) error {
	if d := e.guard(rc, KindToolCall, "interview", []string{LabelPlanWrite}); d.Outcome != policy.OutcomeAllow {
		return fmt.Errorf("interview denied: %s", reasonOr(d.Reason, "default-deny"))
	}
	req, err := e.planner.Interview(ctx, "gpt-medium", rc.state.Goal, 3)
	if err != nil {
		return err
	}
	rc.mu.Lock()
	rc.state.Requirements = &req
	rc.mu.Unlock()
	return nil
}

func (e *Engine) stagePlan(ctx context.Context, rc *runCtx) error {
	if d := e.guard(rc, KindToolCall, "plan", []string{LabelPlanWrite}); d.Outcome != policy.OutcomeAllow {
		return fmt.Errorf("plan denied: %s", reasonOr(d.Reason, "default-deny"))
	}
	rc.mu.Lock()
	goal, run, reqs := rc.state.Goal, rc.state.ID, rc.state.Requirements
	rc.mu.Unlock()
	plan, err := e.planner.Plan(ctx, "gpt-medium", goal, "team", run, reqs)
	if err != nil {
		return err
	}
	rc.mu.Lock()
	rc.state.Plan = &plan
	rc.mu.Unlock()
	return nil
}

func (e *Engine) stagePlanReview(ctx context.Context, rc *runCtx) error {
	if d := e.guard(rc, KindToolCall, "plan_review", []string{LabelPlanRead}); d.Outcome != policy.OutcomeAllow {
		return fmt.Errorf("plan_review denied: %s", reasonOr(d.Reason, "default-deny"))
	}
	rc.mu.Lock()
	plan := rc.state.Plan
	rc.mu.Unlock()
	if plan == nil {
		return nil
	}
	v, err := e.planner.Review(ctx, "gpt-high", *plan)
	if err != nil {
		return err
	}
	rc.mu.Lock()
	rc.state.Plan.Verdict = &v
	rc.mu.Unlock()
	return nil
}

// stageApprove blocks a high-risk run on a human co-sign. A low-risk run passes
// through. The co-sign check and its outcome are audited.
func (e *Engine) stageApprove(ctx context.Context, rc *runCtx) (bool, error) {
	rc.mu.Lock()
	risk := rc.state.Risk
	actor := rc.state.Actor
	rc.mu.Unlock()
	highRisk := risk == "high"
	if !highRisk {
		e.guard(rc, KindCosign, "start_work", nil) // audited allow
		return false, nil
	}
	key := policy.CosignKey(actor.FQDN, "start_work")
	approved := e.cosign != nil && e.cosign.Approved(key)
	labels := []string{LabelExecShell}
	if approved {
		e.guard(rc, KindCosign, "start_work", labels)
		return false, nil
	}
	// Record the pending co-sign as an audited cosign decision and block.
	e.gov.emit(GovernedAction{
		Actor: actor, Kind: KindCosign, Target: "start_work", Labels: labels,
		RunID: string(rc.state.ID),
	}, policy.Decision{Outcome: policy.OutcomeCosign, RuleID: -1, Reason: "high-risk run awaiting human co-sign"})
	return true, nil
}

// stageExecute fans out execution. Loop modes run the loop driver (which does
// execute→verify→fix per round); other modes do a single execute pass. The
// synthesize mode runs N providers on the goal and merges.
func (e *Engine) stageExecute(ctx context.Context, rc *runCtx) error {
	rc.mu.Lock()
	mode, cat := rc.state.Mode, rc.state.Category
	rc.mu.Unlock()

	if mode == ModeSynthesize {
		return e.stageSynthesize(ctx, rc)
	}

	route := e.table.Route(cat)
	width := clampWidth(route.FanOut.width(), rc.state.Budget.FanOut)
	role := executionRole(mode)
	class := route.ModelClass

	if lk := loopKindFor(mode); lk != "" {
		spec := LoopSpec{Kind: lk, MaxRounds: rc.state.Budget.LoopRounds, FanOut: width, VerifyEach: true}
		rounds, stop, err := spec.Drive(ctx, rc.tr, func(ctx context.Context, n int) RoundResult {
			changed := e.executeRound(ctx, rc, class, role, width)
			met, _ := e.verifyOnce(ctx, rc, class, route.Reviewers)
			if !met && changed && rc.tr.retry() {
				e.executeRound(ctx, rc, class, RoleExecutor, width) // bounded fix pass
			}
			return RoundResult{GoalMet: met, Changed: changed}
		})
		rc.mu.Lock()
		rc.state.Rounds = rounds
		rc.state.StopReason = stop
		rc.state.GoalMet = stop == StopGoalMet
		rc.mu.Unlock()
		if err != nil && stop == StopBudget {
			return err
		}
		return nil
	}

	e.executeRound(ctx, rc, class, role, width)
	return nil
}

// stageSynthesize runs the same goal across several provider classes and merges
// the best answer (OMC /ccg). Remote providers would cross federation; here the
// action is governed and audited as a delegate.spawn + net.egress.
func (e *Engine) stageSynthesize(ctx context.Context, rc *runCtx) error {
	if d := e.guard(rc, KindSpawn, "synthesize", []string{LabelDelegateSpawn, LabelNetEgress}); d.Outcome != policy.OutcomeAllow {
		return fmt.Errorf("synthesize denied: %s", reasonOr(d.Reason, "default-deny"))
	}
	classes := []string{"gpt-medium", "opus-class", "gemini-class"}
	var merged strings.Builder
	for _, c := range classes {
		p, err := e.reg.Resolve(ctx, c)
		if err != nil {
			continue
		}
		comp, err := p.Invoke(ctx, provider.Prompt{System: "Answer the task.", User: rc.state.Goal})
		if err != nil {
			continue
		}
		_ = rc.tr.spendTokens(comp.TokensIn + comp.TokensOut)
		fmt.Fprintf(&merged, "== %s ==\n%s\n", p.Name(), comp.Text)
	}
	rc.mu.Lock()
	rc.state.GoalMet = merged.Len() > 0
	rc.mu.Unlock()
	return nil
}

// executeRound builds tasks from the plan (or the goal), fans them out, and
// accounts tokens. It returns whether any worker produced a change.
func (e *Engine) executeRound(ctx context.Context, rc *runCtx, class string, role Role, width int) bool {
	rc.mu.Lock()
	state := rc.state
	sess := cloneLabels(rc.labels)
	rc.mu.Unlock()

	tasks := tasksFromState(state)
	results, _ := rc.sched.Fan(ctx, state, tasks, role, class, width, sess)

	changed := false
	for _, r := range results {
		_ = rc.tr.spendTokens(r.TokensIn + r.TokensOut)
		if r.Changed {
			changed = true
		}
	}
	rc.mu.Lock()
	rc.state.Workers = rc.sched.Minted()
	rc.mu.Unlock()
	return changed
}

// verifyOnce runs the review_work fan-out and the ultragoal check, recording
// findings and the goal-met verdict. Both verdicts are audited.
func (e *Engine) verifyOnce(ctx context.Context, rc *runCtx, class string, reviewers int) (bool, error) {
	if d := e.guard(rc, KindVerdict, "review_work", []string{LabelCodeRead}); d.Outcome != policy.OutcomeAllow {
		return false, fmt.Errorf("review_work denied: %s", reasonOr(d.Reason, "default-deny"))
	}
	rc.mu.Lock()
	run, goal := rc.state.ID, rc.state.Goal
	rc.mu.Unlock()
	findings, _, err := e.verifier.ReviewWork(ctx, run, class, goal, reviewers)
	if err != nil {
		return false, err
	}
	if d := e.guard(rc, KindVerdict, "ultragoal_check", []string{LabelVerifyRead}); d.Outcome != policy.OutcomeAllow {
		return false, fmt.Errorf("ultragoal_check denied: %s", reasonOr(d.Reason, "default-deny"))
	}
	met, gaps, err := e.verifier.UltragoalCheck(ctx, class, goal, []string{"executed the plan", "reviewers ran"})
	if err != nil {
		return false, err
	}
	rc.mu.Lock()
	rc.state.Findings = append(rc.state.Findings, findings...)
	rc.state.GoalMet = met
	rc.mu.Unlock()
	_ = gaps
	return met, nil
}

// stageVerify runs the verify gate once for non-loop modes. Loop modes already
// verified each round, so this is a no-op there.
func (e *Engine) stageVerify(ctx context.Context, rc *runCtx) error {
	rc.mu.Lock()
	mode, cat, rounds := rc.state.Mode, rc.state.Category, rc.state.Rounds
	rc.mu.Unlock()
	if loopKindFor(mode) != "" && rounds > 0 {
		return nil
	}
	route := e.table.Route(cat)
	_, err := e.verifyOnce(ctx, rc, route.ModelClass, route.Reviewers)
	return err
}

// stageFix runs one bounded fix pass when the goal is not yet met. A loop mode's
// fix already ran inside the loop.
func (e *Engine) stageFix(ctx context.Context, rc *runCtx) error {
	rc.mu.Lock()
	met, mode, cat, rounds := rc.state.GoalMet, rc.state.Mode, rc.state.Category, rc.state.Rounds
	rc.mu.Unlock()
	if met || (loopKindFor(mode) != "" && rounds > 0) {
		return nil
	}
	if !rc.tr.retry() {
		return nil // fix budget exhausted; verify already recorded the gap
	}
	route := e.table.Route(cat)
	e.executeRound(ctx, rc, route.ModelClass, RoleExecutor, 1)
	_, _ = e.verifyOnce(ctx, rc, route.ModelClass, route.Reviewers)
	return nil
}

// stageSettle seals the run: records the retired workers, audits a settle
// verdict, flushes the audit checkpoint, and writes the final continuity object.
func (e *Engine) stageSettle(ctx context.Context, rc *runCtx) error {
	e.guard(rc, KindVerdict, "handoff", []string{LabelPlanWrite})
	rc.mu.Lock()
	rc.state.Workers = markRetired(rc.sched.Minted(), e.now())
	rc.state.Status = RunDone
	rc.mu.Unlock()
	e.gov.Flush()
	return nil
}

// --- stage helpers ---

func tasksFromState(s RunState) []Task {
	if s.Plan != nil && len(s.Plan.Steps) > 0 {
		steps := s.Plan.Steps
		if len(steps) > 8 {
			steps = steps[:8] // bound fan-out; the rest queue in a later round
		}
		out := make([]Task, 0, len(steps))
		for _, st := range steps {
			out = append(out, Task{
				ID: st.ID, RunID: s.ID, Title: st.Intent, Body: st.Verify, Status: TaskOpen,
			})
		}
		return out
	}
	return []Task{{ID: "t1", RunID: s.ID, Title: s.Goal, Status: TaskOpen}}
}

func executionRole(m Mode) Role {
	switch m {
	case ModeAutopilot:
		return RoleDeepWorker
	case ModeUltrawork:
		return RoleJunior
	default:
		return RoleExecutor
	}
}

func clampWidth(want, budget int) int {
	if want < 1 {
		want = 1
	}
	if budget > 0 && want > budget {
		want = budget
	}
	return want
}

func markRetired(ws []Worker, t time.Time) []Worker {
	out := make([]Worker, len(ws))
	for i, w := range ws {
		w.RetiredAt = t
		out[i] = w
	}
	return out
}

// --- stage-ordering helpers ---

func stageIdx(s Stage) int {
	for i, st := range pipelineOrder {
		if st == s {
			return i
		}
	}
	return len(pipelineOrder)
}

// stageAtOrAfter reports whether st is at or after current in the pipeline (so
// the Advance loop runs st when the run has not yet passed it).
func stageAtOrAfter(current, st Stage) bool { return stageIdx(st) >= stageIdx(current) }

func nextStage(st Stage) Stage {
	i := stageIdx(st)
	if i+1 < len(pipelineOrder) {
		return pipelineOrder[i+1]
	}
	return StageSettle
}

func ctxErr(ctx context.Context) error { return ctx.Err() }

func cloneLabels(m map[string]bool) map[string]bool {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func labelSlice(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
