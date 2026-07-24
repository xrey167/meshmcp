package harness

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/xrey167/meshmcp/harness/hooks"
	"github.com/xrey167/meshmcp/harness/provider"
	"github.com/xrey167/meshmcp/policy"
)

// Orchestrator owns a single run through the merged pipeline (§5.2).
type Orchestrator interface {
	Start(ctx context.Context, req RunRequest) (RunID, error)
	Advance(ctx context.Context, id RunID) (RunState, error) // drives the state machine
	Cancel(ctx context.Context, id RunID, reason string) error
	Observe(id RunID) (<-chan RunEvent, func()) // for HUD/statusline
}

// Engine is the concrete Orchestrator. It wires the governance choke point
// (Governor), the provider registry, continuity, the identity minter, and the
// per-phase helpers (IntentGate, Planner, Verifier). Every phase transition is a
// governed, audited action; run state is persisted to continuity after each
// stage so a crash/roam resumes without loss.
type Engine struct {
	gov       *Governor
	cosign    policy.CosignStore
	cont      Continuity
	minter    Minter
	reg       *provider.Registry
	gate      *IntentGate
	planner   *Planner
	verifier  *Verifier
	table     CategoryTable
	cfg       Config
	hooks     *hooks.Chain // optional lifecycle hook chain (nil → no hooks)
	spawner   Spawner      // optional subprocess-worker spawner
	workerCmd []string     // subprocess worker argv (with spawner)
	now       func() time.Time

	mu   sync.Mutex
	runs map[RunID]*runCtx
}

// runCtx is the live per-run state the engine holds in memory (the durable copy
// is in continuity).
type runCtx struct {
	mu      sync.Mutex
	state   RunState
	tr      *tracker
	sched   *Scheduler
	labels  map[string]bool
	stopped bool
	subs    []chan RunEvent
	cancel  context.CancelFunc
}

// EngineOpts configures a new Engine.
type EngineOpts struct {
	Policy     *policy.Policy // compiled role policy (CompilePolicy); nil → default roles
	Cosign     policy.CosignStore
	Audit      *policy.AuditLog
	Registry   *provider.Registry
	Continuity Continuity
	Minter     Minter
	Config     Config
	Hooks      *hooks.Chain // optional lifecycle hook chain
	// Spawner + WorkerCommand opt into subprocess-worker execution: when both are
	// set, the scheduler runs each job as an external worker process (joining the
	// mesh as its minted identity) instead of an in-process provider worker.
	Spawner       Spawner
	WorkerCommand []string
	Now           func() time.Time
}

// NewEngine builds an orchestrator. Sensible defaults fill any nil field: the
// default role policy, an in-process continuity store and minter, a registry
// with a single Mock provider covering every model class, and the default config.
func NewEngine(o EngineOpts) *Engine {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	pol := o.Policy
	if pol == nil {
		pol = CompilePolicy(nil)
	}
	reg := o.Registry
	if reg == nil {
		reg = defaultMockRegistry()
	}
	cont := o.Continuity
	if cont == nil {
		cont = NewMemContinuity()
	}
	minter := o.Minter
	if minter == nil {
		minter = NewMemMinter()
	}
	cfg := o.Config
	if cfg.DefaultMode == "" {
		cfg = DefaultConfig()
	}
	table := cfg.CategoryTable()
	gov := NewGovernor(pol, o.Cosign, o.Audit, now)
	return &Engine{
		gov:       gov,
		cosign:    o.Cosign,
		cont:      cont,
		minter:    minter,
		reg:       reg,
		gate:      NewIntentGate(reg, table),
		planner:   NewPlanner(reg),
		verifier:  NewVerifier(reg),
		table:     table,
		cfg:       cfg,
		hooks:     o.Hooks,
		spawner:   o.Spawner,
		workerCmd: o.WorkerCommand,
		now:       now,
		runs:      map[RunID]*runCtx{},
	}
}

// defaultMockRegistry registers one Mock per model class the routing table uses,
// so a headless run with no configured providers still executes deterministically.
func defaultMockRegistry() *provider.Registry {
	reg := provider.NewRegistry()
	classes := []string{"gemini-class", "gpt-high", "gpt-medium", "opus-class", "mini-class", "local-opus"}
	for _, c := range classes {
		reg.Register(provider.NewMock("mock-"+c, c))
	}
	return reg
}

// Governor exposes the governance choke point (for the MCP server to reuse).
func (e *Engine) Governor() *Governor { return e.gov }

// Start classifies the request, opens a run, and persists its initial state.
func (e *Engine) Start(ctx context.Context, req RunRequest) (RunID, error) {
	if req.Goal == "" {
		return "", fmt.Errorf("harness: empty goal")
	}
	id := newRunID()

	// The principal drives via a run-scoped orchestrator identity, so it matches
	// the compiled "orchestrator--*" policy and its actions are attributable to
	// its real key.
	actor := Identity{
		Key:  req.Actor.Key,
		FQDN: fmt.Sprintf("%s--%s--0", RoleOrchestrator, id),
		Role: RoleOrchestrator,
	}
	if actor.Key == "" {
		actor.Key = "principal-" + string(id) // deterministic local principal key
	}

	// IntentGate classification (audited route decision).
	in := e.gate.Classify(ctx, req.Goal, req.Category, req.Mode)
	if req.Mode != "" {
		in.Mode = req.Mode // an explicit mode request stands (still clamped below)
	}
	in.Mode = e.clampMode(in.Mode)

	budget := req.Budget
	if budget == (Budget{}) {
		budget = e.cfg.Budget()
	}

	now := e.now()
	state := RunState{
		ID:        id,
		Goal:      req.Goal,
		Mode:      in.Mode,
		Category:  in.Category,
		Risk:      in.Risk,
		Scope:     req.Scope,
		Actor:     actor,
		Budget:    budget,
		Status:    RunPending,
		Stage:     StageIntake,
		Labels:    in.Labels,
		CreatedAt: now,
		UpdatedAt: now,
	}

	rc := &runCtx{
		state:  state,
		tr:     newTracker(budget, e.now),
		labels: labelSet(in.Labels),
		sched:  e.newScheduler(req.Scope),
	}
	if rc.labels == nil {
		rc.labels = map[string]bool{}
	}

	e.mu.Lock()
	e.runs[id] = rc
	e.mu.Unlock()

	// Audit the routing decision.
	e.gov.Guard(GovernedAction{
		Actor: actor, Kind: KindRoute, Target: "route",
		Labels: []string{}, RunID: string(id), Category: in.Category, Mode: in.Mode,
	}, rc.labels)

	if err := e.cont.Save(state, actor.Key); err != nil {
		return "", fmt.Errorf("harness: persist run: %w", err)
	}
	e.emit(rc, RunEvent{RunID: id, Time: now, Stage: StageIntake, Kind: "start", Msg: fmt.Sprintf("category=%s mode=%s risk=%s", in.Category, in.Mode, in.Risk)})
	return id, nil
}

// Advance drives the run through its remaining stages to a terminal or blocked
// state, persisting after each stage. It is safe to call again on a blocked run
// (e.g. after a co-sign lands) — it resumes from the recorded stage.
func (e *Engine) Advance(ctx context.Context, id RunID) (RunState, error) {
	rc, err := e.get(id)
	if err != nil {
		return RunState{}, err
	}
	rc.mu.Lock()
	if rc.stopped {
		st := rc.state
		rc.mu.Unlock()
		return st, fmt.Errorf("harness: run %s was stopped (stop-continuation guard)", id)
	}
	rc.mu.Unlock()

	cctx, cancel := context.WithCancel(ctx)
	rc.mu.Lock()
	rc.cancel = cancel
	rc.state.Status = RunRunning
	rc.mu.Unlock()
	defer cancel()

	stages := stagesFor(rc.state.Mode)
	for _, st := range stages {
		if !stageAtOrAfter(rc.state.Stage, st) {
			continue // already past this stage (resume)
		}
		if err := ctxErr(cctx); err != nil {
			return e.fail(rc, err)
		}
		blocked, err := e.runStage(cctx, rc, st)
		if err != nil {
			return e.fail(rc, err)
		}
		if blocked {
			// Do NOT advance past a blocking stage: the stage cursor stays at st
			// so a resume RE-RUNS it and re-checks the co-sign. This is what makes
			// the gate un-bypassable — calling Advance again without an approval
			// re-enters approve and blocks again, rather than falling through to
			// execute.
			rc.mu.Lock()
			rc.state.Status = RunBlocked
			blockedState := rc.state
			rc.mu.Unlock()
			_ = e.persist(rc)
			e.emit(rc, RunEvent{RunID: id, Time: e.now(), Kind: "blocked", Msg: "awaiting co-sign approval"})
			return blockedState, nil
		}
		e.setStage(rc, nextStage(st))
		if err := e.persist(rc); err != nil {
			return e.fail(rc, err)
		}
	}
	rc.mu.Lock()
	rc.state.Status = RunDone
	final := rc.state
	rc.mu.Unlock()
	_ = e.persist(rc)
	return final, nil
}

// Run is a convenience: Start then Advance to completion.
func (e *Engine) Run(ctx context.Context, req RunRequest) (RunState, error) {
	id, err := e.Start(ctx, req)
	if err != nil {
		return RunState{}, err
	}
	return e.Advance(ctx, id)
}

// Cancel stops a run: it cancels the in-flight context and sets the
// stop-continuation guard so the run cannot silently resume. The stop is audited.
func (e *Engine) Cancel(ctx context.Context, id RunID, reason string) error {
	rc, err := e.get(id)
	if err != nil {
		return err
	}
	rc.mu.Lock()
	rc.stopped = true
	rc.state.Status = RunCancelled
	rc.state.StopReason = StopOperator
	if rc.cancel != nil {
		rc.cancel()
	}
	actor := rc.state.Actor
	labels := rc.labels
	rc.mu.Unlock()
	e.gov.Guard(GovernedAction{
		Actor: actor, Kind: KindLoopStop, Target: "stop-continuation",
		RunID: string(id), JobID: reason,
	}, labels)
	_ = e.persist(rc)
	e.emit(rc, RunEvent{RunID: id, Time: e.now(), Kind: "cancel", Msg: reason})
	return nil
}

// Observe returns a channel of run events and a cancel func to stop observing.
func (e *Engine) Observe(id RunID) (<-chan RunEvent, func()) {
	rc, err := e.get(id)
	if err != nil {
		ch := make(chan RunEvent)
		close(ch)
		return ch, func() {}
	}
	ch := make(chan RunEvent, 64)
	rc.mu.Lock()
	rc.subs = append(rc.subs, ch)
	rc.mu.Unlock()
	return ch, func() {
		rc.mu.Lock()
		defer rc.mu.Unlock()
		for i, c := range rc.subs {
			if c == ch {
				rc.subs = append(rc.subs[:i], rc.subs[i+1:]...)
				close(ch)
				break
			}
		}
	}
}

// State returns the current state of a run.
func (e *Engine) State(id RunID) (RunState, error) {
	rc, err := e.get(id)
	if err != nil {
		return RunState{}, err
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.state, nil
}
