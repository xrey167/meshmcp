// Package egress is the caller-side governing gateway (spine primitive S7): the
// piece that instantiates a policy.Engine and an audit sink on an agent loop's
// OWN egress, so a run's taint lattice (Decision.AddLabels) and cost budget
// (Decision.Cost) become observable and enforceable CLIENT-SIDE — inside the
// loop — not only at the destination backends.
//
// Without S7 the taint-guard and cost-budget bounds a policy expresses are
// enforced only where a call lands; a runaway or prompt-injected agent could
// still spend without limit and let taint from an earlier call escape the
// decision for a later one. A Gateway closes that gap: it threads ONE run-scoped
// session through every governed tool call, judging each call in the context of
// what the run has already touched (accumulated taint) and halting the loop the
// moment its cumulative cost would breach the budget. That is what makes a
// bounded, governed agent loop real.
//
// A Gateway is per-run and safe for concurrent use: a graph that fans out nodes
// concurrently shares one Gateway, and its mutable state (the taint set and the
// spend counter) is mutex-guarded so calls cannot corrupt the taint set or
// double-spend past the cap. The gateway itself performs no network I/O — the
// tool is run by a caller-supplied execute callback — so it stays pure but for
// its own state and the injected engine and audit sink.
package egress

import (
	"fmt"
	"sync"

	"github.com/xrey167/meshmcp/air/know"
	"github.com/xrey167/meshmcp/policy"
)

// Caller is the acting identity behind a governed call: the WireGuard FQDN the
// run authenticates as and (optionally) its public key. It is passed to the
// policy engine for peer matching and recorded on every audit record so no
// governed egress is unattributable.
type Caller struct {
	PeerFQDN string
	PeerKey  string
}

// Gateway makes one governed, audited, taint- and budget-tracked tool call at a
// time against a shared policy.Engine, holding the run-scoped mutable state that
// makes governance observable in the loop: the accumulated taint label set, the
// cumulative spend, and the budget cap those are enforced against.
//
// Construct one per agent run with NewGateway; share the instance across the
// run's nodes (it is concurrency-safe). The taint set only grows (taint
// propagation is monotonic) and spend only counts governed calls that actually
// executed, so a denied, halted, or failed call leaves both untouched.
type Gateway struct {
	engine *policy.Engine
	sink   policy.AuditSink
	budget int // cumulative-cost ceiling for the run

	mu     sync.Mutex
	labels map[string]bool // accumulated taint/data-flow labels (monotonic)
	spent  int             // cumulative cost of executed governed calls
}

// NewGateway returns a per-run gateway that decides against engine, records
// every governed call to sink (nil disables auditing), and halts the run when
// its cumulative cost would exceed budget. budget is the ceiling on total
// Decision.Cost across the run; a call whose cost would push spend past it is
// denied rather than executed. A non-positive budget therefore admits only
// cost-free (untracked) calls — pass a large value for an effectively unbounded
// run.
func NewGateway(engine *policy.Engine, sink policy.AuditSink, budget int) *Gateway {
	return &Gateway{
		engine: engine,
		sink:   sink,
		budget: budget,
		labels: map[string]bool{},
	}
}

// Call makes one governed tool call. In order it: (1) decides the call with the
// engine against the run's CURRENT accumulated taint labels, so taint from
// earlier calls flows into this decision; (2) on a deny, audits and returns
// without executing; (3) on a cosign outcome, audits and returns the Decision
// so the caller can route to the human co-sign flow (it does NOT execute — a
// cosign is not-yet-allowed); (4) on an allow, budget-checks BEFORE executing
// and HALTS with a budget-exceeded deny if the call's cost would breach the cap;
// (5) otherwise runs execute, then accumulates Decision.AddLabels into the run
// taint set and adds Decision.Cost to spend.
//
// The returned Decision is always the governing verdict. On deny (including a
// budget halt) the error is non-nil and result is nil. On cosign the error is
// nil (routing to a human is not a failure) and result is nil. On allow the
// error is execute's error (spend and taint are left unchanged if execute
// fails) or nil with the tool's result. Audit-sink write errors are surfaced
// via the returned error without changing the governance outcome.
func (g *Gateway) Call(caller Caller, backend, tool string, args []byte, execute func() ([]byte, error)) (policy.Decision, []byte, error) {
	g.mu.Lock()

	// Decide against a snapshot of the run's accumulated taint — the internal
	// map is never handed to the engine, which only reads the labels.
	dec := g.engine.DecideToolCallBound(caller.PeerFQDN, caller.PeerKey, backend, tool, args, g.copyLabelsLocked())

	switch dec.Outcome {
	case policy.OutcomeDeny:
		g.mu.Unlock()
		auditErr := g.audit(caller, tool, "deny", dec.Reason, 0)
		return dec, nil, joinErr(fmt.Errorf("egress: call to %q denied: %s", tool, dec.Reason), auditErr)

	case policy.OutcomeCosign:
		g.mu.Unlock()
		// Not-yet-allowed: surface the Decision so the caller parks it for a
		// human co-sign (air passkey/approvals). We do not execute and it is
		// not an error.
		auditErr := g.audit(caller, tool, "cosign", dec.Reason, 0)
		return dec, nil, auditErr
	}

	// Allow. Budget pre-check: halt the loop before executing if this call's
	// cost would push cumulative spend past the cap. This is the cost bound
	// against a runaway agent.
	if g.spent+dec.Cost > g.budget {
		reason := fmt.Sprintf("budget exceeded: call cost %d + spent %d exceeds cap %d", dec.Cost, g.spent, g.budget)
		g.mu.Unlock()
		halt := policy.Decision{RuleID: dec.RuleID, Outcome: policy.OutcomeDeny, Reason: reason, Cost: dec.Cost}
		auditErr := g.audit(caller, tool, "deny", reason, 0)
		return halt, nil, joinErr(fmt.Errorf("egress: %s", reason), auditErr)
	}

	// Reserve the cost under the lock so a concurrent fan-out cannot both pass
	// the budget check and double-spend past the cap. Refunded if execute fails.
	g.spent += dec.Cost
	g.mu.Unlock()

	result, err := execute()
	if err != nil {
		// The governed tool failed: refund the reserved cost and add no taint,
		// so a failed call is as if it never spent or touched anything.
		g.mu.Lock()
		g.spent -= dec.Cost
		g.mu.Unlock()
		return dec, nil, fmt.Errorf("egress: execute %q: %w", tool, err)
	}

	// Success: propagate taint monotonically into the run's label set.
	g.mu.Lock()
	for _, l := range dec.AddLabels {
		g.labels[l] = true
	}
	g.mu.Unlock()

	auditErr := g.audit(caller, tool, "allow", dec.Reason, dec.Cost)
	return dec, result, auditErr
}

// Release executes a call the engine held as OutcomeCosign after the caller
// consumed a signed, single-use, argument-bound human approval for it. Policy
// is NOT re-decided — dec must be this gateway's own fresh cosign verdict for
// the exact call, and the consumed approval is the authorization — but the
// run's bounds still hold exactly as for an allowed call: the matched rule's
// effects (emit-labels + cost) are recovered from the engine
// (policy.Engine.RuleEffects), the cost is budget-checked BEFORE executing (a
// breach halts the call unexecuted, audited as a deny), spend is reserved and
// refunded if execute fails, and on success the labels merge monotonically
// into the run taint set and an allow record lands on the chain. Without this,
// a human-released call would be the one governed call whose taint and cost
// escape the loop's lattice and budget — a rule that is both require_cosign
// and taint_source would let its release bypass every downstream taint guard.
//
// The returned Decision is the release verdict: on success an OutcomeAllow
// carrying the folded AddLabels+Cost (so a runner mirrors the same truth into
// its state), on a budget breach an OutcomeDeny halt. Fail-closed guards: a
// non-cosign dec, or a dec whose RuleID no longer names a rule in the active
// policy (effects unknowable), refuses without executing.
func (g *Gateway) Release(caller Caller, tool string, dec policy.Decision, execute func() ([]byte, error)) (policy.Decision, []byte, error) {
	if dec.Outcome != policy.OutcomeCosign {
		return dec, nil, fmt.Errorf("egress: release %q: decision is %s, not cosign — refusing to execute", tool, dec.Outcome)
	}
	labels, cost, ok := g.engine.RuleEffects(dec.RuleID)
	if !ok {
		return dec, nil, fmt.Errorf("egress: release %q: rule %d is not in the active policy; cannot determine the call's taint/cost effects — refusing to execute", tool, dec.RuleID)
	}
	rel := policy.Decision{Allow: true, RuleID: dec.RuleID, Outcome: policy.OutcomeAllow,
		Reason: "human co-sign released", AddLabels: labels, Cost: cost}

	// Budget pre-check + reservation under the lock, exactly as Call's allow
	// path: a released call is still bounded by the run cap.
	g.mu.Lock()
	if g.spent+cost > g.budget {
		reason := fmt.Sprintf("budget exceeded: released call cost %d + spent %d exceeds cap %d", cost, g.spent, g.budget)
		g.mu.Unlock()
		halt := policy.Decision{RuleID: dec.RuleID, Outcome: policy.OutcomeDeny, Reason: reason, Cost: cost}
		auditErr := g.audit(caller, tool, "deny", reason, 0)
		return halt, nil, joinErr(fmt.Errorf("egress: %s", reason), auditErr)
	}
	g.spent += cost
	g.mu.Unlock()

	result, err := execute()
	if err != nil {
		// Refund and add no taint: a failed release neither spent nor touched.
		g.mu.Lock()
		g.spent -= cost
		g.mu.Unlock()
		return rel, nil, fmt.Errorf("egress: execute released %q: %w", tool, err)
	}

	g.mu.Lock()
	for _, l := range labels {
		g.labels[l] = true
	}
	g.mu.Unlock()

	auditErr := g.audit(caller, tool, "allow", rel.Reason, cost)
	return rel, result, auditErr
}

// Taint merges labels into the run's accumulated taint set, exactly as a
// successful governed call's Decision.AddLabels would. It exists for the one
// place taint legitimately enters OUTSIDE Call: the graph runner re-seeding a
// fresh per-run gateway from a checkpoint's persisted labels on resume (so the
// monotonic lattice holds ACROSS process restarts, not only within one). A
// human-released cosign call taints through Release, not here. Monotonic by
// construction — labels are only ever added, never cleared.
func (g *Gateway) Taint(labels ...string) {
	if len(labels) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, l := range labels {
		if l != "" {
			g.labels[l] = true
		}
	}
}

// Labels returns a copy of the run's accumulated taint/data-flow label set. The
// internal map is never exposed, so callers cannot mutate the taint state.
func (g *Gateway) Labels() map[string]bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.copyLabelsLocked()
}

// Spent returns the cumulative cost of the run's executed governed calls.
func (g *Gateway) Spent() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.spent
}

// Budget returns the run's cumulative-cost ceiling.
func (g *Gateway) Budget() int { return g.budget }

// Remaining returns the cost budget still available (budget - spent). It can go
// no lower than the last admitted call left it; a halted call never spends.
func (g *Gateway) Remaining() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.budget - g.spent
}

// copyLabelsLocked returns a fresh copy of the label set. Caller holds g.mu.
func (g *Gateway) copyLabelsLocked() map[string]bool {
	out := make(map[string]bool, len(g.labels))
	for l := range g.labels {
		out[l] = true
	}
	return out
}

// audit records one governed call as a graph.node-enter event on the shared
// tamper-evident ledger. A nil sink disables auditing. The chain fields are
// filled by the sink, so the record slots straight into policy.VerifyChain.
func (g *Gateway) audit(caller Caller, tool, decision, reason string, cost int) error {
	if g.sink == nil {
		return nil
	}
	rec := know.NodeEnter(know.Event{
		Peer:     caller.PeerFQDN,
		PeerKey:  caller.PeerKey,
		Corpus:   tool,
		Decision: decision,
		Reason:   reason,
		Cost:     cost,
	})
	if err := g.sink.Append(rec); err != nil {
		return fmt.Errorf("egress: audit %s %q: %w", decision, tool, err)
	}
	return nil
}

// joinErr returns primary, or primary with audit context when both are set. The
// governance outcome (primary) always leads; an audit failure never masks it.
func joinErr(primary, audit error) error {
	if audit == nil {
		return primary
	}
	if primary == nil {
		return audit
	}
	return fmt.Errorf("%w (also: %v)", primary, audit)
}
