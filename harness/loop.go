package harness

import "context"

// LoopKind selects a loop driver. One parameterized driver (LoopSpec.Drive)
// covers every source harness's loop: ralph, ultrawork, autopilot.
type LoopKind string

const (
	LoopRalph     LoopKind = "ralph"     // execute→verify→fix each round until goal met
	LoopUltrawork LoopKind = "ultrawork" // high fan-out aggressive exploration each round
	LoopAutopilot LoopKind = "autopilot" // no per-round operator pause; only co-sign pauses
)

// StopCond is why a loop terminated.
type StopCond string

const (
	StopGoalMet  StopCond = "goal-met"
	StopNoDiff   StopCond = "no-diff"
	StopBudget   StopCond = "budget-exhausted"
	StopOperator StopCond = "operator-stop"
	StopMaxRound StopCond = "max-rounds"
)

// LoopSpec parameterizes the loop driver.
type LoopSpec struct {
	Kind       LoopKind
	StopWhen   StopCond // primary stop condition; the driver also honors the others
	MaxRounds  int      // from Budget.LoopRounds (0 → tracker default)
	FanOut     int      // parallel workers per round
	VerifyEach bool     // run the verify gate each round
}

// RoundResult is one loop round's outcome.
type RoundResult struct {
	GoalMet bool // ultragoal_check passed
	Changed bool // the round produced a diff
	Err     error
}

// hardLoopCap is an absolute backstop on loop rounds. Termination is normally
// bounded by the budget's LoopRounds and/or wall-clock, but a partial budget can
// leave both unset (LoopRounds 0 means "unbounded" in the tracker), which — with
// an autopilot round that always changes and never meets the goal — would loop
// forever. This cap makes Drive terminate UNCONDITIONALLY, honoring the spec's
// "MaxRounds + StopWhen guarantee termination" even when the budget is open.
const hardLoopCap = 10000

// Drive runs rounds until a stop condition. It guarantees termination: the
// hard cap (hardLoopCap) and MaxRounds (via the tracker) bound it, an operator
// stop (ctx cancel) always wins, and a round error stops the loop. The returned
// StopCond and round count are audited by the caller (the orchestrator emits a
// KindLoopStop action).
//
// The stop-continuation guarantee: once Drive returns StopOperator, the caller
// must not silently resume — the orchestrator's stop-continuation guard enforces
// this by refusing to re-enter a stopped run.
func (s LoopSpec) Drive(ctx context.Context, tr *tracker, round func(ctx context.Context, n int) RoundResult) (rounds int, stop StopCond, err error) {
	for {
		if rounds >= hardLoopCap {
			return rounds, StopMaxRound, nil
		}
		select {
		case <-ctx.Done():
			return rounds, StopOperator, ctx.Err()
		default:
		}
		if tr != nil && tr.expired() {
			return rounds, StopBudget, nil
		}
		if tr != nil && !tr.nextRound() {
			return rounds, StopMaxRound, nil
		}
		rounds++
		r := round(ctx, rounds)
		if r.Err != nil {
			return rounds, StopBudget, r.Err
		}
		if r.GoalMet {
			return rounds, StopGoalMet, nil
		}
		// ultrawork/ralph converge on "no more changes": a round that produced
		// no diff and did not meet the goal has nothing left to do.
		if !r.Changed && s.Kind != LoopAutopilot {
			return rounds, StopNoDiff, nil
		}
	}
}
