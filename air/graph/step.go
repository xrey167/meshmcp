package graph

import "context"

// Step is the pure edge evaluator and the enforcement point for boundedness.
// Given the current state it returns the next node id, whether the run is done,
// and a reason. It NEVER mutates state and NEVER executes a node.
//
// Termination criteria are checked FIRST, in this order, so no edge wiring can
// escape them:
//
//  1. Converge (goal predicate) holds  -> done, "converged"  (success).
//  2. Iter has reached MaxIterations   -> done, "max_iterations"  (the hard cap
//     that bounds every cycle; a non-converging loop ends here, not forever).
//  3. Cost has reached CostBudget (>0) -> done, "cost_budget"  (mirror backstop;
//     the gateway is the authoritative budget enforcer in the runner).
//
// Only then does it route: the current node's edges are evaluated in order and
// the first whose When holds (nil When = unconditional) wins. An edge To of
// Terminate ends the run ("terminate"). A node with no matching edge ends the run
// ("no_edge") rather than hanging — a dead end is always finite.
func Step(g *Graph, s GraphState) (next string, done bool, reason string) {
	if g.Bounds.Converge != nil && g.Bounds.Converge(s) {
		return "", true, "converged"
	}
	if s.Iter >= g.Bounds.MaxIterations {
		return "", true, "max_iterations"
	}
	if g.Bounds.CostBudget > 0 && s.Cost >= g.Bounds.CostBudget {
		return "", true, "cost_budget"
	}
	node, ok := g.node(s.Cursor)
	if !ok {
		return "", true, "unknown_node"
	}
	for _, e := range node.Edges {
		if e.When == nil || e.When(s) {
			if e.To == Terminate {
				return "", true, "terminate"
			}
			return e.To, false, "edge:" + e.To
		}
	}
	return "", true, "no_edge"
}

// Result is the outcome of a completed pure Drive: the final state and the reason
// the run ended (the same reason strings Step returns, or "error").
type Result struct {
	State  GraphState
	Reason string
}

// Drive is the pure reference driver: it runs a graph to completion in memory by
// executing each node's Exec, folding the output with Reduce, and choosing the
// next node with Step, until Step reports done. It takes NO gateway and NO
// checkpoint — it exists to unit-test the loop mechanics (a goal-converging graph
// stops via the predicate; a non-converging cyclic graph stops at the
// max-iteration cap) and to document the shape the governed runner elaborates.
//
// It is guaranteed to terminate: Validate coerces MaxIterations to a positive
// bound and Step ends the run once Iter reaches it, so even a graph whose edges
// always route back cannot loop forever. A node Exec error stops the run with
// reason "error" and returns that error.
func Drive(ctx context.Context, g *Graph, init GraphState) (Result, error) {
	if err := g.Validate(); err != nil {
		return Result{}, err
	}
	state := init
	for {
		node, ok := g.node(state.Cursor)
		if !ok {
			return Result{State: state, Reason: "unknown_node"}, nil
		}
		if node.Exec == nil {
			return Result{State: state, Reason: "no_exec"}, nil
		}
		out, err := node.Exec(ctx, state)
		if err != nil {
			return Result{State: state, Reason: "error"}, err
		}
		out.Node = node.ID
		state = Reduce(state, out)
		next, done, reason := Step(g, state)
		if done {
			return Result{State: state, Reason: reason}, nil
		}
		state = state.WithCursor(next)
	}
}
