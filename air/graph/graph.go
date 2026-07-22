package graph

import (
	"errors"
	"fmt"
)

// DefaultMaxIterations is the hard iteration cap applied when a graph declares a
// non-positive max: a run can NEVER be configured unbounded. Zero or negative in
// a definition is treated as "use the safe default", fail-closed, never
// "unlimited". This is the anti-runaway posture.
const DefaultMaxIterations = 25

// ErrInvalidGraph is returned by Validate for any structurally invalid graph.
var ErrInvalidGraph = errors.New("graph: invalid graph")

// Predicate is a pure boolean test over the run state, used both to route a
// conditional edge (Edge.When) and to detect convergence (Bounds.Converge). A nil
// predicate on an edge means "unconditional"; a nil convergence predicate means
// "never converges on a goal" (the run then ends by max-iter or a terminal edge).
type Predicate func(GraphState) bool

// Bounds are the termination criteria that make a loop bounded. They are enforced
// by Step BEFORE any edge is routed, so no node wiring can escape them.
//
//   - Converge: the goal predicate. When it holds, the run ends successfully.
//   - MaxIterations: the hard cap on node executions. Reached => the run ends,
//     even if it never converged. Non-positive is coerced to DefaultMaxIterations
//     by Validate, so this is always a real finite bound.
//   - CostBudget: an optional cost mirror bound. When >0 and the mirrored spend
//     reaches it, the run ends. The authoritative budget enforcement is the egress
//     gateway in the runner; this is a pure backstop so the engine is also
//     cost-bounded in isolation.
type Bounds struct {
	Converge      Predicate
	MaxIterations int
	CostBudget    int
}

// Edge is a conditional, possibly cyclic transition. To may name an EARLIER node
// (a back-edge — what makes reflection/replan loops possible) or Terminate. When
// is the predicate that must hold for the edge to be taken; a nil When is
// unconditional. Loop marks a back-edge for documentation/inspection; it does not
// change enforcement, because the global MaxIterations bounds every cycle
// unconditionally.
type Edge struct {
	To   string
	When Predicate
	Loop bool
}

// Node is one step of the graph: an id, the edges evaluated in order to choose
// the successor, and an execute function. Exec is used by the pure reference
// Drive helper and by unit tests; the governed runner supplies each node's Exec
// as a closure over the egress gateway. Step reads only ID and Edges — never Exec
// — which is why routing stays pure and testable.
type Node struct {
	ID    string
	Exec  NodeFunc
	Edges []Edge
}

// Graph is the compiled, in-memory shape of a run: an entry node, the node set,
// and the mandatory Bounds. It is built either directly (tests) or by compiling a
// Definition (the runner). The Exec functions may be nil after compilation from a
// Definition — the runner attaches them — but structure and Bounds are always
// present and validated.
type Graph struct {
	Name   string
	Entry  string
	Nodes  []Node
	Bounds Bounds

	index map[string]*Node
}

// node returns the node with id and whether it exists, using the built index.
func (g *Graph) node(id string) (*Node, bool) {
	if g.index == nil {
		g.reindex()
	}
	n, ok := g.index[id]
	return n, ok
}

// reindex rebuilds the id->node lookup. Called lazily so a Graph assembled by
// hand in a test needs no separate init step.
func (g *Graph) reindex() {
	g.index = make(map[string]*Node, len(g.Nodes))
	for i := range g.Nodes {
		g.index[g.Nodes[i].ID] = &g.Nodes[i]
	}
}

// Validate checks the graph is structurally sound and coerces the bounds to be
// fail-closed. It returns ErrInvalidGraph (wrapped with detail) when: the entry
// is empty or unknown, a node id is empty or duplicated, or an edge targets a
// node that does not exist (Terminate is always valid). It MUTATES g.Bounds only
// to raise a non-positive MaxIterations to DefaultMaxIterations — the one place a
// zero is turned into a safe bound rather than rejected — so every validated
// graph is guaranteed to terminate.
func (g *Graph) Validate() error {
	if g.Entry == "" {
		return fmt.Errorf("%w: empty entry", ErrInvalidGraph)
	}
	seen := make(map[string]bool, len(g.Nodes))
	for _, n := range g.Nodes {
		if n.ID == "" {
			return fmt.Errorf("%w: a node has an empty id", ErrInvalidGraph)
		}
		if n.ID == Terminate {
			return fmt.Errorf("%w: node id %q is reserved", ErrInvalidGraph, Terminate)
		}
		if seen[n.ID] {
			return fmt.Errorf("%w: duplicate node id %q", ErrInvalidGraph, n.ID)
		}
		seen[n.ID] = true
	}
	if !seen[g.Entry] {
		return fmt.Errorf("%w: entry %q is not a node", ErrInvalidGraph, g.Entry)
	}
	for _, n := range g.Nodes {
		for _, e := range n.Edges {
			if e.To == Terminate {
				continue
			}
			if !seen[e.To] {
				return fmt.Errorf("%w: node %q has an edge to unknown node %q", ErrInvalidGraph, n.ID, e.To)
			}
		}
	}
	if g.Bounds.MaxIterations <= 0 {
		g.Bounds.MaxIterations = DefaultMaxIterations
	}
	g.reindex()
	return nil
}
