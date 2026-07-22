// Package graph is the pure, bounded, governed agent-loop engine (the
// air-agent-graph pillar, v1). It is the loop layer of the Air Knowledge System:
// a typed run state carried through a set of nodes wired by CONDITIONAL, possibly
// CYCLIC edges, so an agent can reflect, retry, and replan — and every such loop
// is bounded so it can never run away.
//
// The package is deliberately PURE: it has no mesh, no network, no policy, and no
// checkpoint dependency, so the whole engine is unit-testable in isolation. The
// two load-bearing functions are:
//
//   - Reduce(state, output): a deterministic, IMMUTABLE reducer that folds one
//     node's output into a NEW state (the input state is never mutated), bumping a
//     monotonic Version and Iter, unioning taint Labels, and appending to an
//     append-only History.
//   - Step(graph, state): a pure edge evaluator returning the next node id, or a
//     terminate signal with a reason. Step enforces the termination criteria that
//     make the loop bounded — a goal/convergence predicate (success), a hard
//     max-iteration cap, and a cost-budget mirror — BEFORE it ever routes an edge,
//     so no configuration can produce an unbounded loop.
//
// The governed runner (cmd/meshmcp) drives this engine, executing each node's
// tool call through the air/egress gateway (taint + budget enforced in-loop,
// client-side) and checkpointing each step through air/checkpoint (durable,
// identity-bound-resumable, double-fire-safe). The engine stays generic: a node
// runs a NodeFunc that may call tools through the gateway — kg/rag/etc. are not
// hard-wired in v1.
package graph

import "context"

// Terminate is the reserved edge target meaning "end the run here". An edge whose
// To is Terminate ends the loop successfully rather than routing to a node.
const Terminate = "END"

// GraphState is the typed, append-only state a run carries. It is treated as an
// immutable value: Reduce and the cursor helpers return a NEW GraphState and
// never mutate the receiver, honoring the repo's immutability rule so a resumed
// or replayed run reconstructs byte-identical state.
//
// Version and Iter are monotonic: Version bumps on every Reduce (a content
// version for the payload), and Iter counts node executions — it is the value the
// hard max-iteration cap is enforced against, and thus the headline bound that
// makes every loop finite.
type GraphState struct {
	// Version is a monotonic content version, bumped once per Reduce. It lets a
	// checkpoint/replay confirm it reconstructed the same state generation.
	Version int `json:"version"`
	// Cursor is the id of the node the run is currently at (or about to execute).
	// It is what Step reads to evaluate the current node's edges and what a resume
	// restores to continue from the right place.
	Cursor string `json:"cursor"`
	// Iter counts node executions across the whole run (incremented by Reduce). The
	// hard max-iteration bound is enforced against it, so a non-converging cyclic
	// graph terminates at the cap instead of looping forever.
	Iter int `json:"iter"`
	// Cost mirrors the cumulative governed cost the run has spent, kept in sync from
	// each real policy Decision.Cost the gateway returns. The gateway is the
	// authoritative budget enforcer; this mirror lets the pure engine also treat a
	// cost budget as a termination criterion and lets a run be inspected offline.
	Cost int `json:"cost"`
	// Data is the reducer-updated payload: each node's output keyed by node id, so a
	// predicate can route on an earlier node's result (e.g. "critic.ok == false").
	Data map[string]any `json:"data,omitempty"`
	// Labels is the taint/data-flow lattice, accumulated MONOTONICALLY from the real
	// Decision.AddLabels of each governed call. A label added in one iteration
	// persists into every later one, so a later egress decision sees taint from an
	// earlier node — prompt-injection defense that holds across the loop.
	Labels map[string]bool `json:"labels,omitempty"`
	// History is the append-only record of what happened each step, for audit and
	// offline inspection. It is never rewritten, only appended.
	History []Record `json:"history,omitempty"`
}

// Record is one append-only history entry: which node produced output at which
// iteration and what it cost. It is data, not control — Step never reads History.
type Record struct {
	Node string `json:"node"`
	Iter int    `json:"iter"`
	Cost int    `json:"cost"`
}

// NodeOutput is what a node produces for the reducer to fold in. Data is the
// node's result payload (keyed under the node id in state), Labels are the taint
// labels the governed call added (mirrored from the real policy Decision), and
// Cost is the governed cost the call consumed (mirrored from Decision.Cost). A
// runner fills Labels/Cost from the gateway's actual verdict, never fabricated.
type NodeOutput struct {
	Node   string
	Data   map[string]any
	Labels []string
	Cost   int
}

// NodeFunc is a node's execute signature: given the current state it produces an
// output (or an error). In the governed runner a NodeFunc calls a tool through
// the egress gateway; in unit tests it is a plain in-memory function. Keeping the
// node body behind this one signature is what keeps node execution generic and
// pluggable in v1 rather than hard-wiring specific capabilities.
type NodeFunc func(ctx context.Context, s GraphState) (NodeOutput, error)

// NewState returns the initial state for a run beginning at entry. Data and
// Labels are non-nil so callers and the reducer never special-case a nil map.
func NewState(entry string) GraphState {
	return GraphState{
		Cursor: entry,
		Data:   map[string]any{},
		Labels: map[string]bool{},
	}
}

// Reduce folds out into prev and returns a NEW state; prev is never mutated. It
// bumps Version and Iter, adds Cost, keys out.Data under out.Node, unions
// out.Labels into the monotonic taint set, and appends a History record. Given
// the same prev and out it always returns the same result (deterministic), and
// the returned state shares no mutable structure with prev (immutable).
func Reduce(prev GraphState, out NodeOutput) GraphState {
	next := prev.clone()
	next.Version = prev.Version + 1
	next.Iter = prev.Iter + 1
	next.Cost = prev.Cost + out.Cost
	if out.Node != "" {
		next.Data[out.Node] = out.Data
	}
	for _, l := range out.Labels {
		next.Labels[l] = true
	}
	next.History = append(next.History, Record{Node: out.Node, Iter: next.Iter, Cost: out.Cost})
	return next
}

// WithCursor returns a copy of s positioned at node id, without mutating s and
// without advancing Version/Iter — moving the cursor is not a reduction, it is
// the routing decision Step already made.
func (s GraphState) WithCursor(id string) GraphState {
	next := s.clone()
	next.Cursor = id
	return next
}

// clone returns a deep-enough copy: fresh Data, Labels, and History containers so
// mutating the copy can never write through to the original. The Data VALUES are
// treated as immutable (a node writes a whole new value per key), matching how
// Reduce assigns them, so a shallow value copy is sufficient and correct here.
func (s GraphState) clone() GraphState {
	data := make(map[string]any, len(s.Data))
	for k, v := range s.Data {
		data[k] = v
	}
	labels := make(map[string]bool, len(s.Labels))
	for k, v := range s.Labels {
		labels[k] = v
	}
	history := make([]Record, len(s.History))
	copy(history, s.History)
	return GraphState{
		Version: s.Version,
		Cursor:  s.Cursor,
		Iter:    s.Iter,
		Cost:    s.Cost,
		Data:    data,
		Labels:  labels,
		History: history,
	}
}
