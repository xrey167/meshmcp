package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/xrey167/meshmcp/air/checkpoint"
	"github.com/xrey167/meshmcp/air/egress"
	"github.com/xrey167/meshmcp/air/graph"
	"github.com/xrey167/meshmcp/policy"
)

// graphRunner drives the pure air/graph engine as a bounded, governed, durable
// agent loop. It is the S5+S7 elaboration of the pure engine: every node's tool
// call is made THROUGH the egress Gateway (taint + budget enforced client-side,
// in the loop) and every step is CHECKPOINTED through the checkpoint Store
// (durable, identity-bound-resumable, double-fire-safe). The pure engine owns the
// routing and the bounds; this runner owns the governance and persistence, and
// never re-derives what the engine already decided.
//
// The runner is deliberately mesh-free at this layer: node execution is behind
// the toolExecutor seam, so the whole governed loop — allow advances, deny
// terminates, budget halts, cosign parks, resume is idempotent — is unit-testable
// against a real Gateway over an in-memory policy with a fake executor.
type graphRunner struct {
	def    *graph.Definition
	graph  *graph.Graph
	gw     *egress.Gateway
	store  *checkpoint.Store
	exec   toolExecutor
	caller egress.Caller
	runID  string
}

// toolExecutor performs the raw tool call a node makes. The Gateway decides
// WHETHER it runs; the executor is what actually runs it (a mesh MCP call in
// production, a fake in tests). It returns the raw result bytes.
type toolExecutor interface {
	Do(ctx context.Context, backend, tool string, args []byte) ([]byte, error)
}

// runOutcome is the terminal result of a driven run: the final state, the reason
// the loop ended (an engine Step reason, or "deny"/"budget"/"cosign"/"error"),
// and whether it parked for a human co-sign (so the caller can surface the card).
type runOutcome struct {
	State  graph.GraphState
	Reason string
	Parked bool
	Node   string // the node in force at termination (the parked/denied/failed node)
}

// start drives a fresh run from the entry node. It writes an initial checkpoint
// (so a side-effecting first node has a checkpoint to record its intent against)
// and then runs the governed loop.
func (r *graphRunner) start(ctx context.Context) (runOutcome, error) {
	state := graph.NewState(r.graph.Entry)
	if err := r.save(state, nil, ""); err != nil {
		return runOutcome{}, err
	}
	return r.loop(ctx, state)
}

// resume continues a parked or crashed run. It loads the checkpoint under the
// creator's identity (Store.Load enforces the binding — only the creator resumes),
// then closes the double-fire window: if a pending pre-execution Intent names the
// node the cursor is still at, that side-effecting node may already have fired, so
// it is NOT re-run — its effect is treated as done, the intent cleared, and the
// loop advances. A stale intent (naming a node already advanced past) is simply
// cleared. Only then does the normal governed loop continue.
func (r *graphRunner) resume(ctx context.Context) (runOutcome, error) {
	cp, ok, err := r.store.Load(r.runID, r.caller.PeerKey)
	if err != nil {
		return runOutcome{}, err
	}
	if !ok {
		return runOutcome{}, fmt.Errorf("air graph resume: no run %q to resume", r.runID)
	}
	var pr persistedRun
	if err := json.Unmarshal(cp.State, &pr); err != nil {
		return runOutcome{}, fmt.Errorf("air graph resume: decode state: %w", err)
	}
	state := pr.State

	if cp.Intent != nil && cp.Intent.NodeID == state.Cursor {
		// The side-effecting node was in-flight when the run stopped. Do not
		// re-fire it (at-most-once): record it as resumed-and-skipped, advance.
		out := graph.NodeOutput{Node: state.Cursor, Data: map[string]any{"resumed": true, "skipped": true}}
		state = graph.Reduce(state, out)
		next, done, reason := graph.Step(r.graph, state)
		if !done {
			state = state.WithCursor(next)
		}
		if err := r.save(state, nil, ""); err != nil {
			return runOutcome{}, err
		}
		_ = r.store.CommitIntent(r.runID, r.caller.PeerKey)
		if done {
			return runOutcome{State: state, Reason: reason}, nil
		}
	} else if cp.Intent != nil {
		// Stale intent from a node already advanced past; clear it and continue.
		_ = r.store.CommitIntent(r.runID, r.caller.PeerKey)
	}
	return r.loop(ctx, state)
}

// loop is the governed driver. For each node it (optionally) records a
// pre-execution intent, makes the node's tool call through the Gateway, and acts
// on the real policy Decision: a deny (including a budget halt) TERMINATES the
// bounded loop; a cosign PARKS the run (checkpoint written, loop stops) for a
// human co-sign; an allow reduces the output into new state, checkpoints it, and
// lets the pure Step choose the next node. The loop cannot run away: Step enforces
// convergence, the hard max-iteration cap, and the cost mirror, and the Gateway
// halts on budget.
func (r *graphRunner) loop(ctx context.Context, state graph.GraphState) (runOutcome, error) {
	for {
		nodeDef, ok := r.def.Node(state.Cursor)
		if !ok {
			return runOutcome{}, fmt.Errorf("air graph: cursor at unknown node %q", state.Cursor)
		}
		args, err := json.Marshal(orEmpty(nodeDef.Args))
		if err != nil {
			return runOutcome{}, fmt.Errorf("air graph: marshal args for %q: %w", nodeDef.ID, err)
		}

		// Pre-execution intent guard for side-effecting nodes (idempotency): a
		// durable record written BEFORE the effect, so a crash in the execute
		// window is caught on resume and the op is not double-fired.
		if nodeDef.SideEffecting {
			if err := r.store.BeginIntent(r.runID, r.caller.PeerKey, checkpoint.Intent{
				NodeID:         nodeDef.ID,
				IdempotencyKey: idemKey(r.caller, nodeDef.Backend, nodeDef.Tool, args),
				ArgsHash:       argsHash(args),
			}); err != nil {
				return runOutcome{}, fmt.Errorf("air graph: begin intent for %q: %w", nodeDef.ID, err)
			}
		}

		dec, result, callErr := r.gw.Call(r.caller, nodeDef.Backend, nodeDef.Tool, args, func() ([]byte, error) {
			return r.exec.Do(ctx, nodeDef.Backend, nodeDef.Tool, args)
		})

		switch dec.Outcome {
		case policy.OutcomeDeny:
			// Governance stop (policy deny or budget halt). Nothing executed, so
			// clear any intent, persist, and terminate the bounded loop.
			if nodeDef.SideEffecting {
				_ = r.store.CommitIntent(r.runID, r.caller.PeerKey)
			}
			reason := "deny"
			if strings.Contains(dec.Reason, "budget") {
				reason = "budget"
			}
			if err := r.save(state, nil, ""); err != nil {
				return runOutcome{}, err
			}
			return runOutcome{State: state, Reason: reason, Node: nodeDef.ID}, nil

		case policy.OutcomeCosign:
			// Not-yet-allowed: nothing executed. Clear the intent (the effect did
			// NOT fire) and PARK the run bound to this exact call, then stop.
			if nodeDef.SideEffecting {
				_ = r.store.CommitIntent(r.runID, r.caller.PeerKey)
			}
			pending := idemKey(r.caller, nodeDef.Backend, nodeDef.Tool, args)
			if err := r.save(state, nil, pending); err != nil {
				return runOutcome{}, err
			}
			return runOutcome{State: state, Reason: "cosign", Parked: true, Node: nodeDef.ID}, nil
		}

		if callErr != nil {
			// Allowed and executed, but the tool failed. The effect may have
			// partially fired; leave the intent pending so resume skips it, persist
			// the pre-node state, and surface the error.
			if err := r.save(state, cp2intent(nodeDef, r.caller, args), ""); err != nil {
				return runOutcome{}, err
			}
			return runOutcome{State: state, Reason: "error", Node: nodeDef.ID}, callErr
		}

		// Allowed and succeeded. Fold the REAL decision (labels + cost) and the
		// tool result into new state, advance the cursor via the pure engine, then
		// atomically persist the advanced state — which, carrying Intent nil for a
		// non-side-effecting node, also closes out this step.
		out := graph.NodeOutput{
			Node:   nodeDef.ID,
			Data:   parseResult(result),
			Labels: dec.AddLabels,
			Cost:   dec.Cost,
		}
		state = graph.Reduce(state, out)
		next, done, reason := graph.Step(r.graph, state)
		if !done {
			state = state.WithCursor(next)
		}
		// Persist the advanced state, carrying the intent forward so the commit is
		// atomic with the advance (a crash after this leaves cursor past the node
		// with a stale intent, which resume clears without re-firing).
		var carry *checkpoint.Intent
		if nodeDef.SideEffecting {
			carry = cp2intent(nodeDef, r.caller, args)
		}
		if err := r.save(state, carry, ""); err != nil {
			return runOutcome{}, err
		}
		if nodeDef.SideEffecting {
			_ = r.store.CommitIntent(r.runID, r.caller.PeerKey)
		}
		if done {
			return runOutcome{State: state, Reason: reason, Node: nodeDef.ID}, nil
		}
	}
}

// save persists the run: the definition, remaining budget, and the current graph
// state, plus an optional pending intent and cosign-pending key. It is one atomic
// Store.Save, identity-bound to the creator — a run id alone can never overwrite
// another identity's state.
func (r *graphRunner) save(state graph.GraphState, intent *checkpoint.Intent, pending string) error {
	defBytes, err := json.Marshal(r.def)
	if err != nil {
		return fmt.Errorf("air graph: marshal definition: %w", err)
	}
	payload, err := json.Marshal(persistedRun{
		Definition: defBytes,
		Budget:     r.gw.Budget(),
		Pending:    pending,
		State:      state,
	})
	if err != nil {
		return fmt.Errorf("air graph: marshal run state: %w", err)
	}
	return r.store.Save(checkpoint.Checkpoint{
		RunID:      r.runID,
		CreatorKey: r.caller.PeerKey,
		Step:       state.Iter,
		State:      payload,
		Intent:     intent,
	})
}

// persistedRun is what is serialized into Checkpoint.State: enough to rebuild and
// resume the exact run — its structure (Definition), its budget, its pure engine
// state, and any cosign-pending binding key.
type persistedRun struct {
	Definition json.RawMessage  `json:"definition"`
	Budget     int              `json:"budget"`
	Pending    string           `json:"pending,omitempty"`
	State      graph.GraphState `json:"state"`
}

// cp2intent builds the pre-execution Intent for a side-effecting node's call.
func cp2intent(n graph.NodeDef, caller egress.Caller, args []byte) *checkpoint.Intent {
	return &checkpoint.Intent{
		NodeID:         n.ID,
		IdempotencyKey: idemKey(caller, n.Backend, n.Tool, args),
		ArgsHash:       argsHash(args),
	}
}

// idemKey is the stable idempotency / cosign-binding key for one exact call:
// SHA-256 over the caller key, backend, tool, and arguments, so an approval or a
// resume decision is bound to this precise call and cannot release a different
// iteration's arguments.
func idemKey(caller egress.Caller, backend, tool string, args []byte) string {
	h := sha256.New()
	h.Write([]byte(caller.PeerKey))
	h.Write([]byte{0})
	h.Write([]byte(backend))
	h.Write([]byte{0})
	h.Write([]byte(tool))
	h.Write([]byte{0})
	h.Write(args)
	return hex.EncodeToString(h.Sum(nil))
}

func argsHash(args []byte) string {
	sum := sha256.Sum256(args)
	return hex.EncodeToString(sum[:])
}

// parseResult turns a tool result into the node's output payload. A JSON object
// is used directly (so predicates can route on its fields); anything else is
// wrapped under "result" so a node still contributes a usable value.
func parseResult(result []byte) map[string]any {
	trimmed := trimSpace(result)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var m map[string]any
		if err := json.Unmarshal(trimmed, &m); err == nil {
			return m
		}
	}
	return map[string]any{"result": string(trimmed)}
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func trimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

// errNoStateDir guards a resume/inspect that names no state directory.
var errNoStateDir = errors.New("air graph: --state-dir is required")
