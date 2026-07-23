package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/air/checkpoint"
	"github.com/xrey167/meshmcp/air/egress"
	"github.com/xrey167/meshmcp/air/graph"
	"github.com/xrey167/meshmcp/air/know"
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

	// audit is the shared hash-chained ledger the runner emits its OWN records
	// to (graph.cosign park/release, wall-clock stops); the gateway and the
	// checkpoint store audit through their own handles to the same sink. nil =
	// those runner events go unrecorded (tests may pass nil).
	audit policy.AuditSink
	// approvals is the request-bound approval store consulted when a call comes
	// back cosign: a signed, single-use approval bound to the EXACT
	// (peer, backend, tool, args) — run-scoped first, then the approver's
	// session-less form — releases the parked call. nil = park-only (no store,
	// nothing ever releases).
	approvals policy.RequestApprovalStore
	// now supplies approval-expiry time; nil = time.Now.
	now func() time.Time
}

func (r *graphRunner) nowT() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// auditEvent appends one runner-level knowledge-op record (best-effort; the
// governance outcome never depends on the sink).
func (r *graphRunner) auditEvent(mk func(know.Event) policy.AuditRecord, decision, reason, corpus string, provenance []string) {
	if r.audit == nil {
		return
	}
	_ = r.audit.Append(mk(know.Event{
		Peer:       r.caller.PeerFQDN,
		PeerKey:    r.caller.PeerKey,
		Corpus:     corpus,
		Decision:   decision,
		Reason:     reason,
		Provenance: provenance,
	}))
}

// consumeApproval atomically consumes a request-bound approval for this exact
// node call, if one exists. It tries the RUN-BOUND binding first (session =
// runID — an approval scoped to this specific run), then the SESSION-LESS
// binding the standard approver mints (policy.Pending.ApprovalRequest leaves
// Session unset). Both are exact-argument-bound: a changed argument, backend,
// tool, or peer is a different binding and matches nothing. Single-use is the
// store's guarantee — a consumed approval is spent.
func (r *graphRunner) consumeApproval(n graph.NodeDef, args []byte) (bool, string) {
	if r.approvals == nil {
		return false, "no approval store configured"
	}
	now := r.nowT()
	runBound := policy.NewApprovalRequest(r.caller.PeerKey, n.Backend, n.Tool, args, r.runID)
	if ok, _ := r.approvals.ConsumeApproval(runBound, now); ok {
		return true, "run-bound approval consumed"
	}
	sessionless := policy.NewApprovalRequest(r.caller.PeerKey, n.Backend, n.Tool, args, "")
	if ok, _ := r.approvals.ConsumeApproval(sessionless, now); ok {
		return true, "request-bound approval consumed"
	}
	return false, "no matching approval"
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

	// Re-seed the fresh per-run gateway with the persisted taint labels, so the
	// monotonic taint lattice holds ACROSS the resume: a label emitted before
	// the park/crash still blocks a later egress decision in this process.
	r.gw.Taint(labelList(state.Labels)...)

	// A parked cosign run must resume as EXACTLY the parked call: rebuild the
	// binding key from the persisted definition at the cursor and require it to
	// match the persisted Pending key. A mismatch means the definition or
	// arguments drifted since the park — refuse rather than silently re-decide
	// (and possibly release an approval against) a different call.
	if pr.Pending != "" {
		nodeDef, ok := r.def.Node(state.Cursor)
		if !ok {
			return runOutcome{}, fmt.Errorf("air graph resume: parked cursor at unknown node %q", state.Cursor)
		}
		args, err := json.Marshal(orEmpty(nodeDef.Args))
		if err != nil {
			return runOutcome{}, fmt.Errorf("air graph resume: marshal parked args: %w", err)
		}
		if idemKey(r.caller, nodeDef.Backend, nodeDef.Tool, args) != pr.Pending {
			return runOutcome{}, fmt.Errorf("air graph resume: parked cosign binding mismatch at node %q — the definition or arguments no longer match the parked call; refusing to re-decide", state.Cursor)
		}
	}

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
// human co-sign — unless a signed, single-use, argument-bound approval for this
// exact call is consumed, which RELEASES it (executed once, audited as a
// graph.cosign allow); an allow reduces the output into new state, checkpoints
// it, and lets the pure Step choose the next node. The loop cannot run away:
// Step enforces convergence, the hard max-iteration cap, and the cost mirror,
// the Gateway halts on budget, and the context deadline is the wall-clock bound
// — checked every hop, checkpointing a resumable "timeout" stop.
func (r *graphRunner) loop(ctx context.Context, state graph.GraphState) (runOutcome, error) {
	for {
		// Wall-clock bound (the fourth termination criterion): an expired or
		// cancelled context stops the run BEFORE the next governed call, with
		// the state checkpointed so the run is resumable.
		if ctxErr := ctx.Err(); ctxErr != nil {
			if err := r.save(state, nil, ""); err != nil {
				return runOutcome{}, err
			}
			r.auditEvent(know.NodeEnter, "deny", "wall_clock: "+ctxErr.Error(), state.Cursor, nil)
			return runOutcome{State: state, Reason: "timeout", Node: state.Cursor}, nil
		}

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
			pending := idemKey(r.caller, nodeDef.Backend, nodeDef.Tool, args)
			released, why := r.consumeApproval(nodeDef, args)
			if released {
				// RELEASE: a signed, single-use approval bound to this exact
				// call was consumed. Policy is not bypassed — the engine still
				// said cosign; the human's argument-bound approval IS the
				// authorization to execute this one call, once. Audit the
				// consumption as graph.cosign allow, then execute THROUGH the
				// gateway's Release so the matched rule's effects still bind:
				// its cost is budget-checked and spent, its emit-labels taint
				// the run (a released taint_source still blocks later guarded
				// egress), and the returned decision carries both for the
				// state fold below. The intent bracket stays pending through
				// the effect, exactly like an allowed call.
				r.auditEvent(know.Cosign, "allow", why+" — human release of parked call at node "+nodeDef.ID, nodeDef.Tool, []string{pending})
				dec, result, callErr = r.gw.Release(r.caller, nodeDef.Tool, dec, func() ([]byte, error) {
					return r.exec.Do(ctx, nodeDef.Backend, nodeDef.Tool, args)
				})
				if dec.Outcome == policy.OutcomeDeny {
					// The released call's own cost would breach the run cap:
					// the bounds outrank the human release. Nothing executed —
					// clear the intent, persist, and halt like any budget stop
					// (the consumed approval stays spent; deny-by-default).
					if nodeDef.SideEffecting {
						_ = r.store.CommitIntent(r.runID, r.caller.PeerKey)
					}
					if err := r.save(state, nil, ""); err != nil {
						return runOutcome{}, err
					}
					return runOutcome{State: state, Reason: "budget", Node: nodeDef.ID}, nil
				}
				break
			}
			// PARK: not-yet-allowed and no approval. Nothing executed — clear
			// the intent (the effect did NOT fire), audit the park as a
			// graph.cosign record, persist the run bound to this exact call,
			// and stop.
			if nodeDef.SideEffecting {
				_ = r.store.CommitIntent(r.runID, r.caller.PeerKey)
			}
			r.auditEvent(know.Cosign, "cosign", "parked for human co-sign at node "+nodeDef.ID+" ("+why+")", nodeDef.Tool, []string{pending})
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
