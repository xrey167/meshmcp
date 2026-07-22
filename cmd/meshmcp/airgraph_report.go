package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xrey167/meshmcp/air/checkpoint"
	"github.com/xrey167/meshmcp/air/graph"
	"github.com/xrey167/meshmcp/policy"
)

// printGraphPlan prints a --dry-run summary: the node/edge shape and the bounds,
// without joining the mesh or running anything.
func printGraphPlan(def *graph.Definition, g *graph.Graph, jsonOut bool) error {
	if jsonOut {
		plan := map[string]any{
			"name":           def.Name,
			"entry":          g.Entry,
			"max_iterations": g.Bounds.MaxIterations,
			"cost_budget":    g.Bounds.CostBudget,
			"nodes":          graphNodeSummaries(def),
		}
		b, err := json.MarshalIndent(plan, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	fmt.Println(bold("graph ") + cyan(def.Name) + dim(fmt.Sprintf("  entry=%s  max_iters=%d  budget=%d", g.Entry, g.Bounds.MaxIterations, g.Bounds.CostBudget)))
	for _, n := range def.Nodes {
		tags := ""
		if n.SideEffecting {
			tags += dim(" [side-effecting]")
		}
		if n.RequireCosign {
			tags += amber(" [cosign]")
		}
		fmt.Printf("  %s %s%s\n", bold(n.ID), dim(n.Backend+" · "+n.Tool), tags)
		for _, e := range n.Edges {
			when := e.When
			if when == "" {
				when = "always"
			}
			arrow := "->"
			if e.Loop {
				arrow = "↻"
			}
			fmt.Printf("      %s %s %s\n", arrow, cyan(e.To), dim("when "+when))
		}
	}
	return nil
}

func graphNodeSummaries(def *graph.Definition) []map[string]any {
	out := make([]map[string]any, 0, len(def.Nodes))
	for _, n := range def.Nodes {
		edges := make([]map[string]any, 0, len(n.Edges))
		for _, e := range n.Edges {
			edges = append(edges, map[string]any{"to": e.To, "when": e.When, "loop": e.Loop})
		}
		out = append(out, map[string]any{
			"id": n.ID, "backend": n.Backend, "tool": n.Tool,
			"side_effecting": n.SideEffecting, "require_cosign": n.RequireCosign,
			"edges": edges,
		})
	}
	return out
}

// reportRun prints the outcome of a run or resume: the terminal reason, iteration
// count, mirrored cost, spent budget, and accumulated taint labels.
func reportRun(runID string, r *graphRunner, out runOutcome, jsonOut bool) error {
	if jsonOut {
		b, err := json.MarshalIndent(map[string]any{
			"run_id":    runID,
			"reason":    out.Reason,
			"parked":    out.Parked,
			"node":      out.Node,
			"iters":     out.State.Iter,
			"cost":      out.State.Cost,
			"spent":     r.gw.Spent(),
			"remaining": r.gw.Remaining(),
			"labels":    labelList(out.State.Labels),
		}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	switch {
	case out.Parked:
		fmt.Println(amber("⏸ parked for cosign ") + dim(fmt.Sprintf("run %s at node %q — approve, then `air graph resume --run-id %s`", runID, out.Node, runID)))
	case out.Reason == "converged":
		fmt.Println(okLine("converged") + dim(fmt.Sprintf(" · run %s · %d iters · cost %d", runID, out.State.Iter, out.State.Cost)))
	case out.Reason == "max_iterations" || out.Reason == "budget" || out.Reason == "cost_budget":
		fmt.Println(amber("bounded stop: ") + out.Reason + dim(fmt.Sprintf(" · run %s · %d iters · cost %d", runID, out.State.Iter, out.State.Cost)))
	default:
		fmt.Println(dim(fmt.Sprintf("run %s ended: %s · %d iters · cost %d", runID, out.Reason, out.State.Iter, out.State.Cost)))
	}
	if labels := labelList(out.State.Labels); len(labels) > 0 {
		fmt.Fprintln(os.Stderr, dim("taint labels: ")+fmt.Sprint(labels))
	}
	return nil
}

// inspectRun replays a run from its checkpoint (state, step/cursor, pending) and,
// when verify is set, checks the audit chain end to end. It reads only — no mesh,
// no execution. The checkpoint file is read directly: inspect is a local,
// read-only operation on state the operator already holds on disk, so it neither
// joins the mesh (it has no identity to bind against) nor mutates the run.
func inspectRun(stateDir, runID, auditPath string, verify, jsonOut bool) error {
	if !safeRunID(runID) {
		return fmt.Errorf("air graph inspect: unsafe run id %q", runID)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, runID+".json"))
	if os.IsNotExist(err) {
		return fmt.Errorf("air graph inspect: no run %q", runID)
	}
	if err != nil {
		return fmt.Errorf("air graph inspect: read checkpoint: %w", err)
	}
	var cp checkpoint.Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return fmt.Errorf("air graph inspect: parse checkpoint: %w", err)
	}
	var pr persistedRun
	if err := json.Unmarshal(cp.State, &pr); err != nil {
		return fmt.Errorf("air graph inspect: decode state: %w", err)
	}

	var verifyRes *policy.VerifyResult
	if verify && auditPath != "" {
		data, rerr := os.ReadFile(auditPath)
		if rerr != nil {
			return fmt.Errorf("air graph inspect: read audit %s: %w", auditPath, rerr)
		}
		res, verr := policy.VerifyChain(bytes.NewReader(data))
		if verr != nil {
			return fmt.Errorf("air graph inspect: verify: %w", verr)
		}
		verifyRes = &res
	}

	if jsonOut {
		summary := map[string]any{
			"run_id":  runID,
			"cursor":  pr.State.Cursor,
			"iters":   pr.State.Iter,
			"cost":    pr.State.Cost,
			"pending": pr.Pending,
			"labels":  labelList(pr.State.Labels),
			"history": pr.State.History,
		}
		if cp.Intent != nil {
			summary["intent_node"] = cp.Intent.NodeID
		}
		if verifyRes != nil {
			summary["chain_ok"] = verifyRes.OK
			summary["chain_count"] = verifyRes.Count
		}
		b, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	fmt.Println(bold("run ") + cyan(runID) + dim(fmt.Sprintf("  cursor=%s  step=%d  cost=%d", pr.State.Cursor, pr.State.Iter, pr.State.Cost)))
	if pr.Pending != "" {
		fmt.Println(amber("  parked for cosign") + dim(" (binding "+shortKey(pr.Pending)+")"))
	}
	if cp.Intent != nil {
		fmt.Println(amber("  pending intent") + dim(" at node "+cp.Intent.NodeID+" — resume will not re-fire it"))
	}
	for _, h := range pr.State.History {
		fmt.Printf("  %s iter=%d cost=%d\n", bold(h.Node), h.Iter, h.Cost)
	}
	if verifyRes != nil {
		if verifyRes.OK {
			fmt.Println(okLine("chain verified") + dim(fmt.Sprintf(" · %d records", verifyRes.Count)))
		} else {
			fmt.Println(red("chain BROKEN") + dim(fmt.Sprintf(" at seq %d: %s", verifyRes.BreakSeq, verifyRes.Reason)))
		}
	}
	return nil
}

// safeRunID rejects a run id that is not a single safe path element, so a
// user-supplied id can never make inspect read outside the state directory.
func safeRunID(runID string) bool {
	if runID == "" || runID == "." || runID == ".." {
		return false
	}
	if strings.ContainsRune(runID, '/') || strings.ContainsRune(runID, '\\') || strings.ContainsRune(runID, filepath.Separator) {
		return false
	}
	return filepath.Base(runID) == runID
}

func labelList(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	return out
}
