package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air/checkpoint"
	"github.com/xrey167/meshmcp/air/egress"
	"github.com/xrey167/meshmcp/air/graph"
	"github.com/xrey167/meshmcp/policy"
)

// fakeExec is an in-memory toolExecutor: it records every tool it was actually
// asked to run (so a test can prove a denied/parked/skipped node NEVER executed)
// and returns per-tool canned JSON so node outputs drive the predicates.
type fakeExec struct {
	mu      sync.Mutex
	calls   []string
	fixed   map[string][]byte             // tool -> canned result
	dynamic map[string]func(n int) []byte // tool -> result by call index (1-based)
	counts  map[string]int
}

func newFakeExec() *fakeExec {
	return &fakeExec{fixed: map[string][]byte{}, dynamic: map[string]func(int) []byte{}, counts: map[string]int{}}
}

func (f *fakeExec) Do(_ context.Context, _, tool string, _ []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, tool)
	f.counts[tool]++
	if fn, ok := f.dynamic[tool]; ok {
		return fn(f.counts[tool]), nil
	}
	if b, ok := f.fixed[tool]; ok {
		return b, nil
	}
	return []byte(`{}`), nil
}

func (f *fakeExec) called(tool string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == tool {
			return true
		}
	}
	return false
}

// harness wires a real egress Gateway over an in-memory policy, a real checkpoint
// Store, one shared audit chain, and a fake executor — the whole governed loop
// with no mesh.
type harness struct {
	runner *graphRunner
	audit  *bytes.Buffer
	dir    string
	runID  string
	key    string
}

func newHarness(t *testing.T, def *graph.Definition, pol *policy.Policy, exec toolExecutor, budget int) *harness {
	t.Helper()
	g, err := def.Compile()
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	buf := &bytes.Buffer{}
	audit := policy.NewAuditLog(buf, func() string { return "2026-07-22T00:00:00Z" })
	engine := policy.NewEngine(pol, func() time.Time { return time.Unix(1_700_000_000, 0) }, nil)
	dir := t.TempDir()
	store, err := checkpoint.New(dir, audit)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	key := "wg-creator-key"
	return &harness{
		runner: &graphRunner{
			def:    def,
			graph:  g,
			gw:     egress.NewGateway(engine, audit, budget),
			store:  store,
			exec:   exec,
			caller: egress.Caller{PeerFQDN: "me.mesh", PeerKey: key},
			runID:  "run-1",
		},
		audit: buf,
		dir:   dir,
		runID: "run-1",
		key:   key,
	}
}

// allowAll is a permissive costed policy: every tool allowed, each call costs
// `cost` units (so a budget test can breach the cap).
func allowAll(cost int) *policy.Policy {
	rule := policy.Rule{Tools: []string{"*"}, Allow: true}
	if cost > 0 {
		rule.Rate = &policy.RateLimit{Max: 1_000_000, Cost: cost}
	}
	return &policy.Policy{Rules: []policy.Rule{rule}}
}

// reflectDef is a generate->critic reflection loop that converges when the critic
// reports ok, else loops back to draft — the canonical cyclic graph.
func reflectDef() *graph.Definition {
	return &graph.Definition{
		Name:   "reflect",
		Entry:  "draft",
		Bounds: graph.BoundsDef{MaxIterations: 20, Converge: "critic.ok == true"},
		Nodes: []graph.NodeDef{
			{ID: "draft", Backend: "rag", Tool: "draft", Edges: []graph.EdgeDef{{To: "critic"}}},
			{ID: "critic", Backend: "lint", Tool: "critic", Edges: []graph.EdgeDef{
				{To: "draft", When: "critic.ok == false", Loop: true},
				{To: graph.Terminate, When: "critic.ok == true"},
			}},
		},
	}
}

func TestRunGraph_ConvergesThroughGateway(t *testing.T) {
	exec := newFakeExec()
	// critic reports not-ok on turn 1, ok on turn 2 -> converge at iter 4.
	exec.dynamic["critic"] = func(n int) []byte {
		if n >= 2 {
			return []byte(`{"ok": true}`)
		}
		return []byte(`{"ok": false}`)
	}
	h := newHarness(t, reflectDef(), allowAll(0), exec, 500000)
	out, err := h.runner.start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Reason != "converged" {
		t.Fatalf("expected converged, got %q at iter %d", out.Reason, out.State.Iter)
	}
	if out.State.Iter != 4 {
		t.Fatalf("expected convergence at iter 4, got %d", out.State.Iter)
	}
	// The whole run — node-enters AND checkpoints — is one verifiable chain.
	res, err := policy.VerifyChain(bytes.NewReader(h.audit.Bytes()))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK || res.Count == 0 {
		t.Fatalf("audit chain not intact: ok=%v count=%d reason=%s", res.OK, res.Count, res.Reason)
	}
}

func TestRunGraph_MaxIterBoundsRunaway(t *testing.T) {
	exec := newFakeExec()
	exec.fixed["critic"] = []byte(`{"ok": false}`) // never converges
	def := reflectDef()
	def.Bounds.MaxIterations = 6
	h := newHarness(t, def, allowAll(0), exec, 500000)
	out, err := h.runner.start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Reason != "max_iterations" {
		t.Fatalf("a non-converging loop must stop at the cap, got %q", out.Reason)
	}
	if out.State.Iter != 6 {
		t.Fatalf("expected termination exactly at the cap, got %d", out.State.Iter)
	}
}

func TestRunGraph_BudgetHaltsLoop(t *testing.T) {
	exec := newFakeExec()
	exec.fixed["critic"] = []byte(`{"ok": false}`)
	// Each call costs 10; budget 15 admits one call, the second breaches -> halt.
	h := newHarness(t, reflectDef(), allowAll(10), exec, 15)
	out, err := h.runner.start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Reason != "budget" {
		t.Fatalf("runaway must be halted by the budget, got %q", out.Reason)
	}
	if h.runner.gw.Spent() != 10 {
		t.Fatalf("halted call must not spend: spent=%d", h.runner.gw.Spent())
	}
}

func TestRunGraph_DenyTerminates(t *testing.T) {
	exec := newFakeExec()
	pol := &policy.Policy{Rules: []policy.Rule{
		{Tools: []string{"draft"}, Allow: true},
		{Tools: []string{"critic"}, Allow: false}, // deny the critic
	}}
	h := newHarness(t, reflectDef(), pol, exec, 500000)
	out, err := h.runner.start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Reason != "deny" || out.Node != "critic" {
		t.Fatalf("expected deny at critic, got reason=%q node=%q", out.Reason, out.Node)
	}
	if exec.called("critic") {
		t.Fatal("a denied node must not execute its tool")
	}
}

func TestRunGraph_TaintBlocksEgressAcrossHops(t *testing.T) {
	exec := newFakeExec()
	def := &graph.Definition{
		Name:   "exfil",
		Entry:  "read",
		Bounds: graph.BoundsDef{MaxIterations: 20},
		Nodes: []graph.NodeDef{
			{ID: "read", Backend: "web", Tool: "read_web", Edges: []graph.EdgeDef{{To: "work"}}},
			{ID: "work", Backend: "cpu", Tool: "noop", Edges: []graph.EdgeDef{{To: "leak"}}},
			{ID: "leak", Backend: "mail", Tool: "egress", Edges: []graph.EdgeDef{{To: graph.Terminate}}},
		},
	}
	pol := &policy.Policy{Rules: []policy.Rule{
		{Tools: []string{"read_web"}, Allow: true, EmitLabels: []string{"pii"}}, // taints the run
		{Tools: []string{"egress"}, Allow: true, BlockLabels: []string{"pii"}},  // must not carry pii out
		{Tools: []string{"*"}, Allow: true},
	}}
	h := newHarness(t, def, pol, exec, 500000)
	out, err := h.runner.start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Reason != "deny" || out.Node != "leak" {
		t.Fatalf("taint from read must block egress at leak, got reason=%q node=%q", out.Reason, out.Node)
	}
	if !exec.called("read_web") || exec.called("egress") {
		t.Fatalf("expected read to run and egress to be blocked; calls=%v", exec.calls)
	}
	if !out.State.Labels["pii"] {
		t.Fatalf("taint label not accumulated into state: %v", out.State.Labels)
	}
}

// sendDef is a single side-effecting, cosign-guarded node.
func sendDef() *graph.Definition {
	return &graph.Definition{
		Name:   "send",
		Entry:  "send",
		Bounds: graph.BoundsDef{MaxIterations: 5},
		Nodes: []graph.NodeDef{
			{ID: "send", Backend: "mail", Tool: "send", SideEffecting: true, RequireCosign: true,
				Edges: []graph.EdgeDef{{To: graph.Terminate}}},
		},
	}
}

func TestRunGraph_CosignParks(t *testing.T) {
	exec := newFakeExec()
	pol := &policy.Policy{Rules: []policy.Rule{
		{Tools: []string{"send"}, Allow: true, RequireCosign: true},
	}}
	h := newHarness(t, sendDef(), pol, exec, 500000)
	out, err := h.runner.start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !out.Parked || out.Reason != "cosign" {
		t.Fatalf("a require_cosign node must park, got parked=%v reason=%q", out.Parked, out.Reason)
	}
	if exec.called("send") {
		t.Fatal("a parked (not-yet-cosigned) node must NOT execute")
	}
	// The checkpoint records the pending cosign binding.
	cp := readCheckpoint(t, h.dir, h.runID)
	var pr persistedRun
	if err := json.Unmarshal(cp.State, &pr); err != nil {
		t.Fatal(err)
	}
	if pr.Pending == "" {
		t.Fatal("parked run did not record a cosign-pending binding key")
	}
}

func TestRunGraph_ResumeIsIdempotent_NoDoubleFire(t *testing.T) {
	exec := newFakeExec()
	h := newHarness(t, sendDef(), allowAll(0), exec, 500000)
	// Simulate a crash mid-flight: the side-effecting node's pre-execution intent
	// is durable, the effect may have fired, but the result was never checkpointed.
	if err := h.runner.save(graph.NewState("send"), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := h.runner.store.BeginIntent(h.runID, h.key, checkpoint.Intent{NodeID: "send", IdempotencyKey: "k", ArgsHash: "a"}); err != nil {
		t.Fatal(err)
	}
	out, err := h.runner.resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if exec.called("send") {
		t.Fatal("resume re-fired a side-effecting node that was already in-flight (double-fire)")
	}
	if out.Reason != "terminate" {
		t.Fatalf("expected the skipped node to advance to termination, got %q", out.Reason)
	}
}

func TestRunGraph_ResumeIdentityBound(t *testing.T) {
	exec := newFakeExec()
	h := newHarness(t, sendDef(), allowAll(0), exec, 500000)
	if err := h.runner.save(graph.NewState("send"), nil, "pending"); err != nil {
		t.Fatal(err)
	}
	// A different identity attempts to resume the parked run.
	attacker := *h.runner
	attacker.caller = egress.Caller{PeerFQDN: "attacker.mesh", PeerKey: "attacker-key"}
	if _, err := attacker.resume(context.Background()); !errors.Is(err, checkpoint.ErrIdentityMismatch) {
		t.Fatalf("resume must be identity-bound; got %v", err)
	}
}

func readCheckpoint(t *testing.T, dir, runID string) checkpoint.Checkpoint {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, runID+".json"))
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	var cp checkpoint.Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		t.Fatalf("parse checkpoint: %v", err)
	}
	return cp
}
