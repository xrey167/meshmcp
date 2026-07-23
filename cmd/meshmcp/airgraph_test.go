package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
			audit:  audit,
		},
		audit: buf,
		dir:   dir,
		runID: "run-1",
		key:   key,
	}
}

// countAudit counts audit records in the harness chain matching every given
// substring (e.g. a method and a decision).
func (h *harness) countAudit(t *testing.T, subs ...string) int {
	t.Helper()
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(h.audit.String()), "\n") {
		ok := line != ""
		for _, s := range subs {
			if !strings.Contains(line, s) {
				ok = false
				break
			}
		}
		if ok {
			n++
		}
	}
	return n
}

// approvalStoreFor builds a signed request-bound approval store rooted in a
// temp dir, returning it plus its signer for granting.
func approvalStoreFor(t *testing.T) (*policy.FileApprovalStore, *policy.Signer) {
	t.Helper()
	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return policy.NewFileApprovalStore(t.TempDir(), time.Minute, signer), signer
}

// sendArgs is the canonical marshaled args of the sendDef node ({}), the bytes
// the runner binds approvals against.
func sendArgs(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// cosignPolicy holds the send tool for co-sign.
func cosignPolicy() *policy.Policy {
	return &policy.Policy{Rules: []policy.Rule{
		{Tools: []string{"send"}, Allow: true, RequireCosign: true},
	}}
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

// --- cosign release, wall-clock bound, graph.cosign verb (AG-1) --------------

// TestRunGraph_CosignParkEmitsGraphCosignVerb proves a park lands a
// graph.cosign record (decision cosign) on the chain and the chain verifies.
func TestRunGraph_CosignParkEmitsGraphCosignVerb(t *testing.T) {
	h := newHarness(t, sendDef(), cosignPolicy(), newFakeExec(), 500000)
	out, err := h.runner.start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !out.Parked {
		t.Fatalf("expected park, got %+v", out)
	}
	if n := h.countAudit(t, `"method":"graph.cosign"`, `"decision":"cosign"`); n != 1 {
		t.Fatalf("graph.cosign park records = %d, want 1\n%s", n, h.audit.String())
	}
	res, err := policy.VerifyChain(bytes.NewReader(h.audit.Bytes()))
	if err != nil || !res.OK {
		t.Fatalf("chain with graph.cosign record broken: %+v %v", res, err)
	}
}

// TestResume_ParkedStaysParkedWithoutApproval proves an unapproved resume
// re-parks without executing: the approval store is the ONLY release mechanism.
func TestResume_ParkedStaysParkedWithoutApproval(t *testing.T) {
	exec := newFakeExec()
	h := newHarness(t, sendDef(), cosignPolicy(), exec, 500000)
	if _, err := h.runner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	firstPending := func() string {
		var pr persistedRun
		cp := readCheckpoint(t, h.dir, h.runID)
		_ = json.Unmarshal(cp.State, &pr)
		return pr.Pending
	}()
	if firstPending == "" {
		t.Fatal("no pending binding after park")
	}

	out, err := h.runner.resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !out.Parked || out.Reason != "cosign" {
		t.Fatalf("unapproved resume must re-park: %+v", out)
	}
	if exec.called("send") {
		t.Fatal("unapproved resume executed the parked node")
	}
	var pr persistedRun
	cp := readCheckpoint(t, h.dir, h.runID)
	_ = json.Unmarshal(cp.State, &pr)
	if pr.Pending != firstPending {
		t.Fatalf("pending binding changed across unapproved resume: %q -> %q", firstPending, pr.Pending)
	}
}

// TestResume_ConsumedApprovalReleasesExactCall proves the release: an approval
// bound to the exact (peer, backend, tool, args, run) lets resume execute the
// node exactly once, terminate, and audit a graph.cosign allow release record.
func TestResume_ConsumedApprovalReleasesExactCall(t *testing.T) {
	exec := newFakeExec()
	h := newHarness(t, sendDef(), cosignPolicy(), exec, 500000)
	if _, err := h.runner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	store, _ := approvalStoreFor(t)
	h.runner.approvals = store

	// Grant the run-bound approval for the EXACT parked call.
	req := policy.NewApprovalRequest(h.key, "mail", "send", sendArgs(t), h.runID)
	if _, err := store.Grant(req, "operator@mesh", "", time.Now()); err != nil {
		t.Fatalf("grant: %v", err)
	}

	out, err := h.runner.resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Reason != "terminate" || out.Parked {
		t.Fatalf("released run must complete: %+v", out)
	}
	if exec.counts["send"] != 1 {
		t.Fatalf("released node fired %d times, want exactly once", exec.counts["send"])
	}
	if n := h.countAudit(t, `"method":"graph.cosign"`, `"decision":"allow"`); n != 1 {
		t.Fatalf("graph.cosign release records = %d, want 1\n%s", n, h.audit.String())
	}
	res, err := policy.VerifyChain(bytes.NewReader(h.audit.Bytes()))
	if err != nil || !res.OK {
		t.Fatalf("chain broken after release: %+v %v", res, err)
	}
}

// TestResume_SessionlessApprovalAlsoReleases proves interop with the standard
// approver flow, which mints approvals with Session unset
// (policy.Pending.ApprovalRequest): the same exact-argument binding releases.
func TestResume_SessionlessApprovalAlsoReleases(t *testing.T) {
	exec := newFakeExec()
	h := newHarness(t, sendDef(), cosignPolicy(), exec, 500000)
	if _, err := h.runner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	store, _ := approvalStoreFor(t)
	h.runner.approvals = store
	req := policy.NewApprovalRequest(h.key, "mail", "send", sendArgs(t), "") // approver shape
	if _, err := store.Grant(req, "operator@mesh", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	out, err := h.runner.resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Reason != "terminate" || exec.counts["send"] != 1 {
		t.Fatalf("session-less approval must release exactly once: %+v calls=%d", out, exec.counts["send"])
	}
}

// TestResume_ApprovalForDifferentArgsDoesNotRelease is the iteration-N vs N+1
// attack: an approval bound to DIFFERENT arguments must not release this call.
func TestResume_ApprovalForDifferentArgsDoesNotRelease(t *testing.T) {
	exec := newFakeExec()
	h := newHarness(t, sendDef(), cosignPolicy(), exec, 500000)
	if _, err := h.runner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	store, _ := approvalStoreFor(t)
	h.runner.approvals = store
	other := policy.NewApprovalRequest(h.key, "mail", "send", []byte(`{"amount":10000}`), h.runID)
	if _, err := store.Grant(other, "operator@mesh", "", time.Now()); err != nil {
		t.Fatal(err)
	}

	out, err := h.runner.resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !out.Parked || exec.called("send") {
		t.Fatalf("approval for different args released the call: %+v calls=%v", out, exec.calls)
	}
}

// TestResume_ApprovalIsSingleUse proves a spent approval cannot re-fire the
// node: after the released run completes, a further resume parks again with
// the executor still at one firing.
func TestResume_ApprovalIsSingleUse(t *testing.T) {
	exec := newFakeExec()
	h := newHarness(t, sendDef(), cosignPolicy(), exec, 500000)
	if _, err := h.runner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	store, _ := approvalStoreFor(t)
	h.runner.approvals = store
	req := policy.NewApprovalRequest(h.key, "mail", "send", sendArgs(t), h.runID)
	if _, err := store.Grant(req, "operator@mesh", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if out, err := h.runner.resume(context.Background()); err != nil || out.Reason != "terminate" {
		t.Fatalf("first resume: %+v %v", out, err)
	}
	// The terminated run's cursor still names the node; resuming again must
	// NOT re-fire — the approval is spent, so the call re-parks.
	out, err := h.runner.resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if exec.counts["send"] != 1 {
		t.Fatalf("spent approval re-fired the node: %d executions", exec.counts["send"])
	}
	if !out.Parked {
		t.Fatalf("post-release resume should re-park, got %+v", out)
	}
}

// exfilDef is a cosign-guarded fetch followed by an egress node — the
// released-taint scenario: if a release drops the fetch rule's taint, egress
// exfiltrates; if the lattice holds, egress is denied.
func exfilDef() *graph.Definition {
	return &graph.Definition{
		Name:   "exfil",
		Entry:  "fetch",
		Bounds: graph.BoundsDef{MaxIterations: 5},
		Nodes: []graph.NodeDef{
			{ID: "fetch", Backend: "web", Tool: "fetch_sensitive", Edges: []graph.EdgeDef{{To: "leak"}}},
			{ID: "leak", Backend: "mail", Tool: "egress", Edges: []graph.EdgeDef{{To: graph.Terminate}}},
		},
	}
}

// TestResume_ReleasedCosignCallStillTaints closes the release taint bypass: a
// rule that is BOTH require_cosign and taint_source must taint the run when a
// human releases it, so a downstream taint-guarded egress node is still denied.
// Before the fix the release folded the engine's label-free cosign verdict
// directly, and the egress node exfiltrated untainted.
func TestResume_ReleasedCosignCallStillTaints(t *testing.T) {
	exec := newFakeExec()
	pol := &policy.Policy{Rules: []policy.Rule{
		{Tools: []string{"fetch_sensitive"}, Allow: true, RequireCosign: true, TaintSource: true},
		{Tools: []string{"egress"}, Allow: true, TaintGuard: true},
	}}
	h := newHarness(t, exfilDef(), pol, exec, 500000)
	if out, err := h.runner.start(context.Background()); err != nil || !out.Parked {
		t.Fatalf("fetch must park first: %+v %v", out, err)
	}
	store, _ := approvalStoreFor(t)
	h.runner.approvals = store
	req := policy.NewApprovalRequest(h.key, "web", "fetch_sensitive", sendArgs(t), h.runID)
	if _, err := store.Grant(req, "operator@mesh", "", time.Now()); err != nil {
		t.Fatal(err)
	}

	out, err := h.runner.resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if exec.counts["fetch_sensitive"] != 1 {
		t.Fatalf("released fetch fired %d times, want exactly 1", exec.counts["fetch_sensitive"])
	}
	if out.Reason != "deny" || out.Node != "leak" {
		t.Fatalf("taint-guarded egress after release must deny at leak, got %+v", out)
	}
	if exec.called("egress") {
		t.Fatal("EXFILTRATION: egress executed after a released taint_source call (taint dropped on release)")
	}
	if !out.State.Labels["tainted"] {
		t.Fatalf("released call's taint missing from the state mirror: %v", out.State.Labels)
	}
	if !h.runner.gw.Labels()["tainted"] {
		t.Fatalf("released call's taint missing from the gateway: %v", h.runner.gw.Labels())
	}
}

// TestResume_ReleasedCosignCallSpendsRuleCost closes the release budget bypass:
// the released call's rule cost lands in BOTH the gateway spend and the state
// cost mirror (which prices resume budgets), instead of executing for free.
func TestResume_ReleasedCosignCallSpendsRuleCost(t *testing.T) {
	exec := newFakeExec()
	pol := &policy.Policy{Rules: []policy.Rule{
		{Tools: []string{"send"}, Allow: true, RequireCosign: true,
			Rate: &policy.RateLimit{Max: 1000, Per: "1h", Cost: 7}},
	}}
	h := newHarness(t, sendDef(), pol, exec, 500000)
	if _, err := h.runner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	store, _ := approvalStoreFor(t)
	h.runner.approvals = store
	req := policy.NewApprovalRequest(h.key, "mail", "send", sendArgs(t), h.runID)
	if _, err := store.Grant(req, "operator@mesh", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	out, err := h.runner.resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Reason != "terminate" || exec.counts["send"] != 1 {
		t.Fatalf("release should complete exactly once: %+v calls=%d", out, exec.counts["send"])
	}
	if got := h.runner.gw.Spent(); got != 7 {
		t.Fatalf("released call spent %d against the gateway budget, want 7", got)
	}
	if out.State.Cost != 7 {
		t.Fatalf("released call mirrored cost %d into state, want 7", out.State.Cost)
	}
}

// TestResume_ReleasedCosignCallBudgetHalted proves the run budget outranks a
// human release: a released call whose cost would breach the cap is halted
// unexecuted with reason "budget" and spends nothing.
func TestResume_ReleasedCosignCallBudgetHalted(t *testing.T) {
	exec := newFakeExec()
	pol := &policy.Policy{Rules: []policy.Rule{
		{Tools: []string{"send"}, Allow: true, RequireCosign: true,
			Rate: &policy.RateLimit{Max: 1000, Per: "1h", Cost: 7}},
	}}
	h := newHarness(t, sendDef(), pol, exec, 5) // cap 5 < released cost 7
	if _, err := h.runner.start(context.Background()); err != nil {
		t.Fatal(err)
	}
	store, _ := approvalStoreFor(t)
	h.runner.approvals = store
	req := policy.NewApprovalRequest(h.key, "mail", "send", sendArgs(t), h.runID)
	if _, err := store.Grant(req, "operator@mesh", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	out, err := h.runner.resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Reason != "budget" || out.Node != "send" {
		t.Fatalf("released call breaching the cap must halt as budget, got %+v", out)
	}
	if exec.called("send") {
		t.Fatal("budget-halted release executed the tool")
	}
	if h.runner.gw.Spent() != 0 {
		t.Fatalf("halted release spent %d, want 0", h.runner.gw.Spent())
	}
}

// TestResume_PendingKeyMismatchRefused proves a drifted parked binding
// (definition/arguments no longer produce the persisted Pending key) refuses to
// resume rather than silently re-deciding a different call.
func TestResume_PendingKeyMismatchRefused(t *testing.T) {
	exec := newFakeExec()
	h := newHarness(t, sendDef(), cosignPolicy(), exec, 500000)
	if err := h.runner.save(graph.NewState("send"), nil, "tampered-binding-key"); err != nil {
		t.Fatal(err)
	}
	_, err := h.runner.resume(context.Background())
	if err == nil || !strings.Contains(err.Error(), "binding mismatch") {
		t.Fatalf("drifted pending binding must refuse resume, got %v", err)
	}
	if exec.called("send") {
		t.Fatal("refused resume executed the node")
	}
}

// TestRunGraph_WallClockTimeoutCheckpointsAndTerminates proves the wall-clock
// bound: an expired context stops the run with reason "timeout", audited, with
// a checkpoint on disk — and a later resume under a fresh context completes.
func TestRunGraph_WallClockTimeoutCheckpointsAndTerminates(t *testing.T) {
	exec := newFakeExec()
	h := newHarness(t, sendDef(), allowAll(0), exec, 500000)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already expired: the bound trips before any governed call
	out, err := h.runner.start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Reason != "timeout" {
		t.Fatalf("expired context must stop with timeout, got %q", out.Reason)
	}
	if exec.called("send") {
		t.Fatal("timed-out run executed a node")
	}
	if n := h.countAudit(t, "wall_clock", `"decision":"deny"`); n != 1 {
		t.Fatalf("wall-clock stop not audited: %d\n%s", n, h.audit.String())
	}
	// Resumable: the checkpoint exists and a fresh context completes the run.
	if _, err := os.Stat(filepath.Join(h.dir, h.runID+".json")); err != nil {
		t.Fatalf("no checkpoint after timeout: %v", err)
	}
	out, err = h.runner.resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Reason != "terminate" || !exec.called("send") {
		t.Fatalf("post-timeout resume must complete: %+v", out)
	}
}

// TestRunGraph_ZeroTimeoutCoercedToDefault proves the fail-closed coercion: a
// zero/negative wall-clock config becomes the default, never unbounded.
func TestRunGraph_ZeroTimeoutCoercedToDefault(t *testing.T) {
	if got := graphTimeout(0); got != defaultGraphTimeout {
		t.Fatalf("graphTimeout(0) = %v, want %v", got, defaultGraphTimeout)
	}
	if got := graphTimeout(-5 * time.Second); got != defaultGraphTimeout {
		t.Fatalf("graphTimeout(-5s) = %v, want %v", got, defaultGraphTimeout)
	}
	if got := graphTimeout(3 * time.Second); got != 3*time.Second {
		t.Fatalf("graphTimeout(3s) = %v, want 3s", got)
	}
}

// TestRunGraph_PolicyConsultedEveryHop proves no hop runs on a cached verdict:
// with a rate limit admitting exactly 3 calls, the run halts at precisely the
// 4th hop with exactly 4 governed-call audit records (3 allow + 1 deny).
func TestRunGraph_PolicyConsultedEveryHop(t *testing.T) {
	exec := newFakeExec()
	exec.fixed["critic"] = []byte(`{"ok": false}`) // never converges
	pol := &policy.Policy{Rules: []policy.Rule{
		{Tools: []string{"*"}, Allow: true, Rate: &policy.RateLimit{Max: 3, Per: "1h", Cost: 1}},
	}}
	h := newHarness(t, reflectDef(), pol, exec, 500000)
	out, err := h.runner.start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Reason != "deny" {
		t.Fatalf("rate exhaustion must deny, got %q", out.Reason)
	}
	if out.State.Iter != 3 {
		t.Fatalf("run advanced %d hops before the deny, want exactly 3", out.State.Iter)
	}
	allows := h.countAudit(t, `"method":"graph.node-enter"`, `"decision":"allow"`)
	denies := h.countAudit(t, `"method":"graph.node-enter"`, `"decision":"deny"`)
	if allows != 3 || denies != 1 {
		t.Fatalf("governed-call records = %d allow / %d deny, want 3/1 (every hop freshly decided)\n%s", allows, denies, h.audit.String())
	}
}

// TestResume_TaintSeededFromCheckpoint proves the taint lattice survives a
// resume: persisted labels re-seed the fresh gateway, so a pii label from
// before the crash still blocks a pii-forbidding egress node afterward.
func TestResume_TaintSeededFromCheckpoint(t *testing.T) {
	exec := newFakeExec()
	def := &graph.Definition{
		Name:   "leaky",
		Entry:  "leak",
		Bounds: graph.BoundsDef{MaxIterations: 5},
		Nodes: []graph.NodeDef{
			{ID: "leak", Backend: "mail", Tool: "egress", Edges: []graph.EdgeDef{{To: graph.Terminate}}},
		},
	}
	pol := &policy.Policy{Rules: []policy.Rule{
		{Tools: []string{"egress"}, Allow: true, BlockLabels: []string{"pii"}},
		{Tools: []string{"*"}, Allow: true},
	}}
	h := newHarness(t, def, pol, exec, 500000)

	// Persist a checkpoint whose state already carries the pii taint (as if an
	// earlier node had emitted it before the crash).
	tainted := graph.GraphState{
		Cursor: "leak",
		Data:   map[string]any{},
		Labels: map[string]bool{"pii": true},
	}
	if err := h.runner.save(tainted, nil, ""); err != nil {
		t.Fatal(err)
	}

	out, err := h.runner.resume(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Reason != "deny" || out.Node != "leak" {
		t.Fatalf("persisted taint must block egress after resume, got %+v", out)
	}
	if exec.called("egress") {
		t.Fatal("tainted egress executed after resume (taint lattice lost across restart)")
	}
}
