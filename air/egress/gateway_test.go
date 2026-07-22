package egress

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

// caller is the fixed acting identity used across these tests.
var caller = Caller{PeerFQDN: "agent.netbird.cloud", PeerKey: "agent-key"}

// newAudit returns an AuditLog over buf with a fixed clock, so the emitted
// chain is deterministic and verifiable with policy.VerifyChain.
func newAudit(buf *bytes.Buffer) *policy.AuditLog {
	return policy.NewAuditLog(buf, func() string { return "2026-07-22T00:00:00Z" })
}

// okExec is an execute callback that succeeds, recording that it ran.
func okExec(ran *bool) func() ([]byte, error) {
	return func() ([]byte, error) {
		*ran = true
		return []byte("ok"), nil
	}
}

// TestAllowPath proves an allowed call executes, spends its cost, merges its
// emitted labels into the run taint set, audits an allow, and returns the result.
func TestAllowPath(t *testing.T) {
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"read_customer"}, Allow: true,
			EmitLabels: []string{"pii"}, Rate: &policy.RateLimit{Max: 100, Per: "24h", Cost: 5}},
	}}
	var buf bytes.Buffer
	g := NewGateway(policy.NewEngine(pol, nil, nil), newAudit(&buf), 100)

	var ran bool
	dec, result, err := g.Call(caller, "kb", "read_customer", nil, okExec(&ran))
	if err != nil {
		t.Fatalf("allow call errored: %v", err)
	}
	if !ran {
		t.Fatal("execute was not run on an allow")
	}
	if dec.Outcome != policy.OutcomeAllow {
		t.Fatalf("outcome = %v, want allow", dec.Outcome)
	}
	if string(result) != "ok" {
		t.Fatalf("result = %q, want ok", result)
	}
	if g.Spent() != 5 {
		t.Fatalf("spent = %d, want 5", g.Spent())
	}
	if !g.Labels()["pii"] {
		t.Fatalf("taint set missing pii label: %v", g.Labels())
	}
	if g.Remaining() != 95 {
		t.Fatalf("remaining = %d, want 95", g.Remaining())
	}
	assertChain(t, &buf, 1)
}

// TestDenyPath proves a denied call does not execute, spends nothing, adds no
// taint, audits a deny, and returns a deny error.
func TestDenyPath(t *testing.T) {
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"deploy"}, Allow: false},
	}}
	var buf bytes.Buffer
	g := NewGateway(policy.NewEngine(pol, nil, nil), newAudit(&buf), 100)

	var ran bool
	dec, result, err := g.Call(caller, "kb", "deploy", nil, okExec(&ran))
	if err == nil {
		t.Fatal("deny call should return an error")
	}
	if ran {
		t.Fatal("execute ran on a deny")
	}
	if dec.Outcome != policy.OutcomeDeny || result != nil {
		t.Fatalf("dec=%+v result=%v, want deny/nil", dec, result)
	}
	if g.Spent() != 0 || len(g.Labels()) != 0 {
		t.Fatalf("deny mutated state: spent=%d labels=%v", g.Spent(), g.Labels())
	}
	assertChain(t, &buf, 1)
}

// TestCosignPath proves a require_cosign call with no approval surfaces the
// cosign Decision without executing and without being treated as an error, so
// the caller can route it to the human co-sign flow.
func TestCosignPath(t *testing.T) {
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"transfer_funds"}, Allow: true, RequireCosign: true},
	}}
	var buf bytes.Buffer
	// No cosign store → the engine parks the call as OutcomeCosign.
	g := NewGateway(policy.NewEngine(pol, nil, nil), newAudit(&buf), 100)

	var ran bool
	dec, result, err := g.Call(caller, "kb", "transfer_funds", nil, okExec(&ran))
	if err != nil {
		t.Fatalf("cosign should not be an error, got %v", err)
	}
	if ran {
		t.Fatal("execute ran on a cosign")
	}
	if dec.Outcome != policy.OutcomeCosign || result != nil {
		t.Fatalf("dec=%+v result=%v, want cosign/nil", dec, result)
	}
	if g.Spent() != 0 {
		t.Fatalf("cosign spent %d, want 0", g.Spent())
	}
	assertChain(t, &buf, 1)
}

// TestBudgetBoundHaltsRunawayLoop is the headline bound: a sequence of allowed
// calls whose cumulative cost exceeds the cap has the breaching call HALTED
// (denied, not executed), after which no further spend occurs. This is what
// makes a runaway agent loop provably bounded.
func TestBudgetBoundHaltsRunawayLoop(t *testing.T) {
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"expensive"}, Allow: true,
			Rate: &policy.RateLimit{Max: 1000, Per: "24h", Cost: 10}},
	}}
	var buf bytes.Buffer
	g := NewGateway(policy.NewEngine(pol, nil, nil), newAudit(&buf), 25) // cap fits 2 calls (20), not 3 (30)

	execs := 0
	exec := func() ([]byte, error) { execs++; return []byte("x"), nil }

	// Calls 1 and 2 fit within the 25-unit cap (spend 10, then 20).
	for i := 0; i < 2; i++ {
		if _, _, err := g.Call(caller, "kb", "expensive", nil, exec); err != nil {
			t.Fatalf("call %d should be allowed, got %v", i+1, err)
		}
	}
	if g.Spent() != 20 || execs != 2 {
		t.Fatalf("after 2 calls: spent=%d execs=%d, want 20/2", g.Spent(), execs)
	}

	// Call 3 would push spend to 30 > 25: it must be HALTED, not executed.
	dec, result, err := g.Call(caller, "kb", "expensive", nil, exec)
	if err == nil || dec.Outcome != policy.OutcomeDeny || result != nil {
		t.Fatalf("breaching call not halted: dec=%+v result=%v err=%v", dec, result, err)
	}
	if execs != 2 {
		t.Fatalf("halted call still executed: execs=%d", execs)
	}
	if g.Spent() != 20 {
		t.Fatalf("halt changed spend: %d, want 20", g.Spent())
	}
	if g.Remaining() != 5 {
		t.Fatalf("remaining = %d, want 5", g.Remaining())
	}

	// A further attempt stays halted — the loop cannot spend past the cap.
	if _, _, err := g.Call(caller, "kb", "expensive", nil, exec); err == nil {
		t.Fatal("loop resumed spending after budget exhaustion")
	}
	if execs != 2 || g.Spent() != 20 {
		t.Fatalf("post-exhaustion drift: execs=%d spent=%d", execs, g.Spent())
	}
	assertChain(t, &buf, 4) // 2 allow + 2 deny records
}

// TestTaintPropagation proves taint from an earlier allowed call flows into a
// later call's decision: a first call emits the "tainted" label, and a second
// call to a taint-guarded tool is then DENIED because the run carries that
// label — enforced with a real policy, not a mocked engine.
func TestTaintPropagation(t *testing.T) {
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		// fetch brings untrusted content in → taints the run.
		{Peers: []string{"*"}, Tools: []string{"fetch"}, Allow: true, TaintSource: true},
		// write_file is privileged: guarded against a tainted run.
		{Peers: []string{"*"}, Tools: []string{"write_file"}, Allow: true, TaintGuard: true},
	}}
	var buf bytes.Buffer
	g := NewGateway(policy.NewEngine(pol, nil, nil), newAudit(&buf), 100)

	// Before any taint, write_file is allowed.
	var wrote bool
	if dec, _, err := g.Call(caller, "kb", "write_file", nil, okExec(&wrote)); err != nil || dec.Outcome != policy.OutcomeAllow {
		t.Fatalf("write_file before taint: dec=%+v err=%v", dec, err)
	}

	// fetch taints the run.
	var fetched bool
	if dec, _, err := g.Call(caller, "kb", "fetch", nil, okExec(&fetched)); err != nil || dec.Outcome != policy.OutcomeAllow {
		t.Fatalf("fetch: dec=%+v err=%v", dec, err)
	}
	if !g.Labels()["tainted"] {
		t.Fatalf("run not tainted after fetch: %v", g.Labels())
	}

	// Now write_file is DENIED: the accumulated taint flowed into its decision.
	var wroteAgain bool
	dec, _, err := g.Call(caller, "kb", "write_file", nil, okExec(&wroteAgain))
	if err == nil || dec.Outcome != policy.OutcomeDeny {
		t.Fatalf("write_file after taint should be denied, got dec=%+v err=%v", dec, err)
	}
	if wroteAgain {
		t.Fatal("guarded write executed despite taint")
	}
	assertChain(t, &buf, 3)
}

// TestExecuteFailureRefundsCost proves a governed call whose execute fails
// spends nothing and adds no taint — a failed call is as if it never happened.
func TestExecuteFailureRefundsCost(t *testing.T) {
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"flaky"}, Allow: true,
			EmitLabels: []string{"pii"}, Rate: &policy.RateLimit{Max: 100, Per: "24h", Cost: 7}},
	}}
	g := NewGateway(policy.NewEngine(pol, nil, nil), nil, 100)

	boom := errors.New("backend down")
	dec, result, err := g.Call(caller, "kb", "flaky", nil, func() ([]byte, error) { return nil, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("execute error not propagated: %v", err)
	}
	if dec.Outcome != policy.OutcomeAllow || result != nil {
		t.Fatalf("dec=%+v result=%v", dec, result)
	}
	if g.Spent() != 0 || len(g.Labels()) != 0 {
		t.Fatalf("failed execute left residue: spent=%d labels=%v", g.Spent(), g.Labels())
	}
}

// TestConcurrentCallsBounded proves the per-run mutex keeps spend and taint
// consistent under a concurrent fan-out: with a cap admitting exactly N calls,
// exactly N of many concurrent calls execute and spend lands on the cap — no
// double-spend, no lost taint.
func TestConcurrentCallsBounded(t *testing.T) {
	const perCall, admit, racers = 4, 10, 50
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"node"}, Allow: true,
			EmitLabels: []string{"work"}, Rate: &policy.RateLimit{Max: 100000, Per: "24h", Cost: perCall}},
	}}
	g := NewGateway(policy.NewEngine(pol, nil, nil), nil, perCall*admit)

	var mu sync.Mutex
	execs := 0
	exec := func() ([]byte, error) {
		mu.Lock()
		execs++
		mu.Unlock()
		return nil, nil
	}

	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = g.Call(caller, "kb", "node", nil, exec)
		}()
	}
	wg.Wait()

	if execs != admit {
		t.Fatalf("executed %d calls, want exactly %d admitted by budget", execs, admit)
	}
	if g.Spent() != perCall*admit {
		t.Fatalf("spent=%d, want %d (no double-spend)", g.Spent(), perCall*admit)
	}
	if g.Remaining() != 0 {
		t.Fatalf("remaining=%d, want 0", g.Remaining())
	}
	if !g.Labels()["work"] {
		t.Fatalf("taint lost under concurrency: %v", g.Labels())
	}
}

// TestRuleRateLimitNotBudgetHalt confirms the engine's own per-rule rate limit
// (a distinct control) still surfaces as a deny through the gateway, separate
// from the gateway's run-level budget halt.
func TestEngineRateLimitDeny(t *testing.T) {
	pol := &policy.Policy{DefaultAllow: false, Rules: []policy.Rule{
		{Peers: []string{"*"}, Tools: []string{"ping"}, Allow: true,
			Rate: &policy.RateLimit{Max: 1, Per: "24h"}},
	}}
	g := NewGateway(policy.NewEngine(pol, nil, nil), nil, 1000)

	var ran bool
	if _, _, err := g.Call(caller, "kb", "ping", nil, okExec(&ran)); err != nil {
		t.Fatalf("first ping should pass, got %v", err)
	}
	// Second call within the window exhausts the rule's rate bucket → deny.
	dec, _, err := g.Call(caller, "kb", "ping", nil, okExec(&ran))
	if err == nil || dec.Outcome != policy.OutcomeDeny {
		t.Fatalf("rate-limited call should deny, got dec=%+v err=%v", dec, err)
	}
}

// assertChain verifies the audit buffer holds an intact hash chain of wantN
// records, proving governed calls land on one tamper-evident ledger.
func assertChain(t *testing.T, buf *bytes.Buffer, wantN int) {
	t.Helper()
	res, err := policy.VerifyChain(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if !res.OK {
		t.Fatalf("audit chain broken at seq %d: %s", res.BreakSeq, res.Reason)
	}
	if res.Count != wantN {
		t.Fatalf("audit records = %d, want %d", res.Count, wantN)
	}
}
