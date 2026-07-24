package harness

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/harness/sandbox"
	"github.com/xrey167/meshmcp/policy"
)

// TestHighRiskCosignNotBypassable is the regression for the co-sign bypass:
// calling Advance again on a blocked high-risk run WITHOUT an approval must stay
// blocked (re-running approve), never fall through to execute.
func TestHighRiskCosignNotBypassable(t *testing.T) {
	var buf bytes.Buffer
	al := policy.NewAuditLog(&buf, fixedClock())
	cos := policy.NewMemCosign()
	eng := NewEngine(EngineOpts{Audit: al, Cosign: cos, Now: func() time.Time { return time.Unix(0, 0) }})

	id, err := eng.Start(context.Background(), RunRequest{
		Goal: "deploy the migration to production and drop the old table", Mode: ModeTeam, Actor: Identity{Key: "k"},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	st, _ := eng.Advance(context.Background(), id)
	if st.Status != RunBlocked || st.Stage != StageApprove {
		t.Fatalf("first advance should block AT approve, got status=%s stage=%s (risk=%s)", st.Status, st.Stage, st.Risk)
	}
	// Advance again with NO approval — must remain blocked, not execute.
	st, _ = eng.Advance(context.Background(), id)
	if st.Status != RunBlocked {
		t.Fatalf("re-advancing without a co-sign must stay blocked (bypass!), got %s stage=%s goal_met=%v", st.Status, st.Stage, st.GoalMet)
	}
	if len(st.Workers) != 0 {
		t.Fatalf("execute must not have run without co-sign, but %d worker(s) spawned", len(st.Workers))
	}
	// Now approve → the run completes.
	cos.Approve(policy.CosignKey(st.Actor.FQDN, "start_work"))
	st, _ = eng.Advance(context.Background(), id)
	if st.Status != RunDone {
		t.Fatalf("after co-sign the run should complete, got %s", st.Status)
	}
}

// TestSynthesizeHasApproveStage is the regression for synthesize skipping approve.
func TestSynthesizeHasApproveStage(t *testing.T) {
	found := false
	for _, s := range stagesFor(ModeSynthesize) {
		if s == StageApprove {
			found = true
		}
	}
	if !found {
		t.Fatal("synthesize mode must include the approve co-sign gate")
	}
}

// TestSchedulerUniqueOrdinals is the regression for colliding worker ordinals:
// concurrent fan-out must mint unique FQDNs. Runs under -race to also cover the
// Fan wait-for-inflight fix.
func TestSchedulerUniqueOrdinals(t *testing.T) {
	gov := NewGovernor(CompilePolicy(nil), nil, nil, func() time.Time { return time.Unix(0, 0) })
	minter := NewMemMinter()
	sched := NewScheduler(gov, minter, defaultMockRegistry(), sandbox.Spec{Kind: "local", Root: "."})
	run := RunState{ID: "run-x", Actor: Identity{Key: "k", FQDN: "orchestrator--run-x--0", Role: RoleOrchestrator}, Category: CatDeep, Mode: ModeTeam}
	tasks := make([]Task, 24)
	for i := range tasks {
		tasks[i] = Task{ID: fmt.Sprintf("t%d", i), Title: "do"}
	}
	results, err := sched.Fan(context.Background(), run, tasks, RoleExecutor, "gpt-medium", 8, nil)
	if err != nil {
		t.Fatalf("fan: %v", err)
	}
	if len(results) != len(tasks) {
		t.Fatalf("expected %d results, got %d", len(tasks), len(results))
	}
	seen := map[string]bool{}
	minted := sched.Minted()
	for _, w := range minted {
		if seen[w.Identity.FQDN] {
			t.Fatalf("duplicate worker FQDN: %s", w.Identity.FQDN)
		}
		seen[w.Identity.FQDN] = true
	}
	if len(minted) != len(tasks) {
		t.Fatalf("expected %d minted workers, got %d", len(tasks), len(minted))
	}
}

// TestObserveCancelNoRace is the regression for emit racing Observe's cancel:
// advancing while cancelling the observation must not panic (send on a closed
// channel) — validated under -race.
func TestObserveCancelNoRace(t *testing.T) {
	eng := NewEngine(EngineOpts{Now: func() time.Time { return time.Unix(0, 0) }})
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		id, err := eng.Start(context.Background(), RunRequest{Goal: "do work", Mode: ModeQuick, Actor: Identity{Key: "k"}})
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		ch, cancel := eng.Observe(id)
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range ch {
			}
		}()
		go func() { defer wg.Done(); _, _ = eng.Advance(context.Background(), id) }()
		cancel() // cancel concurrently with the advancing emits
	}
	wg.Wait()
}

// TestTaintGuardBlocksEgress is the regression for the missing taint guard:
// a tainted session is denied egress tools it would otherwise be allowed.
func TestTaintGuardBlocksEgress(t *testing.T) {
	eng := policy.NewEngine(CompilePolicy(nil), nil, nil)
	tainted := map[string]bool{LabelTainted: true}

	// orchestrator/synthesize (net.egress): allowed clean, denied when tainted.
	oFQDN := "orchestrator--r--0"
	if d := eng.DecideToolCall(oFQDN, "k", "synthesize", nil); d.Outcome != policy.OutcomeAllow {
		t.Fatalf("clean synthesize should be allowed, got %s", d.Outcome)
	}
	if d := eng.DecideToolCall(oFQDN, "k", "synthesize", tainted); d.Outcome == policy.OutcomeAllow {
		t.Fatalf("tainted synthesize must be blocked (prompt-injection guard)")
	}

	// explorer/search (net.egress): allowed clean, denied when tainted.
	eFQDN := "explorer--r--0"
	if d := eng.DecideToolCall(eFQDN, "k", "search", nil); d.Outcome != policy.OutcomeAllow {
		t.Fatalf("clean search should be allowed, got %s", d.Outcome)
	}
	if d := eng.DecideToolCall(eFQDN, "k", "search", tainted); d.Outcome == policy.OutcomeAllow {
		t.Fatalf("tainted search must be blocked")
	}
	// A non-egress read tool is unaffected by taint.
	if d := eng.DecideToolCall(eFQDN, "k", "grep", tainted); d.Outcome != policy.OutcomeAllow {
		t.Fatalf("tainted must not block a non-egress read tool like grep, got %s", d.Outcome)
	}
}
