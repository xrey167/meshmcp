package harness

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// fixedClock returns a deterministic RFC3339 timestamp source for the audit log.
func fixedClock() func() string {
	return func() string { return "2026-07-23T00:00:00Z" }
}

// newTestEngine builds an engine with an in-memory audit log we can verify.
func newTestEngine(t *testing.T) (*Engine, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, fixedClock())
	eng := NewEngine(EngineOpts{
		Audit: audit,
		Now:   func() time.Time { return time.Unix(0, 0) },
	})
	return eng, &buf
}

// TestGoldenPipelineTeam runs a full team-mode run against mock providers and
// asserts it settles, the goal is met, the audit chain verifies, and every
// worker was retired.
func TestGoldenPipelineTeam(t *testing.T) {
	eng, buf := newTestEngine(t)
	st, err := eng.Run(context.Background(), RunRequest{
		Goal:  "add a health check endpoint to the server",
		Mode:  ModeTeam,
		Actor: Identity{Key: "principal-key"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if st.Status != RunDone {
		t.Fatalf("status = %s, want done (err=%s)", st.Status, st.Error)
	}
	if !st.GoalMet {
		t.Fatalf("goal not met")
	}
	if st.Plan == nil || len(st.Plan.Steps) == 0 {
		t.Fatalf("expected a plan with steps")
	}
	// Every minted worker must be retired (identity sealed) at settle.
	minter := eng.minter.(*MemMinter)
	for _, w := range st.Workers {
		if minter.Active(w.Identity.Key) {
			t.Fatalf("worker %s left un-retired", w.Identity.FQDN)
		}
	}
	// The audit chain must verify end to end.
	res, err := policy.VerifyChain(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("audit chain broke at seq %d: %s", res.BreakSeq, res.Reason)
	}
	if res.Count == 0 {
		t.Fatal("expected audit records")
	}
}

// TestQuickModeSkipsInterview asserts quick mode skips the interview/plan-review
// stages (no requirements artifact) yet still settles.
func TestQuickModeSkipsInterview(t *testing.T) {
	eng, _ := newTestEngine(t)
	st, err := eng.Run(context.Background(), RunRequest{
		Goal:  "fix a typo in the readme",
		Mode:  ModeQuick,
		Actor: Identity{Key: "k"},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if st.Status != RunDone {
		t.Fatalf("status=%s", st.Status)
	}
	if st.Requirements != nil {
		t.Fatalf("quick mode should not run an interview")
	}
}

// TestRalphLoopTerminates asserts a ralph run converges (stops) within budget.
func TestRalphLoopTerminates(t *testing.T) {
	eng, _ := newTestEngine(t)
	st, err := eng.Run(context.Background(), RunRequest{
		Goal:   "keep improving until the tests pass",
		Mode:   ModeRalph,
		Actor:  Identity{Key: "k"},
		Budget: Budget{LoopRounds: 5, RetryPerRun: 10},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if st.Status != RunDone {
		t.Fatalf("status=%s err=%s", st.Status, st.Error)
	}
	if st.Rounds == 0 {
		t.Fatalf("ralph should record loop rounds")
	}
	if st.StopReason == "" {
		t.Fatalf("ralph should record a stop reason")
	}
}

// TestHighRiskBlocksOnCosign asserts a high-risk run parks on the approve gate
// until a human co-signs, then completes.
func TestHighRiskBlocksOnCosign(t *testing.T) {
	var buf bytes.Buffer
	audit := policy.NewAuditLog(&buf, fixedClock())
	cos := policy.NewMemCosign()
	eng := NewEngine(EngineOpts{Audit: audit, Cosign: cos, Now: func() time.Time { return time.Unix(0, 0) }})

	id, err := eng.Start(context.Background(), RunRequest{
		Goal:  "deploy the migration to production and drop the old table",
		Mode:  ModeTeam,
		Actor: Identity{Key: "k"},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	st, err := eng.Advance(context.Background(), id)
	if err != nil {
		t.Fatalf("advance: %v", err)
	}
	if st.Status != RunBlocked {
		t.Fatalf("high-risk run should block on co-sign, got %s (risk=%s)", st.Status, st.Risk)
	}
	// Co-sign and resume.
	cos.Approve(policy.CosignKey(st.Actor.FQDN, "start_work"))
	st, err = eng.Advance(context.Background(), id)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if st.Status != RunDone {
		t.Fatalf("after co-sign, run should complete, got %s", st.Status)
	}
	if res, _ := policy.VerifyChain(bytes.NewReader(buf.Bytes())); !res.OK {
		t.Fatalf("audit chain broke: %s", res.Reason)
	}
}

// TestStopContinuationGuard asserts a cancelled run cannot silently resume.
func TestStopContinuationGuard(t *testing.T) {
	eng, _ := newTestEngine(t)
	id, err := eng.Start(context.Background(), RunRequest{Goal: "long task", Mode: ModeTeam, Actor: Identity{Key: "k"}})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := eng.Cancel(context.Background(), id, "operator stop"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := eng.Advance(context.Background(), id); err == nil || !strings.Contains(err.Error(), "stop-continuation") {
		t.Fatalf("advance after cancel should be refused by the stop-continuation guard, got %v", err)
	}
}

// TestContinuityRoundtrip asserts run state persists and reloads under the
// creator key and is refused under a different key.
func TestContinuityRoundtrip(t *testing.T) {
	cont := NewMemContinuity()
	state := RunState{ID: "run-x", Goal: "g", Status: RunRunning, Stage: StagePlan}
	if err := cont.Save(state, "owner"); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, ok, err := cont.Load("run-x", "owner")
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if got.Goal != "g" || got.Stage != StagePlan {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if _, _, err := cont.Load("run-x", "intruder"); err == nil {
		t.Fatalf("load under a different key must be refused")
	}
}
