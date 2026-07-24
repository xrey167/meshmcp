package harness

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/xrey167/meshmcp/harness/provider"
)

// TestMagicWordDeterministic is the regression for the map-range nondeterminism:
// a goal containing several magic words must classify to the SAME mode every
// time (first match in the fixed precedence wins), so the audited intent decision
// is reproducible across replays.
func TestMagicWordDeterministic(t *testing.T) {
	g := NewIntentGate(nil, nil)
	goal := "please ralph and autopilot this and synthesize — ultrawork it"
	first := g.Classify(context.Background(), goal, "", "").Mode
	// "ultrawork" is first in the precedence list, so it must win over the others.
	if first != ModeUltrawork {
		t.Fatalf("first-precedence magic word (ultrawork) must win, got %s", first)
	}
	for i := 0; i < 200; i++ {
		if got := g.Classify(context.Background(), goal, "", "").Mode; got != first {
			t.Fatalf("magic-word resolution is nondeterministic: %s != %s", got, first)
		}
	}
}

// TestMemContinuityDeepCopy is the regression for aliased state in the in-memory
// store: neither a caller mutating the saved value nor a caller mutating a loaded
// value may reach into the persisted snapshot.
func TestMemContinuityDeepCopy(t *testing.T) {
	c := NewMemContinuity()
	st := RunState{
		ID:      "r1",
		Labels:  []string{"a"},
		Workers: []Worker{{Role: RoleExecutor, RunID: "r1"}},
	}
	if err := c.Save(st, "k"); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Mutate the caller's copy AFTER save — the store must be unaffected.
	st.Labels[0] = "MUTATED"
	st.Workers[0].Role = RoleJunior

	got, ok, err := c.Load("r1", "k")
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if got.Labels[0] != "a" {
		t.Fatalf("saved snapshot aliased the caller's slice: label=%q", got.Labels[0])
	}
	if got.Workers[0].Role != RoleExecutor {
		t.Fatalf("saved snapshot aliased the caller's worker slice: role=%q", got.Workers[0].Role)
	}
	// Mutate the LOADED copy — a second load must still be clean.
	got.Labels[0] = "X"
	got2, _, _ := c.Load("r1", "k")
	if got2.Labels[0] != "a" {
		t.Fatalf("loaded copy aliased the store: label=%q", got2.Labels[0])
	}
}

// TestUltragoalCheckFailsClosedOnEmptyVerdict is the regression for the fail-open
// durable check: a blank verdict (a soft provider failure) must NOT be treated as
// "goal met", even when evidence is present.
func TestUltragoalCheckFailsClosedOnEmptyVerdict(t *testing.T) {
	reg := provider.NewRegistry()
	blank := provider.NewMock("blank", "opus-class")
	blank.Reply = func(in provider.Prompt) string { return "   " } // whitespace only
	reg.Register(blank)
	v := NewVerifier(reg)

	met, gaps, err := v.UltragoalCheck(context.Background(), "opus-class", "ship it", []string{"tests pass"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if met {
		t.Fatal("a blank verifier verdict must fail closed (goal NOT met), not pass silently")
	}
	if len(gaps) == 0 {
		t.Fatal("a not-met result should report a gap")
	}

	// Positive control: a normal non-empty verdict with evidence still converges
	// (the mock pipeline must not be broken by the fail-closed tightening).
	reg2 := provider.NewRegistry()
	reg2.Register(provider.NewMock("ok", "opus-class"))
	if met, _, _ := NewVerifier(reg2).UltragoalCheck(context.Background(), "opus-class", "ship it", []string{"tests pass"}); !met {
		t.Fatal("a well-formed run with evidence must still be reported as met")
	}
}

// TestReviewWorkClampsReviewers is the regression for the unbounded fan-out: a
// caller-supplied reviewer count is clamped so it cannot launch an arbitrary
// number of provider invocations.
func TestReviewWorkClampsReviewers(t *testing.T) {
	reg := provider.NewRegistry()
	var calls int64
	m := provider.NewMock("m", "opus-class")
	m.Reply = func(in provider.Prompt) string { atomic.AddInt64(&calls, 1); return "clean" }
	reg.Register(m)
	v := NewVerifier(reg)

	if _, _, err := v.ReviewWork(context.Background(), "run", "opus-class", "scope", 100000); err != nil {
		t.Fatalf("review: %v", err)
	}
	if n := atomic.LoadInt64(&calls); n != maxReviewers {
		t.Fatalf("reviewer count must be clamped to %d, but %d invocations ran", maxReviewers, n)
	}
}
