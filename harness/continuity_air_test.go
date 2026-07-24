package harness

import (
	"testing"

	"github.com/xrey167/meshmcp/air/checkpoint"
)

// TestAirContinuityRoundtrip exercises the air/checkpoint-backed continuity
// store: save/load under the creator key, refusal under a different key, missing
// runs, and rejection of an unsafe run id (path-traversal defense).
func TestAirContinuityRoundtrip(t *testing.T) {
	store, err := checkpoint.New(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("checkpoint store: %v", err)
	}
	ac := NewAirContinuity(store)

	state := RunState{ID: "run-abc", Goal: "ship it", Status: RunRunning, Stage: StagePlan, GoalMet: false}
	if err := ac.Save(state, "owner-key"); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, ok, err := ac.Load("run-abc", "owner-key")
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if got.Goal != "ship it" || got.Stage != StagePlan {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	// A different key must be refused (identity binding).
	if _, _, err := ac.Load("run-abc", "intruder"); err == nil {
		t.Fatal("load under a different key must be refused")
	}

	// A missing run is ok=false, no error.
	if _, ok, err := ac.Load("run-missing", "owner-key"); ok || err != nil {
		t.Fatalf("missing run: ok=%v err=%v", ok, err)
	}

	// An unsafe run id must be rejected (path traversal defense in air/checkpoint).
	if err := ac.Save(RunState{ID: "../../etc/evil", Goal: "x"}, "owner-key"); err == nil {
		t.Fatal("an unsafe run id must be rejected")
	}

	// Overwriting under a different key is refused.
	if err := ac.Save(RunState{ID: "run-abc", Goal: "hijack"}, "other-key"); err == nil {
		t.Fatal("overwriting another identity's run must be refused")
	}
}
