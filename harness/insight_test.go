package harness

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// TestTunerRecommendsFromAudit asserts the harness can feed its own audit stream
// through insight to produce a tightened allowlist and simulate it without error
// — the §9.3 adaptive-tuning loop, end to end.
func TestTunerRecommendsFromAudit(t *testing.T) {
	var buf bytes.Buffer
	al := policy.NewAuditLog(&buf, fixedClock())
	eng := NewEngine(EngineOpts{Audit: al, Now: func() time.Time { return time.Unix(0, 0) }})

	// Generate real governed traffic.
	for i := 0; i < 3; i++ {
		if _, err := eng.Run(context.Background(), RunRequest{Goal: "do work", Mode: ModeQuick, Actor: Identity{Key: "k"}}); err != nil {
			t.Fatalf("run: %v", err)
		}
	}

	tuner := NewTuner(CompilePolicy(nil))
	candidate, notes, err := tuner.Recommend(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("recommend: %v", err)
	}
	if candidate == nil {
		t.Fatal("recommend produced no policy")
	}
	if candidate.DefaultAllow {
		t.Fatal("a recommended policy must remain default-deny")
	}
	_ = notes

	sim, err := tuner.Simulate(bytes.NewReader(buf.Bytes()), candidate)
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if sim.Total == 0 {
		t.Fatal("simulate saw no decisions")
	}
}
