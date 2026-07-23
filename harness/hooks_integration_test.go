package harness

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/harness/hooks"
	"github.com/xrey167/meshmcp/policy"
)

// blockTool is a test hook that blocks a single named tool at pre-tool.
type blockTool struct{ tool string }

func (b blockTool) Name() string          { return "block-" + b.tool }
func (b blockTool) Phases() []hooks.Phase { return []hooks.Phase{hooks.PreTool} }
func (b blockTool) Handle(e hooks.Event) hooks.Effect {
	if e.Tool == b.tool {
		return hooks.Effect{Kind: hooks.Block, Reason: "blocked by test hook"}
	}
	return hooks.Cont
}

// TestHookLayerBlocksStage asserts an engine-wired hook can veto an
// otherwise-policy-allowed stage, and the veto surfaces as a run failure.
func TestHookLayerBlocksStage(t *testing.T) {
	var buf bytes.Buffer
	al := policy.NewAuditLog(&buf, fixedClock())
	chain := hooks.NewChain(true, nil)
	chain.Add(blockTool{tool: "review_work"})

	eng := NewEngine(EngineOpts{
		Audit: al,
		Hooks: chain,
		Now:   func() time.Time { return time.Unix(0, 0) },
	})
	st, err := eng.Run(context.Background(), RunRequest{Goal: "do work", Mode: ModeQuick, Actor: Identity{Key: "k"}})
	if err == nil {
		t.Fatalf("run should fail when a hook blocks the verify stage; got status %s", st.Status)
	}
	if !strings.Contains(err.Error(), "hook blocked") {
		t.Fatalf("error should attribute the hook block, got: %v", err)
	}
	if st.Status != RunFailed {
		t.Fatalf("status = %s, want failed", st.Status)
	}
	// The audit chain must still verify despite the hook veto.
	if res, _ := policy.VerifyChain(bytes.NewReader(buf.Bytes())); !res.OK {
		t.Fatalf("audit chain broke: %s", res.Reason)
	}
}
