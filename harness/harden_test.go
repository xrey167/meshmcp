package harness

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// TestLoopAlwaysTerminates asserts Drive terminates for every loop kind and
// every budget shape — including an open budget (LoopRounds 0) with a round that
// always changes and never meets the goal, which the hard cap must still bound.
func TestLoopAlwaysTerminates(t *testing.T) {
	clock := func() time.Time { return time.Unix(0, 0) }
	alwaysChanging := func(ctx context.Context, n int) RoundResult { return RoundResult{Changed: true} }
	for _, kind := range []LoopKind{LoopRalph, LoopUltrawork, LoopAutopilot} {
		for _, b := range []Budget{{}, {LoopRounds: 1}, {LoopRounds: 7}, {Tokens: 5}} { // Tokens-only ⇒ LoopRounds 0 (open)
			tr := newTracker(b, clock)
			spec := LoopSpec{Kind: kind, MaxRounds: b.LoopRounds}
			rounds, stop, err := spec.Drive(context.Background(), tr, alwaysChanging)
			if err != nil {
				t.Fatalf("kind=%s budget=%+v: unexpected err %v", kind, b, err)
			}
			if rounds > hardLoopCap {
				t.Fatalf("kind=%s budget=%+v ran %d rounds — exceeded the hard cap %d", kind, b, rounds, hardLoopCap)
			}
			if stop == "" {
				t.Fatalf("kind=%s budget=%+v: empty stop condition", kind, b)
			}
		}
	}
}

// TestLoopConvergesOnNoDiff asserts ralph/ultrawork stop when a round makes no
// change, while autopilot keeps going (bounded by rounds).
func TestLoopConvergesOnNoDiff(t *testing.T) {
	noChange := func(ctx context.Context, n int) RoundResult { return RoundResult{Changed: false} }
	for _, kind := range []LoopKind{LoopRalph, LoopUltrawork} {
		_, stop, _ := LoopSpec{Kind: kind}.Drive(context.Background(), newTracker(Budget{LoopRounds: 100}, nil), noChange)
		if stop != StopNoDiff {
			t.Fatalf("kind=%s should stop on no-diff, got %s", kind, stop)
		}
	}
	// autopilot ignores no-diff and runs to the round budget.
	_, stop, _ := LoopSpec{Kind: LoopAutopilot}.Drive(context.Background(), newTracker(Budget{LoopRounds: 3}, nil), noChange)
	if stop != StopMaxRound {
		t.Fatalf("autopilot should run to the round cap, got %s", stop)
	}
}

// TestLoopOperatorCancelWins asserts a cancelled context stops the loop immediately.
func TestLoopOperatorCancelWins(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, stop, _ := LoopSpec{Kind: LoopAutopilot}.Drive(ctx, newTracker(Budget{LoopRounds: 100}, nil),
		func(ctx context.Context, n int) RoundResult { return RoundResult{Changed: true} })
	if stop != StopOperator {
		t.Fatalf("operator cancel must win, got %s", stop)
	}
}

// TestReadOnlyRolesNeverWrite asserts every ReadOnly canonical role is denied
// every write/exec tool by the compiled policy, and that writing roles are
// allowed to edit — the firewall's core promise.
func TestReadOnlyRolesNeverWrite(t *testing.T) {
	eng := policy.NewEngine(CompilePolicy(nil), nil, nil)
	writeTools := []string{"edit", "ast_grep_replace", "lsp_rename", "interactive_bash"}
	for _, spec := range Roles() {
		fqdn := string(spec.Role) + "--r--0"
		if spec.ReadOnly {
			for _, tool := range writeTools {
				if d := eng.DecideToolCall(fqdn, "k", tool, nil); d.Outcome == policy.OutcomeAllow {
					t.Errorf("read-only role %s must not be allowed to call %q", spec.Role, tool)
				}
			}
		}
	}
	for _, role := range []Role{RoleExecutor, RoleJunior, RoleDeepWorker} {
		fqdn := string(role) + "--r--0"
		if d := eng.DecideToolCall(fqdn, "k", "edit", nil); d.Outcome != policy.OutcomeAllow {
			t.Errorf("writing role %s should be allowed to edit", role)
		}
	}
}

// TestRunIDSafePathElement asserts newRunID always yields a single safe path
// element (air/checkpoint uses it as a filename — path traversal must be impossible).
func TestRunIDSafePathElement(t *testing.T) {
	for i := 0; i < 3000; i++ {
		id := string(newRunID())
		if id == "" || id == "." || id == ".." {
			t.Fatalf("unsafe run id %q", id)
		}
		if strings.ContainsAny(id, `/\`) || filepath.Base(id) != id {
			t.Fatalf("run id is not a safe path element: %q", id)
		}
	}
}

// TestCategoryRouteNeverEmpty asserts routing never yields an empty model class
// or a zero reviewer count for any category, including unknown/empty ones.
func TestCategoryRouteNeverEmpty(t *testing.T) {
	tbl := DefaultCategoryTable()
	cats := append(tbl.Categories(), Category(""), Category("totally-unknown"))
	for _, c := range cats {
		r := tbl.Route(c)
		if r.ModelClass == "" {
			t.Errorf("category %q routed to an empty model class", c)
		}
		if r.Reviewers < 1 {
			t.Errorf("category %q routed to %d reviewers (want >=1)", c, r.Reviewers)
		}
	}
}

// TestBudgetTrackerConcurrent stresses the tracker from many goroutines under
// the race detector, and confirms token exhaustion is enforced.
func TestBudgetTrackerConcurrent(t *testing.T) {
	tr := newTracker(Budget{Tokens: 1000, LoopRounds: 50}, nil)
	var wg sync.WaitGroup
	var mu sync.Mutex
	errs := 0
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tr.spendTokens(10); err != nil {
				mu.Lock()
				errs++
				mu.Unlock()
			}
			tr.nextRound()
		}()
	}
	wg.Wait()
	// 200×10 = 2000 tokens against a 1000 budget ⇒ roughly half exhaust.
	if errs == 0 {
		t.Fatal("token budget was never enforced under concurrency")
	}
	tokens, rounds, _ := tr.snapshot()
	if tokens < 1000 {
		t.Fatalf("expected accumulated spend >= budget, got %d", tokens)
	}
	if rounds > 50 {
		t.Fatalf("round budget breached: %d", rounds)
	}
}

// TestIntentGateNoPanic asserts classification never panics and always yields a
// known category + mode, for hostile goal strings.
func TestIntentGateNoPanic(t *testing.T) {
	g := NewIntentGate(nil, nil)
	goals := []string{"", " ", "\x00\n\t", strings.Repeat("ultrawork ", 5000), "𝕦𝕟𝕚 💥", "ultrathink ralph autopilot ulw synthesize", "DROP TABLE; deploy to prod"}
	for _, goal := range goals {
		in := g.Classify(context.Background(), goal, "", "")
		if !KnownCategory(in.Category) {
			t.Errorf("goal %q → unknown category %q", truncate(goal, 20), in.Category)
		}
		if !KnownMode(in.Mode) {
			t.Errorf("goal %q → unknown mode %q", truncate(goal, 20), in.Mode)
		}
	}
}

// TestConfigLoadRobustness asserts config loading fails cleanly (never panics)
// on malformed input and applies defaults on partial input.
func TestConfigLoadRobustness(t *testing.T) {
	if _, err := LoadConfig([]byte("default_mode: nonsense-mode")); err == nil {
		t.Error("unknown default_mode should error")
	}
	if _, err := LoadConfig([]byte("budgets:\n  wall_clock: not-a-duration")); err == nil {
		t.Error("invalid wall_clock should error")
	}
	if _, err := LoadConfig([]byte("::: not yaml :::")); err == nil {
		t.Error("malformed YAML should error")
	}
	c, err := LoadConfig(nil)
	if err != nil || c.DefaultMode != ModeTeam {
		t.Fatalf("nil config should yield defaults: %+v err=%v", c, err)
	}
	c, err = LoadConfig([]byte("default_mode: ralph"))
	if err != nil || c.DefaultMode != ModeRalph {
		t.Fatalf("partial config should override just that field: %+v err=%v", c, err)
	}
}
