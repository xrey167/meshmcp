package hooks

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// safeBlockHook is a Safety hook that blocks at pre-tool. Used to prove a safety
// hook cannot be disabled even when its name was disabled before it was added.
type safeBlockHook struct{}

func (safeBlockHook) Name() string    { return "safe-block" }
func (safeBlockHook) Phases() []Phase { return []Phase{PreTool} }
func (safeBlockHook) IsSafety() bool  { return true }
func (safeBlockHook) Handle(Event) Effect {
	return Effect{Kind: Block, Reason: "safety"}
}

// TestSafetyHookCannotBeDisabledBeforeAdd is the regression for the order-
// dependent disable bypass: disabling a safety hook's NAME before the hook is
// added must still not disable it at evaluation time.
func TestSafetyHookCannotBeDisabledBeforeAdd(t *testing.T) {
	c := NewChain(true, nil)
	c.Disable("safe-block") // named before the hook exists
	c.Add(safeBlockHook{})
	if eff, _ := c.Run(Event{Phase: PreTool}); eff.Kind != Block {
		t.Fatalf("a safety hook must fire even if disabled by name before Add, got %s", eff.Kind)
	}
	names := c.Names(PreTool)
	if len(names) != 1 || names[0] != "safe-block" {
		t.Fatalf("Names must list the safety hook regardless of an earlier Disable, got %v", names)
	}
}

// TestToolOutputTruncatorRuneSafe asserts truncation never splits a multi-byte
// rune, so the mutated output is always valid UTF-8.
func TestToolOutputTruncatorRuneSafe(t *testing.T) {
	text := strings.Repeat("é", 400) // 800 bytes of 2-byte runes
	c := NewChain(true, nil)
	c.Add(ToolOutputTruncator{Max: 101}) // odd cap lands mid-rune if naive
	eff, _ := c.Run(Event{Phase: PostTool, Text: text})
	if eff.Kind != Mutate {
		t.Fatalf("oversized output must be truncated, got %s", eff.Kind)
	}
	if !utf8.ValidString(eff.Text) {
		t.Fatal("truncated output must remain valid UTF-8 (no split rune)")
	}
}

// injectHook injects fixed text at pre-plan.
type injectHook struct{ text string }

func (injectHook) Name() string          { return "inject" }
func (injectHook) Phases() []Phase       { return []Phase{PrePlan} }
func (h injectHook) Handle(Event) Effect { return Effect{Kind: Inject, Text: h.text} }

// mutTag appends a Meta tag at pre-plan.
type mutTag struct{ k, v string }

func (m mutTag) Name() string        { return "mut-" + m.k }
func (mutTag) Phases() []Phase       { return []Phase{PrePlan} }
func (m mutTag) Handle(Event) Effect { return Effect{Kind: Mutate, Meta: map[string]string{m.k: m.v}} }

func TestEmptyChainContinues(t *testing.T) {
	eff, fired := NewChain(true, nil).Run(Event{Phase: PrePlan, Text: "hi"})
	if eff.Kind != Continue || len(fired) != 0 {
		t.Fatalf("empty chain should continue with no fired hooks, got %s / %v", eff.Kind, fired)
	}
}

func TestInjectIsTerminal(t *testing.T) {
	c := NewChain(true, nil)
	c.Add(injectHook{text: "RULES"})
	c.Add(mutTag{k: "after", v: "1"}) // must NOT run (inject is terminal)
	eff, fired := c.Run(Event{Phase: PrePlan})
	if eff.Kind != Inject || eff.Text != "RULES" {
		t.Fatalf("expected terminal inject, got %s %q", eff.Kind, eff.Text)
	}
	if len(fired) != 1 {
		t.Fatalf("inject is terminal — the later hook must not fire, got %v", fired)
	}
}

func TestMutateThreadsThroughChain(t *testing.T) {
	c := NewChain(true, nil)
	c.Add(mutTag{k: "a", v: "1"})
	c.Add(mutTag{k: "b", v: "2"})
	eff, fired := c.Run(Event{Phase: PrePlan, Meta: map[string]string{"orig": "y"}})
	if eff.Kind != Mutate {
		t.Fatalf("expected a mutate result, got %s", eff.Kind)
	}
	if eff.Meta["b"] != "2" {
		t.Fatalf("final mutate should carry the last hook's meta, got %v", eff.Meta)
	}
	if len(fired) != 2 {
		t.Fatalf("both mutate hooks should fire, got %v", fired)
	}
}

func TestRuntimeFallbackRetriesTransientOnly(t *testing.T) {
	c := NewChain(true, nil)
	c.Add(RuntimeFallback{})
	if eff, _ := c.Run(Event{Phase: OnError, ErrMsg: "connection reset by peer"}); eff.Kind != Retry {
		t.Fatalf("transient error should retry, got %s", eff.Kind)
	}
	if eff, _ := c.Run(Event{Phase: OnError, ErrMsg: "nil pointer dereference"}); eff.Kind != Continue {
		t.Fatalf("a non-transient error must not retry, got %s", eff.Kind)
	}
}
