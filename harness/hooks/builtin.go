package hooks

import "fmt"

// Built-in hooks: a representative, governed subset of the source harnesses'
// 54–61 hooks, grouped as in the spec (context/injection, productivity/control,
// quality/safety, recovery/stability, truncation, notifications). Each is a pure
// (Event) → Effect. Safety-critical guards implement Safety so they cannot be
// disabled.

// --- productivity / control ---

// KeywordDetector catches the magic words (ultrawork/ultrathink/ulw) and
// slash-commands in the pre-plan text and mutates the run mode/effort via Meta.
type KeywordDetector struct{}

func (KeywordDetector) Name() string    { return "keyword-detector" }
func (KeywordDetector) Phases() []Phase { return []Phase{PrePlan} }
func (KeywordDetector) Handle(e Event) Effect {
	meta := map[string]string{}
	switch {
	case containsAny(e.Text, "ultrawork", "ulw"):
		meta["mode"] = "ultrawork"
	case containsAny(e.Text, "autopilot"):
		meta["mode"] = "autopilot"
	case containsAny(e.Text, "ralph"):
		meta["mode"] = "ralph"
	}
	if containsAny(e.Text, "ultrathink", "think hard") {
		meta["effort"] = "high"
	}
	if len(meta) == 0 {
		return Cont
	}
	return Effect{Kind: Mutate, Reason: "magic word detected", Meta: meta}
}

// StopContinuationGuard blocks any action once a run is stopped, so a loop
// cannot silently resume. Safety: cannot be disabled.
type StopContinuationGuard struct{}

func (StopContinuationGuard) Name() string    { return "stop-continuation-guard" }
func (StopContinuationGuard) Phases() []Phase { return []Phase{PrePlan, PreTool, PreSpawn} }
func (StopContinuationGuard) IsSafety() bool  { return true }
func (StopContinuationGuard) Handle(e Event) Effect {
	if e.Meta["stopped"] == "true" {
		return Effect{Kind: Block, Reason: "run was stopped; continuation refused"}
	}
	return Cont
}

// --- quality / safety ---

// WriteExistingFileGuard blocks a code.write tool that targets a file the caller
// has not read/that does not exist, forcing an explicit read-before-write. It
// keys on Meta["file_exists"]. Safety: cannot be disabled.
type WriteExistingFileGuard struct{}

func (WriteExistingFileGuard) Name() string    { return "write-existing-file-guard" }
func (WriteExistingFileGuard) Phases() []Phase { return []Phase{PreTool} }
func (WriteExistingFileGuard) IsSafety() bool  { return true }
func (WriteExistingFileGuard) Handle(e Event) Effect {
	if hasLabel(e.Labels, "code.write") && e.Meta["file_exists"] == "false" {
		return Effect{Kind: Block, Reason: "refusing to write a file that does not exist (edit, not create)"}
	}
	return Cont
}

// TaintEgressGuard blocks a net.egress tool once the session is tainted by
// untrusted data — prompt-injection defense at the hook layer, mirroring the
// policy taint guard. Safety: cannot be disabled.
type TaintEgressGuard struct{}

func (TaintEgressGuard) Name() string    { return "taint-egress-guard" }
func (TaintEgressGuard) Phases() []Phase { return []Phase{PreTool} }
func (TaintEgressGuard) IsSafety() bool  { return true }
func (TaintEgressGuard) Handle(e Event) Effect {
	if hasLabel(e.Labels, "net.egress") && hasLabel(e.Labels, "tainted") {
		return Effect{Kind: Block, Reason: "session tainted by untrusted data; egress refused"}
	}
	return Cont
}

// --- context / injection ---

// RulesInjector injects standing project rules into the pre-plan context.
type RulesInjector struct{ Rules string }

func (RulesInjector) Name() string    { return "rules-injector" }
func (RulesInjector) Phases() []Phase { return []Phase{PrePlan} }
func (r RulesInjector) Handle(e Event) Effect {
	if r.Rules == "" {
		return Cont
	}
	return Effect{Kind: Inject, Reason: "project rules", Text: r.Rules}
}

// --- truncation ---

// ToolOutputTruncator caps tool output to Max bytes and marks what was dropped,
// so a large result never floods the context (no silent truncation).
type ToolOutputTruncator struct{ Max int }

func (ToolOutputTruncator) Name() string    { return "tool-output-truncator" }
func (ToolOutputTruncator) Phases() []Phase { return []Phase{PostTool} }
func (t ToolOutputTruncator) Handle(e Event) Effect {
	max := t.Max
	if max <= 0 {
		max = 16384
	}
	if len(e.Text) <= max {
		return Cont
	}
	dropped := len(e.Text) - max
	out := e.Text[:max] + fmt.Sprintf("\n…(truncated %d bytes)", dropped)
	return Effect{Kind: Mutate, Reason: fmt.Sprintf("truncated %d bytes", dropped), Text: out}
}

// --- recovery / stability ---

// RuntimeFallback asks the caller to retry after a transient runtime error,
// bounded by the caller's retry budget.
type RuntimeFallback struct{}

func (RuntimeFallback) Name() string    { return "runtime-fallback" }
func (RuntimeFallback) Phases() []Phase { return []Phase{OnError} }
func (RuntimeFallback) Handle(e Event) Effect {
	if containsAny(e.ErrMsg, "timeout", "temporarily", "rate limit", "unavailable", "connection reset") {
		return Effect{Kind: Retry, Reason: "transient runtime error; retry"}
	}
	return Cont
}

// DefaultChain builds the built-in hook chain. strict rejects user hooks that
// weaken safety labels; audit records non-continue effects.
func DefaultChain(strict bool, audit AuditFunc) *Chain {
	c := NewChain(strict, audit)
	c.Add(KeywordDetector{})
	c.Add(StopContinuationGuard{})
	c.Add(WriteExistingFileGuard{})
	c.Add(TaintEgressGuard{})
	c.Add(ToolOutputTruncator{Max: 16384})
	c.Add(RuntimeFallback{})
	return c
}
