package hooks

import "testing"

func TestKeywordDetectorMutatesMode(t *testing.T) {
	c := DefaultChain(true, nil)
	eff, fired := c.Run(Event{Phase: PrePlan, Text: "please ultrawork this refactor"})
	if eff.Kind != Mutate || eff.Meta["mode"] != "ultrawork" {
		t.Fatalf("expected mode mutation to ultrawork, got %+v", eff)
	}
	if len(fired) == 0 {
		t.Fatal("keyword-detector should have fired")
	}
}

func TestTaintEgressGuardBlocks(t *testing.T) {
	c := DefaultChain(true, nil)
	eff, _ := c.Run(Event{Phase: PreTool, Tool: "browser", Labels: []string{"net.egress", "tainted"}})
	if eff.Kind != Block {
		t.Fatalf("tainted egress must be blocked, got %s", eff.Kind)
	}
}

func TestWriteGuardBlocksMissingFile(t *testing.T) {
	c := DefaultChain(true, nil)
	eff, _ := c.Run(Event{Phase: PreTool, Tool: "edit", Labels: []string{"code.write"}, Meta: map[string]string{"file_exists": "false"}})
	if eff.Kind != Block {
		t.Fatalf("write to a missing file must be blocked, got %s", eff.Kind)
	}
}

func TestSafetyHookCannotBeDisabled(t *testing.T) {
	c := DefaultChain(true, nil)
	c.Disable("taint-egress-guard", "keyword-detector")
	// The safety guard must still fire despite being named in Disable.
	eff, _ := c.Run(Event{Phase: PreTool, Tool: "browser", Labels: []string{"net.egress", "tainted"}})
	if eff.Kind != Block {
		t.Fatalf("safety hook must not be disablable")
	}
	// The non-safety hook must be off.
	eff, _ = c.Run(Event{Phase: PrePlan, Text: "ultrawork"})
	if eff.Kind == Mutate {
		t.Fatalf("disabled keyword-detector must not fire")
	}
}

// weakener is a user hook that self-declares it relaxes a safety label.
type weakener struct{}

func (weakener) Name() string        { return "weakener" }
func (weakener) Phases() []Phase     { return []Phase{PreTool} }
func (weakener) Handle(Event) Effect { return Cont }
func (weakener) WeakensSafety() bool { return true }

func TestStrictRejectsWeakeningHook(t *testing.T) {
	c := NewChain(true, nil)
	if c.Add(weakener{}) {
		t.Fatal("strict chain must refuse a hook that weakens a safety label")
	}
	if names := c.Names(PreTool); len(names) != 0 {
		t.Fatalf("weakening hook must not be registered, got %v", names)
	}
}

func TestTruncatorMarksDropped(t *testing.T) {
	c := NewChain(false, nil)
	c.Add(ToolOutputTruncator{Max: 10})
	eff, _ := c.Run(Event{Phase: PostTool, Text: "this is a long output that exceeds ten bytes"})
	if eff.Kind != Mutate {
		t.Fatalf("truncator should mutate, got %s", eff.Kind)
	}
	if len(eff.Text) == 0 || !containsAny(eff.Text, "truncated") {
		t.Fatalf("truncation must be marked, got %q", eff.Text)
	}
}

func TestAuditCalledForNonContinue(t *testing.T) {
	var got []string
	c := DefaultChain(true, func(name string, e Event, eff Effect) { got = append(got, name) })
	c.Run(Event{Phase: PreTool, Tool: "browser", Labels: []string{"net.egress", "tainted"}})
	if len(got) == 0 {
		t.Fatal("audit must be called for a blocking effect")
	}
}
