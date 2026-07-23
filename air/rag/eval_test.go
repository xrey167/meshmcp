package rag

import (
	"math"
	"testing"
)

// TestContextPrecision_ZeroAndFullEdges covers the 0%, 100%, and partial cases.
func TestContextPrecision_ZeroAndFullEdges(t *testing.T) {
	gold := []string{"a", "b"}
	if got := ContextPrecision([]string{"a", "b"}, gold); got != 1 {
		t.Fatalf("all-relevant precision = %f, want 1", got)
	}
	if got := ContextPrecision([]string{"x", "y"}, gold); got != 0 {
		t.Fatalf("none-relevant precision = %f, want 0", got)
	}
	if got := ContextPrecision([]string{"a", "x"}, gold); got != 0.5 {
		t.Fatalf("half-relevant precision = %f, want 0.5", got)
	}
}

// TestContextRecall_ZeroAndFullEdges covers the 0%, 100%, and partial cases.
func TestContextRecall_ZeroAndFullEdges(t *testing.T) {
	gold := []string{"a", "b"}
	if got := ContextRecall([]string{"a", "b", "x"}, gold); got != 1 {
		t.Fatalf("full recall = %f, want 1", got)
	}
	if got := ContextRecall([]string{"x"}, gold); got != 0 {
		t.Fatalf("zero recall = %f, want 0", got)
	}
	if got := ContextRecall([]string{"a", "x"}, gold); got != 0.5 {
		t.Fatalf("half recall = %f, want 0.5", got)
	}
}

// TestEval_EmptyGoldAndEmptyRetrievedSafe proves every empty shape yields a
// defined number — never NaN, never a panic.
func TestEval_EmptyGoldAndEmptyRetrievedSafe(t *testing.T) {
	checks := []struct {
		name      string
		retrieved []string
		gold      []string
		wantP     float64
		wantR     float64
	}{
		{"both empty", nil, nil, 1, 1},
		{"empty retrieved", nil, []string{"a"}, 0, 0},
		{"empty gold", []string{"a"}, nil, 0, 1},
		{"blank ids ignored", []string{""}, []string{""}, 1, 1},
	}
	for _, c := range checks {
		p := ContextPrecision(c.retrieved, c.gold)
		r := ContextRecall(c.retrieved, c.gold)
		if math.IsNaN(p) || math.IsNaN(r) {
			t.Fatalf("%s: NaN (p=%f r=%f)", c.name, p, r)
		}
		if p != c.wantP || r != c.wantR {
			t.Fatalf("%s: p=%f r=%f, want p=%f r=%f", c.name, p, r, c.wantP, c.wantR)
		}
	}
	if s := Summarize(nil); s.Cases != 0 || math.IsNaN(s.MeanPrecision) {
		t.Fatalf("empty summary = %+v", s)
	}
}

// TestEval_OrderInvariant proves both metrics are set metrics: order and
// duplicates never change a score.
func TestEval_OrderInvariant(t *testing.T) {
	gold := []string{"b", "a"}
	p1 := ContextPrecision([]string{"a", "b", "x"}, gold)
	p2 := ContextPrecision([]string{"x", "b", "a", "a"}, gold)
	if p1 != p2 {
		t.Fatalf("precision order/dup-sensitive: %f vs %f", p1, p2)
	}
	r1 := ContextRecall([]string{"a", "x"}, gold)
	r2 := ContextRecall([]string{"x", "a"}, []string{"a", "b"})
	if r1 != r2 {
		t.Fatalf("recall order-sensitive: %f vs %f", r1, r2)
	}
}

// TestEval_SummarizeMeans proves the aggregate is the arithmetic mean over
// cases.
func TestEval_SummarizeMeans(t *testing.T) {
	results := []EvalResult{
		Evaluate(EvalCase{Question: "q1", Gold: []string{"a"}}, []string{"a"}),      // p=1 r=1
		Evaluate(EvalCase{Question: "q2", Gold: []string{"a", "b"}}, []string{"x"}), // p=0 r=0
	}
	s := Summarize(results)
	if s.Cases != 2 || s.MeanPrecision != 0.5 || s.MeanRecall != 0.5 {
		t.Fatalf("summary = %+v, want means 0.5/0.5 over 2 cases", s)
	}
}
