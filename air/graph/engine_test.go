package graph

import (
	"context"
	"reflect"
	"testing"
)

// fixedOut returns a NodeFunc that always emits the given data/labels/cost.
func fixedOut(data map[string]any, labels []string, cost int) NodeFunc {
	return func(_ context.Context, _ GraphState) (NodeOutput, error) {
		return NodeOutput{Data: data, Labels: labels, Cost: cost}, nil
	}
}

// countingCritic emits ok=true only once the run has reached the target iter, so
// a generate->critic loop converges after a known number of turns.
func countingCritic(convergeAtIter int) NodeFunc {
	return func(_ context.Context, s GraphState) (NodeOutput, error) {
		return NodeOutput{Data: map[string]any{"ok": s.Iter+1 >= convergeAtIter}}, nil
	}
}

func TestReduce_IsImmutableAndDeterministic(t *testing.T) {
	prev := NewState("a")
	prev = Reduce(prev, NodeOutput{Node: "a", Data: map[string]any{"x": 1}, Labels: []string{"seed"}, Cost: 3})

	before := prev.clone()
	out := NodeOutput{Node: "b", Data: map[string]any{"y": 2}, Labels: []string{"pii"}, Cost: 5}

	n1 := Reduce(prev, out)
	n2 := Reduce(prev, out)

	// Deterministic: same inputs -> equal results.
	if !reflect.DeepEqual(n1, n2) {
		t.Fatalf("Reduce not deterministic:\n%+v\n%+v", n1, n2)
	}
	// Immutable: prev is untouched by Reduce.
	if !reflect.DeepEqual(prev, before) {
		t.Fatalf("Reduce mutated its input state:\ngot  %+v\nwant %+v", prev, before)
	}
	// The new state carries the folded result.
	if n1.Iter != 2 || n1.Cost != 8 || n1.Version != 2 {
		t.Fatalf("bad reduced counters: iter=%d cost=%d version=%d", n1.Iter, n1.Cost, n1.Version)
	}
	if !n1.Labels["seed"] || !n1.Labels["pii"] {
		t.Fatalf("labels did not accumulate monotonically: %+v", n1.Labels)
	}
	if got := n1.Data["b"]; !reflect.DeepEqual(got, map[string]any{"y": 2}) {
		t.Fatalf("node output not keyed under node id: %+v", n1.Data)
	}
}

func TestDrive_ConvergesViaGoalPredicate(t *testing.T) {
	converge, err := CompilePredicate("critic.ok == true")
	if err != nil {
		t.Fatal(err)
	}
	g := &Graph{
		Entry:  "gen",
		Bounds: Bounds{Converge: converge, MaxIterations: 100},
		Nodes: []Node{
			{ID: "gen", Exec: fixedOut(map[string]any{"draft": 1}, nil, 1),
				Edges: []Edge{{To: "critic"}}},
			{ID: "critic", Exec: countingCritic(4),
				Edges: []Edge{{To: "gen", Loop: true}}},
		},
	}
	res, err := Drive(context.Background(), g, NewState("gen"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "converged" {
		t.Fatalf("expected converged, got %q at iter %d", res.Reason, res.State.Iter)
	}
	// gen+critic per turn; converges when critic sees iter+1>=4 => 4 executions.
	if res.State.Iter != 4 {
		t.Fatalf("expected convergence at iter 4, got %d", res.State.Iter)
	}
}

func TestDrive_NonConvergingHitsMaxIter(t *testing.T) {
	// A goal that never holds + an always-looping back-edge: the ONLY thing that
	// can stop this is the hard iteration cap. This is the headline bound.
	converge, _ := CompilePredicate("critic.ok == true")
	g := &Graph{
		Entry:  "gen",
		Bounds: Bounds{Converge: converge, MaxIterations: 6},
		Nodes: []Node{
			{ID: "gen", Exec: fixedOut(map[string]any{"draft": 1}, nil, 1),
				Edges: []Edge{{To: "critic"}}},
			{ID: "critic", Exec: fixedOut(map[string]any{"ok": false}, nil, 1),
				Edges: []Edge{{To: "gen", Loop: true}}},
		},
	}
	res, err := Drive(context.Background(), g, NewState("gen"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "max_iterations" {
		t.Fatalf("expected max_iterations termination, got %q", res.Reason)
	}
	if res.State.Iter != 6 {
		t.Fatalf("expected termination exactly at the cap (6), got %d", res.State.Iter)
	}
}

func TestBounds_ZeroMaxIterationsCoercedToDefault(t *testing.T) {
	g := &Graph{
		Entry:  "loop",
		Bounds: Bounds{MaxIterations: 0}, // must NOT mean unbounded
		Nodes: []Node{
			{ID: "loop", Exec: fixedOut(nil, nil, 0), Edges: []Edge{{To: "loop", Loop: true}}},
		},
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	if g.Bounds.MaxIterations != DefaultMaxIterations {
		t.Fatalf("zero max not coerced to default: %d", g.Bounds.MaxIterations)
	}
	res, err := Drive(context.Background(), g, NewState("loop"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Reason != "max_iterations" || res.State.Iter != DefaultMaxIterations {
		t.Fatalf("unbounded self-loop not capped: reason=%q iter=%d", res.Reason, res.State.Iter)
	}
}

func TestStep_CostBudgetTerminates(t *testing.T) {
	g := &Graph{Entry: "n", Bounds: Bounds{MaxIterations: 100, CostBudget: 10},
		Nodes: []Node{{ID: "n", Edges: []Edge{{To: "n", Loop: true}}}}}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	s := NewState("n")
	s.Cost = 10
	_, done, reason := Step(g, s)
	if !done || reason != "cost_budget" {
		t.Fatalf("cost budget not enforced: done=%v reason=%q", done, reason)
	}
}

func TestStep_ConditionalRouting(t *testing.T) {
	when, _ := CompilePredicate("critic.ok == false")
	g := &Graph{
		Entry:  "critic",
		Bounds: Bounds{MaxIterations: 100},
		Nodes: []Node{
			{ID: "gen", Edges: []Edge{{To: "critic"}}},
			{ID: "critic", Edges: []Edge{
				{To: "gen", When: when, Loop: true}, // retry when critique failed
				{To: Terminate},                     // else finish
			}},
		},
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	// critic.ok == false -> route back to gen.
	s := NewState("critic")
	s.Data["critic"] = map[string]any{"ok": false}
	if next, done, _ := Step(g, s); done || next != "gen" {
		t.Fatalf("expected route to gen, got next=%q done=%v", next, done)
	}
	// critic.ok == true -> the first edge's When is false, fall to Terminate.
	s2 := NewState("critic")
	s2.Data["critic"] = map[string]any{"ok": true}
	if _, done, reason := Step(g, s2); !done || reason != "terminate" {
		t.Fatalf("expected terminate, got done=%v reason=%q", done, reason)
	}
}

func TestValidate_RejectsBadStructure(t *testing.T) {
	cases := map[string]*Graph{
		"empty entry":   {Nodes: []Node{{ID: "a"}}},
		"unknown entry": {Entry: "x", Nodes: []Node{{ID: "a"}}},
		"dup node":      {Entry: "a", Nodes: []Node{{ID: "a"}, {ID: "a"}}},
		"bad edge":      {Entry: "a", Nodes: []Node{{ID: "a", Edges: []Edge{{To: "ghost"}}}}},
	}
	for name, g := range cases {
		if err := g.Validate(); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}
