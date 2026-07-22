package graph

import "testing"

func stateWith(data map[string]any, labels ...string) GraphState {
	s := NewState("n")
	s.Data = data
	for _, l := range labels {
		s.Labels[l] = true
	}
	return s
}

func TestPredicate_EvalRouting(t *testing.T) {
	data := map[string]any{
		"critic": map[string]any{"ok": true, "score": float64(7), "status": "done"},
	}
	cases := []struct {
		expr string
		want bool
	}{
		{"critic.ok == true", true},
		{"critic.ok == false", false},
		{"critic.ok", true},
		{"critic.score > 5", true},
		{"critic.score < 5", false},
		{"critic.score >= 7", true},
		{"critic.status == \"done\"", true},
		{"critic.status != \"done\"", false},
		{"critic.ok == true && critic.score > 5", true},
		{"critic.ok == false || critic.score > 5", true},
		{"critic.ok == false && critic.score > 5", false},
		{"missing.field == true", false}, // missing field = false
		{"missing.field != true", true},  // missing differs from a concrete literal
		{"missing.field", false},         // bare truthiness of a missing path = false
	}
	for _, c := range cases {
		p, err := CompilePredicate(c.expr)
		if err != nil {
			t.Fatalf("%q: compile error %v", c.expr, err)
		}
		if got := p(stateWith(data)); got != c.want {
			t.Errorf("%q = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestPredicate_LabelTest(t *testing.T) {
	p, err := CompilePredicate("label:pii")
	if err != nil {
		t.Fatal(err)
	}
	if p(stateWith(nil)) {
		t.Fatal("label:pii should be false when unset")
	}
	if !p(stateWith(nil, "pii")) {
		t.Fatal("label:pii should be true when the taint label is set")
	}
}

func TestPredicate_EmptyIsNil(t *testing.T) {
	p, err := CompilePredicate("   ")
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Fatal("empty expression should compile to a nil (unconditional) predicate")
	}
}
