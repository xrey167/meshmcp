package policy

import "testing"

// TestDecisionCarriesCost proves an allowed call surfaces the cost/quota units
// charged by its rate rule, so the audit can total per-identity spend (F29).
func TestDecisionCarriesCost(t *testing.T) {
	pol := &Policy{DefaultAllow: false, Rules: []Rule{
		{Peers: []string{"*"}, Tools: []string{"cheap"}, Allow: true, Rate: &RateLimit{Max: 100, Per: "24h", Cost: 1}},
		{Peers: []string{"*"}, Tools: []string{"pricey"}, Allow: true, Rate: &RateLimit{Max: 100, Per: "24h", Cost: 25}},
		{Peers: []string{"*"}, Tools: []string{"free"}, Allow: true}, // no rate → untracked (cost 0)
	}}
	e := NewEngine(pol, nil, nil)

	if d := e.DecideToolCall("p", "k", "cheap", nil); d.Cost != 1 {
		t.Fatalf("cheap cost = %d, want 1", d.Cost)
	}
	if d := e.DecideToolCall("p", "k", "pricey", nil); d.Cost != 25 {
		t.Fatalf("pricey cost = %d, want 25", d.Cost)
	}
	if d := e.DecideToolCall("p", "k", "free", nil); d.Cost != 0 {
		t.Fatalf("untracked cost = %d, want 0", d.Cost)
	}
	// A denied call charges nothing.
	if d := e.DecideToolCall("p", "k", "unknown", nil); d.Cost != 0 || d.Outcome != OutcomeDeny {
		t.Fatalf("denied call: cost=%d outcome=%v", d.Cost, d.Outcome)
	}
}
