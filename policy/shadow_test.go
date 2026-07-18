package policy

import "testing"

func TestShadowHookReportsDivergenceWithoutEnforcing(t *testing.T) {
	// Candidate would DENY deploy; the enforced base ALLOWS it.
	candidate := &Policy{DefaultAllow: false, Rules: []Rule{
		{Peers: []string{"*"}, Tools: []string{"read_*"}, Allow: true},
	}}
	var got []ShadowDivergence
	h := NewShadowHook(candidate, func(d ShadowDivergence) { got = append(got, d) })

	base := Decision{Outcome: OutcomeAllow, Allow: true}
	out := h.DecideTool(ToolCallInfo{Caller: Caller{Peer: "alice"}, Tool: "deploy"}, base)

	// Enforcement unchanged.
	if out.Outcome != OutcomeAllow {
		t.Fatalf("shadow hook changed enforcement: %v", out.Outcome)
	}
	// Divergence reported (candidate would deny).
	if len(got) != 1 || got[0].Tool != "deploy" || got[0].Live != OutcomeAllow || got[0].Shadow != OutcomeDeny {
		t.Fatalf("expected one deploy divergence allow->deny, got %+v", got)
	}

	// A call the candidate agrees on reports nothing.
	got = nil
	_ = h.DecideTool(ToolCallInfo{Caller: Caller{Peer: "alice"}, Tool: "read_file"}, base)
	if len(got) != 0 {
		t.Fatalf("agreeing call should not report, got %+v", got)
	}
}
