package policy

import "testing"

// TestShadowHookDenyToAllowDirection: the candidate would ALLOW what the
// enforced policy denies. The divergence is reported in that direction and —
// critically — the enforced deny stands: a shadow can never widen enforcement.
func TestShadowHookDenyToAllowDirection(t *testing.T) {
	candidate := &Policy{DefaultAllow: false, Rules: []Rule{
		{Peers: []string{"*"}, Tools: []string{"deploy"}, Allow: true},
	}}
	var got []ShadowDivergence
	h := NewShadowHook(candidate, func(d ShadowDivergence) { got = append(got, d) })

	base := Decision{Outcome: OutcomeDeny, Reason: "denied by rule"}
	out := h.DecideTool(ToolCallInfo{Caller: Caller{Peer: "alice", PeerKey: "AK"}, Tool: "deploy"}, base)

	if out.Outcome != OutcomeDeny || out.Allow {
		t.Fatalf("shadow must not widen a deny: %+v", out)
	}
	if len(got) != 1 || got[0].Live != OutcomeDeny || got[0].Shadow != OutcomeAllow {
		t.Fatalf("expected one deny->allow divergence, got %+v", got)
	}
	// The report carries the caller identity for triage.
	if got[0].Peer != "alice" || got[0].PeerKey != "AK" || got[0].Tool != "deploy" {
		t.Fatalf("divergence must carry peer identity and tool: %+v", got[0])
	}
}

// TestShadowHookNilReportIsNoOp: a nil report func is documented as a no-op —
// the hook must neither panic nor alter the decision.
func TestShadowHookNilReportIsNoOp(t *testing.T) {
	candidate := &Policy{DefaultAllow: false}
	h := NewShadowHook(candidate, nil)
	base := Decision{Outcome: OutcomeAllow, Allow: true}
	out := h.DecideTool(ToolCallInfo{Caller: Caller{Peer: "p"}, Tool: "anything"}, base)
	if out.Outcome != OutcomeAllow || !out.Allow {
		t.Fatalf("nil-report shadow hook must leave the decision unchanged: %+v", out)
	}
}

// TestShadowHookUsesPeerKeyAndLabels: the candidate is evaluated with the
// call's PeerKey and Labels — a candidate keyed on pubkey or on data-flow
// labels sees the same inputs the enforced engine saw.
func TestShadowHookUsesPeerKeyAndLabels(t *testing.T) {
	candidate := &Policy{DefaultAllow: false, Rules: []Rule{
		// Egress is allowed by pubkey, but blocked once the session carries pii.
		{Peers: []string{"pubkey:trusted-key"}, Tools: []string{"post"}, Allow: true, BlockLabels: []string{"pii"}},
	}}
	var got []ShadowDivergence
	h := NewShadowHook(candidate, func(d ShadowDivergence) { got = append(got, d) })
	base := Decision{Outcome: OutcomeAllow, Allow: true}

	// Matching pubkey, no labels: candidate agrees with the live allow → silent.
	_ = h.DecideTool(ToolCallInfo{Caller: Caller{Peer: "x", PeerKey: "trusted-key"}, Tool: "post"}, base)
	if len(got) != 0 {
		t.Fatalf("agreement must not report: %+v", got)
	}
	// Wrong pubkey: candidate denies (rule keyed on PeerKey does not match).
	_ = h.DecideTool(ToolCallInfo{Caller: Caller{Peer: "x", PeerKey: "other-key"}, Tool: "post"}, base)
	if len(got) != 1 || got[0].Shadow != OutcomeDeny {
		t.Fatalf("candidate must see PeerKey, got %+v", got)
	}
	// Right pubkey but the session carries pii: candidate's block_labels fires,
	// proving Labels are propagated into the candidate evaluation.
	got = nil
	_ = h.DecideTool(ToolCallInfo{
		Caller: Caller{Peer: "x", PeerKey: "trusted-key"}, Tool: "post",
		Labels: map[string]bool{"pii": true},
	}, base)
	if len(got) != 1 || got[0].Shadow != OutcomeDeny {
		t.Fatalf("candidate must see session Labels, got %+v", got)
	}
}
