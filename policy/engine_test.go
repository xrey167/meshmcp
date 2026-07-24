package policy

import (
	"testing"
	"time"
)

func TestRateLimit(t *testing.T) {
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	pol := &Policy{Rules: []Rule{
		{Peers: []string{"*"}, Tools: []string{"*"}, Allow: true, Rate: &RateLimit{Max: 2, Per: "1m"}},
	}}
	eng := NewEngine(pol, func() time.Time { return now }, nil)

	// First two calls in the same instant pass; the third is limited.
	for i := 0; i < 2; i++ {
		if d := eng.DecideToolCall("p", "K", "any", nil); d.Outcome != OutcomeAllow {
			t.Fatalf("call %d should be allowed, got %v (%s)", i, d.Outcome, d.Reason)
		}
	}
	if d := eng.DecideToolCall("p", "K", "any", nil); d.Outcome != OutcomeDeny {
		t.Fatalf("third call should be rate-limited, got %v", d.Outcome)
	} else if d.RetryAfter <= 0 {
		t.Fatalf("rate-limit denial should carry a positive RetryAfter (S56), got %d", d.RetryAfter)
	}
	// After the window refills, a call passes again.
	now = now.Add(time.Minute)
	if d := eng.DecideToolCall("p", "K", "any", nil); d.Outcome != OutcomeAllow {
		t.Fatalf("call after refill should be allowed, got %v (%s)", d.Outcome, d.Reason)
	}
	// A different identity has its own bucket.
	if d := eng.DecideToolCall("p", "OTHER", "any", nil); d.Outcome != OutcomeAllow {
		t.Fatalf("separate identity should not share the bucket")
	}
}

func TestTimeWindow(t *testing.T) {
	pol := &Policy{
		DefaultAllow: false,
		Rules: []Rule{
			{Peers: []string{"*"}, Tools: []string{"deploy"}, Allow: true,
				When: &Window{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Hours: "09:00-17:00", TZ: "UTC"}},
		},
	}
	// Wednesday 10:00 UTC — inside the window.
	inside := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	eng := NewEngine(pol, func() time.Time { return inside }, nil)
	if d := eng.DecideToolCall("p", "K", "deploy", nil); d.Outcome != OutcomeAllow {
		t.Fatalf("deploy inside window should be allowed, got %v", d.Outcome)
	}
	// Wednesday 20:00 UTC — outside; rule falls through to default deny.
	outside := time.Date(2026, 7, 15, 20, 0, 0, 0, time.UTC)
	eng = NewEngine(pol, func() time.Time { return outside }, nil)
	if d := eng.DecideToolCall("p", "K", "deploy", nil); d.Outcome != OutcomeDeny {
		t.Fatalf("deploy outside window should fall through to deny, got %v", d.Outcome)
	}
	// Saturday — wrong day.
	sat := time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)
	eng = NewEngine(pol, func() time.Time { return sat }, nil)
	if d := eng.DecideToolCall("p", "K", "deploy", nil); d.Outcome != OutcomeDeny {
		t.Fatalf("deploy on weekend should be denied, got %v", d.Outcome)
	}
}

func TestTaintGuardBlocksAfterUntrustedSource(t *testing.T) {
	pol := &Policy{
		DefaultAllow: false,
		Rules: []Rule{
			// fetch brings untrusted web content into the session.
			{Peers: []string{"*"}, Tools: []string{"fetch"}, Allow: true, TaintSource: true},
			// write_file is privileged: blocked once the session is tainted.
			{Peers: []string{"*"}, Tools: []string{"write_file"}, Allow: true, TaintGuard: true},
		},
	}
	eng := NewEngine(pol, nil, nil)

	// Before any untrusted data: write_file is allowed.
	if d := eng.DecideToolCall("p", "K", "write_file", nil); d.Outcome != OutcomeAllow {
		t.Fatalf("write_file should be allowed when untainted, got %v", d.Outcome)
	}
	// fetch is a taint source: allowed, and adds the "tainted" label.
	d := eng.DecideToolCall("p", "K", "fetch", nil)
	if d.Outcome != OutcomeAllow || firstPresent([]string{"tainted"}, toSet(d.AddLabels)) != "tainted" {
		t.Fatalf("fetch should be allowed and add the tainted label, got %+v", d)
	}
	// Now, with the session tainted, write_file is blocked at the network layer.
	if d := eng.DecideToolCall("p", "K", "write_file", map[string]bool{"tainted": true}); d.Outcome != OutcomeDeny {
		t.Fatalf("write_file should be blocked after taint, got %v (%s)", d.Outcome, d.Reason)
	}
}

func toSet(ls []string) map[string]bool {
	m := map[string]bool{}
	for _, l := range ls {
		m[l] = true
	}
	return m
}

func TestDataFlowLabelsBlockPIIEgress(t *testing.T) {
	// The category-defining rule: PII read from an internal tool may not flow
	// to an external-egress tool. No LLM guardrail or ordinary firewall can
	// express this; the mesh enforces it from data-flow state.
	pol := &Policy{
		DefaultAllow: false,
		Rules: []Rule{
			{Peers: []string{"*"}, Tools: []string{"read_customer"}, Allow: true, EmitLabels: []string{"pii"}},
			{Peers: []string{"*"}, Tools: []string{"post_external"}, Allow: true, BlockLabels: []string{"pii"}},
			{Peers: []string{"*"}, Tools: []string{"read_public"}, Allow: true},
		},
	}
	eng := NewEngine(pol, nil, nil)

	// Posting externally is fine before any PII enters the session.
	if d := eng.DecideToolCall("p", "K", "post_external", nil); d.Outcome != OutcomeAllow {
		t.Fatalf("external post should be allowed with no PII, got %v", d.Outcome)
	}
	// Read customer data → session now carries the pii label.
	d := eng.DecideToolCall("p", "K", "read_customer", nil)
	if firstPresent([]string{"pii"}, toSet(d.AddLabels)) != "pii" {
		t.Fatalf("read_customer should emit the pii label, got %+v", d)
	}
	// Now external egress is blocked.
	if d := eng.DecideToolCall("p", "K", "post_external", map[string]bool{"pii": true}); d.Outcome != OutcomeDeny {
		t.Fatalf("external post after PII read should be blocked, got %v (%s)", d.Outcome, d.Reason)
	}
	// A different (non-egress) tool is unaffected by the pii label.
	if d := eng.DecideToolCall("p", "K", "read_public", map[string]bool{"pii": true}); d.Outcome != OutcomeAllow {
		t.Fatalf("read_public should stay allowed even with pii label, got %v", d.Outcome)
	}
}

func TestCosign(t *testing.T) {
	pol := &Policy{
		DefaultAllow: false,
		Rules: []Rule{
			{Peers: []string{"*"}, Tools: []string{"transfer_funds"}, Allow: true, RequireCosign: true},
		},
	}
	store := NewMemCosign()
	eng := NewEngine(pol, nil, store)

	// Without an approval, the call is held pending co-sign.
	if d := eng.DecideToolCall("agent.mesh", "K", "transfer_funds", nil); d.Outcome != OutcomeCosign {
		t.Fatalf("should require co-sign, got %v", d.Outcome)
	}
	// A human identity co-signs (peer|tool key).
	store.Approve(CosignKey("agent.mesh", "transfer_funds"))
	if d := eng.DecideToolCall("agent.mesh", "K", "transfer_funds", nil); d.Outcome != OutcomeAllow {
		t.Fatalf("should be allowed after co-sign, got %v (%s)", d.Outcome, d.Reason)
	}
}

func TestOvernightWindow(t *testing.T) {
	w := &Window{Hours: "22:00-06:00", TZ: "UTC"}
	if !w.active(time.Date(2026, 7, 15, 23, 0, 0, 0, time.UTC)) {
		t.Fatal("23:00 should be inside an overnight window")
	}
	if !w.active(time.Date(2026, 7, 15, 3, 0, 0, 0, time.UTC)) {
		t.Fatal("03:00 should be inside an overnight window")
	}
	if w.active(time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("12:00 should be outside an overnight window")
	}
}
