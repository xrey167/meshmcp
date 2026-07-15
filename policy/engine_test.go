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
		if d := eng.DecideToolCall("p", "K", "any", false); d.Outcome != OutcomeAllow {
			t.Fatalf("call %d should be allowed, got %v (%s)", i, d.Outcome, d.Reason)
		}
	}
	if d := eng.DecideToolCall("p", "K", "any", false); d.Outcome != OutcomeDeny {
		t.Fatalf("third call should be rate-limited, got %v", d.Outcome)
	}
	// After the window refills, a call passes again.
	now = now.Add(time.Minute)
	if d := eng.DecideToolCall("p", "K", "any", false); d.Outcome != OutcomeAllow {
		t.Fatalf("call after refill should be allowed, got %v (%s)", d.Outcome, d.Reason)
	}
	// A different identity has its own bucket.
	if d := eng.DecideToolCall("p", "OTHER", "any", false); d.Outcome != OutcomeAllow {
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
	if d := eng.DecideToolCall("p", "K", "deploy", false); d.Outcome != OutcomeAllow {
		t.Fatalf("deploy inside window should be allowed, got %v", d.Outcome)
	}
	// Wednesday 20:00 UTC — outside; rule falls through to default deny.
	outside := time.Date(2026, 7, 15, 20, 0, 0, 0, time.UTC)
	eng = NewEngine(pol, func() time.Time { return outside }, nil)
	if d := eng.DecideToolCall("p", "K", "deploy", false); d.Outcome != OutcomeDeny {
		t.Fatalf("deploy outside window should fall through to deny, got %v", d.Outcome)
	}
	// Saturday — wrong day.
	sat := time.Date(2026, 7, 18, 10, 0, 0, 0, time.UTC)
	eng = NewEngine(pol, func() time.Time { return sat }, nil)
	if d := eng.DecideToolCall("p", "K", "deploy", false); d.Outcome != OutcomeDeny {
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
	if d := eng.DecideToolCall("p", "K", "write_file", false); d.Outcome != OutcomeAllow {
		t.Fatalf("write_file should be allowed when untainted, got %v", d.Outcome)
	}
	// fetch is a taint source: allowed, and flags the session.
	d := eng.DecideToolCall("p", "K", "fetch", false)
	if d.Outcome != OutcomeAllow || !d.SetTaint {
		t.Fatalf("fetch should be allowed and set taint, got %+v", d)
	}
	// Now, with the session tainted, write_file is blocked at the network layer.
	if d := eng.DecideToolCall("p", "K", "write_file", true); d.Outcome != OutcomeDeny {
		t.Fatalf("write_file should be blocked after taint, got %v (%s)", d.Outcome, d.Reason)
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
	if d := eng.DecideToolCall("agent.mesh", "K", "transfer_funds", false); d.Outcome != OutcomeCosign {
		t.Fatalf("should require co-sign, got %v", d.Outcome)
	}
	// A human identity co-signs (peer|tool key).
	store.Approve(CosignKey("agent.mesh", "transfer_funds"))
	if d := eng.DecideToolCall("agent.mesh", "K", "transfer_funds", false); d.Outcome != OutcomeAllow {
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
