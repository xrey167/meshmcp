package policy

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRateLimitPartialRefillAccrues: the bucket refills continuously by elapsed
// time — half the window restores half the budget, and the balance never
// exceeds Max. A variant that only resets on full-window boundaries fails the
// mid-window allowance; one that forgets the cap fails the burst check.
func TestRateLimitPartialRefillAccrues(t *testing.T) {
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	pol := &Policy{Rules: []Rule{
		{Peers: []string{"*"}, Tools: []string{"*"}, Allow: true, Rate: &RateLimit{Max: 2, Per: "10s"}},
	}}
	eng := NewEngine(pol, func() time.Time { return now }, nil)

	allow := func() bool { return eng.DecideToolCall("p", "K", "t", nil).Outcome == OutcomeAllow }
	if !allow() || !allow() {
		t.Fatal("initial budget of 2 must allow two calls")
	}
	if allow() {
		t.Fatal("third call in the same instant must be limited")
	}
	// Half the window elapses: exactly one token has accrued.
	now = now.Add(5 * time.Second)
	if !allow() {
		t.Fatal("half a window must restore one token")
	}
	if allow() {
		t.Fatal("only ONE token accrues over half a window")
	}
	// A long idle period restores the budget but never beyond Max.
	now = now.Add(10 * time.Minute)
	if !allow() || !allow() {
		t.Fatal("a full window must restore the full budget")
	}
	if allow() {
		t.Fatal("idle time must not accrue tokens beyond Max (no burst banking)")
	}
}

// TestRateLimitMaxZeroBypasses: Max <= 0 disables the limiter for the rule —
// every call passes — while the rule's Cost is still surfaced for accounting.
func TestRateLimitMaxZeroBypasses(t *testing.T) {
	pol := &Policy{Rules: []Rule{
		{Peers: []string{"*"}, Tools: []string{"*"}, Allow: true, Rate: &RateLimit{Max: 0, Per: "1s", Cost: 5}},
	}}
	eng := NewEngine(pol, nil, nil)
	for i := 0; i < 50; i++ {
		d := eng.DecideToolCall("p", "K", "t", nil)
		if d.Outcome != OutcomeAllow {
			t.Fatalf("call %d: Max<=0 must never limit, got %v", i, d.Outcome)
		}
		if d.Cost != 5 {
			t.Fatalf("call %d: cost must still be surfaced, got %d", i, d.Cost)
		}
	}
}

// TestRateLimitBadPerDefaultsToOneSecond: an empty, unparseable, or
// non-positive Per falls back to a one-second window rather than disabling or
// inflating the limit.
func TestRateLimitBadPerDefaultsToOneSecond(t *testing.T) {
	for _, per := range []string{"", "bogus", "-5s"} {
		t.Run("per="+per, func(t *testing.T) {
			now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
			pol := &Policy{Rules: []Rule{
				{Peers: []string{"*"}, Tools: []string{"*"}, Allow: true, Rate: &RateLimit{Max: 1, Per: per}},
			}}
			eng := NewEngine(pol, func() time.Time { return now }, nil)
			if d := eng.DecideToolCall("p", "K", "t", nil); d.Outcome != OutcomeAllow {
				t.Fatalf("first call must pass, got %v", d.Outcome)
			}
			if d := eng.DecideToolCall("p", "K", "t", nil); d.Outcome != OutcomeDeny {
				t.Fatalf("second call in the same instant must be limited, got %v", d.Outcome)
			}
			// One second refills the whole (defaulted) window.
			now = now.Add(time.Second)
			if d := eng.DecideToolCall("p", "K", "t", nil); d.Outcome != OutcomeAllow {
				t.Fatalf("after 1s the defaulted window must refill, got %v", d.Outcome)
			}
		})
	}
}

// TestCosignConsumedDecisionCarriesCost: an allow produced through the
// ambient co-sign path (engine.go's "co-signed" branch) still surfaces the
// rule's cost, so approved privileged calls are charged like any other.
func TestCosignConsumedDecisionCarriesCost(t *testing.T) {
	pol := &Policy{DefaultAllow: false, Rules: []Rule{
		{Peers: []string{"*"}, Tools: []string{"transfer"}, Allow: true,
			RequireCosign: true, Rate: &RateLimit{Max: 100, Per: "1h", Cost: 7}},
	}}
	store := NewMemCosign()
	eng := NewEngine(pol, nil, store)

	// Held pending co-sign: nothing consumed, nothing charged.
	if d := eng.DecideToolCall("a.mesh", "K", "transfer", nil); d.Outcome != OutcomeCosign || d.Cost != 0 {
		t.Fatalf("pending cosign must not charge, got %+v", d)
	}
	store.Approve(CosignKey("a.mesh", "transfer"))
	d := eng.DecideToolCall("a.mesh", "K", "transfer", nil)
	if d.Outcome != OutcomeAllow {
		t.Fatalf("co-signed call should be allowed, got %v (%s)", d.Outcome, d.Reason)
	}
	if d.Cost != 7 {
		t.Fatalf("co-signed allow must carry the rule cost, got %d", d.Cost)
	}
}

// TestBoundCosignConsumeCarriesCostAndIsSingleUse: the request-bound co-sign
// branch — a granted approval is consumed exactly once (the second identical
// call is held again), and the consuming allow carries the rule's cost.
func TestBoundCosignConsumeCarriesCostAndIsSingleUse(t *testing.T) {
	now := func() time.Time { return time.Unix(1000, 0) }
	pol := &Policy{DefaultAllow: false, Rules: []Rule{
		{Peers: []string{"*"}, Tools: []string{"transfer"}, Allow: true,
			RequireCosign: true, Rate: &RateLimit{Max: 100, Per: "1h", Cost: 9}},
	}}
	signer := mustSigner(t)
	store := NewFileApprovalStore(t.TempDir(), time.Minute, signer)
	eng := NewEngine(pol, now, nil)
	eng.SetRequestApprovals(store)

	args := []byte(`{"amount":10}`)
	// No approval yet: held.
	if d := eng.DecideToolCallBound("a.mesh", "PK", "pay", "transfer", args, nil); d.Outcome != OutcomeCosign {
		t.Fatalf("unapproved bound call must be held, got %v", d.Outcome)
	}
	req := NewApprovalRequest("PK", "pay", "transfer", args, "")
	if _, err := store.Grant(req, "approver", eng.PolicyHash(), now()); err != nil {
		t.Fatal(err)
	}
	d := eng.DecideToolCallBound("a.mesh", "PK", "pay", "transfer", args, nil)
	if d.Outcome != OutcomeAllow {
		t.Fatalf("granted bound call should consume and allow, got %v (%s)", d.Outcome, d.Reason)
	}
	if d.Cost != 9 {
		t.Fatalf("bound-consume allow must carry the rule cost, got %d", d.Cost)
	}
	// Single-use: the identical call is held again.
	if d := eng.DecideToolCallBound("a.mesh", "PK", "pay", "transfer", args, nil); d.Outcome != OutcomeCosign {
		t.Fatalf("replay after consume must be held, got %v", d.Outcome)
	}
}

// TestEngineConcurrentBoundConsumeSingleWinner: many concurrent bound decisions
// racing on ONE approval — exactly one may allow; the rest are held. This is
// the engine-level restatement of the store's single-use contract.
func TestEngineConcurrentBoundConsumeSingleWinner(t *testing.T) {
	now := func() time.Time { return time.Unix(1000, 0) }
	pol := &Policy{DefaultAllow: false, Rules: []Rule{
		{Peers: []string{"*"}, Tools: []string{"transfer"}, Allow: true, RequireCosign: true},
	}}
	signer := mustSigner(t)
	store := NewFileApprovalStore(t.TempDir(), time.Minute, signer)
	eng := NewEngine(pol, now, nil)
	eng.SetRequestApprovals(store)

	args := []byte(`{"amount":10}`)
	req := NewApprovalRequest("PK", "pay", "transfer", args, "")
	if _, err := store.Grant(req, "approver", eng.PolicyHash(), now()); err != nil {
		t.Fatal(err)
	}

	var allows, holds int64
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch d := eng.DecideToolCallBound("a.mesh", "PK", "pay", "transfer", args, nil); d.Outcome {
			case OutcomeAllow:
				atomic.AddInt64(&allows, 1)
			case OutcomeCosign:
				atomic.AddInt64(&holds, 1)
			default:
				t.Errorf("unexpected outcome %v (%s)", d.Outcome, d.Reason)
			}
		}()
	}
	wg.Wait()
	if allows != 1 || holds != 15 {
		t.Fatalf("exactly one racer may consume the approval: allows=%d holds=%d", allows, holds)
	}
}
