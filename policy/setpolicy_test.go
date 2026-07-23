package policy

import (
	"sync"
	"testing"
	"time"
)

// TestSetPolicyHotSwapsDecisions proves SetPolicy replaces the active rules in
// place: a call denied under the initial deny-by-default policy is allowed after
// a swap to a policy that permits it, and vice versa — without rebuilding the
// Engine (so rate-limit buckets and co-sign state survive a reload).
func TestSetPolicyHotSwapsDecisions(t *testing.T) {
	deny := &Policy{DefaultAllow: false}
	eng := NewEngine(deny, func() time.Time { return time.Unix(0, 0) }, nil)

	if d := eng.DecideToolCall("peer.example", "k", "search", nil); d.Allow {
		t.Fatalf("deny-by-default should deny, got %+v", d)
	}

	allow := &Policy{Rules: []Rule{{Peers: []string{"*"}, Tools: []string{"search"}, Allow: true}}}
	eng.SetPolicy(allow)
	if d := eng.DecideToolCall("peer.example", "k", "search", nil); !d.Allow {
		t.Fatalf("after swap to allow, should allow, got %+v", d)
	}

	// Swap back to deny — the change is live immediately.
	eng.SetPolicy(deny)
	if d := eng.DecideToolCall("peer.example", "k", "search", nil); d.Allow {
		t.Fatalf("after swap back to deny, should deny, got %+v", d)
	}
}

// TestSetPolicyRecomputesHash proves PolicyHash tracks the active policy across a
// swap — request-bound co-sign approvals bind to this hash, so it must change
// when the rules change and be stable when they do not.
func TestSetPolicyRecomputesHash(t *testing.T) {
	eng := NewEngine(&Policy{DefaultAllow: false}, nil, nil)
	h0 := eng.PolicyHash()
	if h0 == "" {
		t.Fatal("PolicyHash empty for a fresh engine")
	}

	eng.SetPolicy(&Policy{Rules: []Rule{{Peers: []string{"*"}, Tools: []string{"x"}, Allow: true}}})
	h1 := eng.PolicyHash()
	if h1 == h0 {
		t.Errorf("PolicyHash did not change after a rule change")
	}

	// Swapping to an identical policy yields the same hash (stable).
	eng.SetPolicy(&Policy{DefaultAllow: false})
	if eng.PolicyHash() != h0 {
		t.Errorf("PolicyHash for an equal policy is not stable: %q != %q", eng.PolicyHash(), h0)
	}

	// A nil policy is a no-op (never clears the active policy).
	eng.SetPolicy(nil)
	if eng.PolicyHash() != h0 {
		t.Errorf("SetPolicy(nil) changed the active policy")
	}
}

// TestSetPolicyConcurrentWithDecisions is the race-detector guard: many
// decisions run concurrently with policy swaps. It asserts no data race (via
// -race) and that every decision returns a well-formed outcome regardless of
// which policy snapshot it observed.
func TestSetPolicyConcurrentWithDecisions(t *testing.T) {
	eng := NewEngine(&Policy{DefaultAllow: false}, func() time.Time { return time.Unix(0, 0) }, nil)
	allow := &Policy{Rules: []Rule{{Peers: []string{"*"}, Tools: []string{"search"}, Allow: true}}}
	deny := &Policy{DefaultAllow: false}

	stop := make(chan struct{})
	var swapper sync.WaitGroup
	swapper.Add(1)
	go func() {
		defer swapper.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				eng.SetPolicy(allow)
			} else {
				eng.SetPolicy(deny)
			}
			_ = eng.PolicyHash()
		}
	}()

	// Bounded deciders: wait only on these, then stop the (unbounded) swapper.
	var deciders sync.WaitGroup
	for g := 0; g < 8; g++ {
		deciders.Add(1)
		go func() {
			defer deciders.Done()
			for i := 0; i < 2000; i++ {
				d := eng.DecideToolCall("peer.example", "k", "search", nil)
				switch d.Outcome {
				case OutcomeAllow, OutcomeDeny, OutcomeCosign:
				default:
					t.Errorf("decision produced an invalid outcome %q", d.Outcome)
					return
				}
			}
		}()
	}
	deciders.Wait()
	close(stop)
	swapper.Wait()
}
