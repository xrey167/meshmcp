package policy

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestSSOGroups_BindAndInGroup(t *testing.T) {
	cur := time.Unix(1000, 0)
	s := NewSSOGroups(func() time.Time { return cur })
	s.Bind("keyA", OIDCClaims{Subject: "u1", Groups: []string{"finance", "eng"}}, time.Unix(2000, 0))

	if !s.InGroup("keyA", "", "finance") {
		t.Fatal("bound group finance should match")
	}
	if !s.InGroup("keyA", "ignored-fqdn", "eng") {
		t.Fatal("bound group eng should match (fqdn is ignored)")
	}
	if s.InGroup("keyA", "", "admin") {
		t.Fatal("unbound group admin must not match")
	}
}

func TestSSOGroups_PerTransportKeyIsolation(t *testing.T) {
	cur := time.Unix(1000, 0)
	s := NewSSOGroups(func() time.Time { return cur })
	// keyA is attributed finance; keyB presents/binds nothing.
	s.Bind("keyA", OIDCClaims{Groups: []string{"finance"}}, time.Unix(2000, 0))

	if s.InGroup("keyB", "", "finance") {
		t.Fatal("keyB has no binding — its InGroup must be false; attribution is strictly per transport key")
	}
	if s.InGroup("", "", "finance") {
		t.Fatal("a blank transport key must never match")
	}
}

func TestSSOGroups_ExpiryEviction(t *testing.T) {
	cur := time.Unix(1000, 0)
	s := NewSSOGroups(func() time.Time { return cur })
	s.Bind("keyA", OIDCClaims{Groups: []string{"finance"}}, time.Unix(2000, 0))

	if !s.InGroup("keyA", "", "finance") {
		t.Fatal("should match before expiry")
	}
	cur = time.Unix(2000, 0) // now == exp: expired (now >= exp)
	if s.InGroup("keyA", "", "finance") {
		t.Fatal("a previously valid binding must not match once now >= exp")
	}
	// A second read confirms lazy eviction removed it (no resurrection).
	cur = time.Unix(1500, 0) // even rewinding the clock, the binding is gone
	if s.InGroup("keyA", "", "finance") {
		t.Fatal("evicted binding must stay gone")
	}
}

func TestSSOGroups_ImmutableReplace(t *testing.T) {
	cur := time.Unix(1000, 0)
	s := NewSSOGroups(func() time.Time { return cur })
	s.Bind("keyA", OIDCClaims{Groups: []string{"finance"}}, time.Unix(2000, 0))
	// Re-bind with a different group set — the prior groups must not persist.
	s.Bind("keyA", OIDCClaims{Groups: []string{"ops"}}, time.Unix(2000, 0))

	if s.InGroup("keyA", "", "finance") {
		t.Fatal("re-bind must replace the group set (finance should be gone)")
	}
	if !s.InGroup("keyA", "", "ops") {
		t.Fatal("re-bind must install the new group set (ops)")
	}
}

func TestSSOGroups_BlankKeyBindIgnored(t *testing.T) {
	cur := time.Unix(1000, 0)
	s := NewSSOGroups(func() time.Time { return cur })
	s.Bind("", OIDCClaims{Groups: []string{"finance"}}, time.Unix(2000, 0))
	if s.InGroup("", "", "finance") {
		t.Fatal("binding to a blank key must be a no-op")
	}
}

func TestCombinedGroups_ORsResolvers(t *testing.T) {
	cur := time.Unix(1000, 0)
	static := StaticGroups{"admins": {"pubkey:alice"}}
	sso := NewSSOGroups(func() time.Time { return cur })
	sso.Bind("bob", OIDCClaims{Groups: []string{"finance"}}, time.Unix(2000, 0))
	c := CombinedGroups{static, sso}

	if !c.InGroup("alice", "", "admins") {
		t.Fatal("static membership must match through the combinator")
	}
	if !c.InGroup("bob", "", "finance") {
		t.Fatal("SSO membership must match through the combinator")
	}
	if c.InGroup("bob", "", "admins") {
		t.Fatal("bob is not a static admin")
	}
	if c.InGroup("alice", "", "finance") {
		t.Fatal("alice has no SSO binding")
	}
}

func TestCombinedGroups_NilMembersSkipped(t *testing.T) {
	c := CombinedGroups{nil, StaticGroups{"g": {"pubkey:k"}}, nil}
	if !c.InGroup("k", "", "g") {
		t.Fatal("nil resolvers must be skipped, not panic")
	}
	if c.InGroup("k", "", "other") {
		t.Fatal("no resolver grants 'other'")
	}
}

// The store is read concurrently by every backend's engine (InGroup) while the
// attest handler writes (Bind); exercise that under -race.
func TestSSOGroups_ConcurrentBindInGroup(t *testing.T) {
	s := NewSSOGroups(func() time.Time { return time.Unix(1000, 0) })
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		key := fmt.Sprintf("key-%d", i)
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.Bind(key, OIDCClaims{Groups: []string{"finance"}}, time.Unix(2000, 0))
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = s.InGroup(key, "", "finance")
			}
		}()
	}
	wg.Wait()
}

// End-to-end at the policy layer: a group:<sso-group> rule matches an
// SSO-attributed caller through the Engine's single resolver slot, and stops
// matching once the binding expires — mirroring groups_test.go's static case.
func TestSSOGroups_EngineGroupRuleMatches(t *testing.T) {
	cur := time.Unix(1000, 0)
	clk := func() time.Time { return cur }
	pol := &Policy{DefaultAllow: false, Rules: []Rule{
		{Peers: []string{"group:finance"}, Tools: []string{"pay"}, Allow: true},
	}}
	sso := NewSSOGroups(clk)
	e := NewEngine(pol, clk, nil)
	e.SetGroupResolver(CombinedGroups{StaticGroups(nil), sso})

	// Unbound: the group rule cannot match → default deny.
	if d := e.DecideToolCall("host", "keyA", "pay", nil); d.Outcome != OutcomeDeny {
		t.Fatalf("unbound caller should be denied, got %v", d.Outcome)
	}
	// Bind finance to keyA → the rule now matches → allow.
	sso.Bind("keyA", OIDCClaims{Groups: []string{"finance"}}, time.Unix(2000, 0))
	if d := e.DecideToolCall("host", "keyA", "pay", nil); d.Outcome != OutcomeAllow {
		t.Fatalf("SSO-attributed caller should be allowed, got %v", d.Outcome)
	}
	// A different key never inherits keyA's binding.
	if d := e.DecideToolCall("host", "keyB", "pay", nil); d.Outcome != OutcomeDeny {
		t.Fatalf("unrelated key must not inherit the binding, got %v", d.Outcome)
	}
	// After expiry the binding stops matching → deny again.
	cur = time.Unix(2000, 0)
	if d := e.DecideToolCall("host", "keyA", "pay", nil); d.Outcome != OutcomeDeny {
		t.Fatalf("expired binding should deny, got %v", d.Outcome)
	}
}
