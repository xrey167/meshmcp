package policy

import "testing"

func TestGroupBasedPolicy(t *testing.T) {
	pol := &Policy{DefaultAllow: false, Rules: []Rule{
		{Peers: []string{"group:admins"}, Tools: []string{"deploy"}, Allow: true},
	}}
	groups := StaticGroups{"admins": {"pubkey:alice-key", "ops-*.netbird.cloud"}}
	e := NewEngine(pol, nil, nil)
	e.SetGroupResolver(groups)

	// A member by pubkey is allowed.
	if d := e.DecideToolCall("whoever", "alice-key", "deploy", nil); d.Outcome != OutcomeAllow {
		t.Fatalf("group member (pubkey) should be allowed, got %v", d.Outcome)
	}
	// A member by FQDN glob is allowed.
	if d := e.DecideToolCall("ops-3.netbird.cloud", "k", "deploy", nil); d.Outcome != OutcomeAllow {
		t.Fatalf("group member (fqdn glob) should be allowed, got %v", d.Outcome)
	}
	// A non-member is denied (default deny).
	if d := e.DecideToolCall("intern.netbird.cloud", "bob-key", "deploy", nil); d.Outcome != OutcomeDeny {
		t.Fatalf("non-member should be denied, got %v", d.Outcome)
	}
	// With no resolver, a group: rule never matches → default deny.
	e2 := NewEngine(pol, nil, nil)
	if d := e2.DecideToolCall("x", "alice-key", "deploy", nil); d.Outcome != OutcomeDeny {
		t.Fatalf("no resolver → group rule must not match, got %v", d.Outcome)
	}
}
