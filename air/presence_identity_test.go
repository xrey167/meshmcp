package air

import (
	"strings"
	"testing"
)

func identityFixture() []Presence {
	return []Presence{
		{Name: "Analyst", FQDN: "analyst.mesh", PublicKey: "KEY-A"},
		{Name: "Builder", FQDN: "builder.mesh", PublicKey: "KEY-B"},
		{Name: "twin", FQDN: "twin-one.mesh", PublicKey: "KEY-T1"},
		{Name: "twin", FQDN: "twin-two.mesh", PublicKey: "KEY-T2"},
	}
}

func TestResolvePresenceIdentityTiers(t *testing.T) {
	list := identityFixture()
	for _, tc := range []struct {
		selector, wantKey string
	}{
		{"pubkey:KEY-A", "KEY-A"},
		{"KEY-B", "KEY-B"},
		{"analyst.mesh", "KEY-A"},
		{"Builder", "KEY-B"},
	} {
		got, err := ResolvePresenceIdentity(list, tc.selector)
		if err != nil {
			t.Fatalf("%q: %v", tc.selector, err)
		}
		if got.PublicKey != tc.wantKey {
			t.Fatalf("%q resolved to %q, want %q", tc.selector, got.PublicKey, tc.wantKey)
		}
	}
}

func TestResolvePresenceIdentityFailsClosed(t *testing.T) {
	list := identityFixture()
	if _, err := ResolvePresenceIdentity(list, "twin"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous name must fail closed, got %v", err)
	}
	if _, err := ResolvePresenceIdentity(list, "nobody"); err == nil {
		t.Fatal("unknown selector must fail")
	}
	if _, err := ResolvePresenceIdentity(list, "bad\x00selector"); err == nil {
		t.Fatal("control characters must be rejected before matching")
	}
	// No service requirement: a node with zero advertised services resolves.
	if got, err := ResolvePresenceIdentity(list, "pubkey:KEY-A"); err != nil || len(got.Services) != 0 {
		t.Fatalf("identity resolution must not require a service: %v %v", got, err)
	}
}
