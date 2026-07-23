package main

import (
	"strings"
	"testing"
)

// The Steer identity-binding contract: exactly one live session carrying the
// resolved node's transport-stamped public key; anything else fails closed.
func TestIdentityBoundSession(t *testing.T) {
	sessions := []AirSession{
		{Backend: "fs", ID: "s1", Peer: "analyst.mesh", PeerKey: "KEY-A"},
		{Backend: "kg", ID: "s2", Peer: "builder.mesh", PeerKey: "KEY-B"},
		{Backend: "fs", ID: "s3", Peer: "builder.mesh", PeerKey: "KEY-B"},
		{Backend: "fs", ID: "s4", Peer: "legacy.mesh"}, // no peer_key (older gateway)
	}

	got, err := identityBoundSession(sessions, "KEY-A")
	if err != nil || got.Backend != "fs" || got.ID != "s1" {
		t.Fatalf("single match: got %+v, %v", got, err)
	}

	if _, err := identityBoundSession(sessions, "KEY-B"); err == nil || !strings.Contains(err.Error(), "--backend") {
		t.Fatalf("multiple matches must fail closed with explicit-flags guidance, got %v", err)
	}
	if _, err := identityBoundSession(sessions, "KEY-Z"); err == nil {
		t.Fatal("zero matches must fail closed")
	}
	// An empty resolved key must never match the legacy no-key session.
	if _, err := identityBoundSession(sessions, ""); err == nil {
		t.Fatal("empty public key must be rejected, not matched against key-less sessions")
	}
}
