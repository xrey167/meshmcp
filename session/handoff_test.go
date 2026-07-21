package session

import (
	"errors"
	"testing"
	"time"
)

// TestHandoffRebindsIdentity proves Continuity 2.0 (F30): after a governed
// handoff, the session is owned by the NEW identity — the target may reattach,
// the former owner may not, and the original creator is no longer privileged.
// The F23 identity binding still rejects every other peer.
func TestHandoffRebindsIdentity(t *testing.T) {
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	srv := NewServer(factory, 2*time.Minute, nil)

	// Alice opens a session.
	sess, _, err := srv.attach(sessionID{}, Meta{PeerFQDN: "alice", PeerKey: "alice-key"})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	id := sess.ep.id
	defer srv.remove(id)

	// Hand the live session off to Bob.
	if err := srv.Handoff(id.String(), "bob-key"); err != nil {
		t.Fatalf("handoff: %v", err)
	}

	// Bob (the new owner) may now reattach.
	if _, resumed, err := srv.attach(id, Meta{PeerFQDN: "bob", PeerKey: "bob-key"}); err != nil || !resumed {
		t.Fatalf("new owner reattach: resumed=%v err=%v", resumed, err)
	}
	// Alice (the former owner) may no longer reattach.
	if _, _, err := srv.attach(id, Meta{PeerFQDN: "alice", PeerKey: "alice-key"}); !errors.Is(err, errSessionIdentity) {
		t.Fatalf("former owner after handoff: want errSessionIdentity, got %v", err)
	}
}

// TestHandoffPersistsForFailover proves the re-bind survives a gateway failover:
// after handoff the persisted CreatorKey is the new identity, so a second
// gateway rehydrating from the shared store admits the new owner and rejects the
// old one.
func TestHandoffPersistsForFailover(t *testing.T) {
	store := NewMemStore()
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	gw1 := NewServer(factory, 2*time.Minute, nil).WithStore(store, MigrateHandshake)

	sess, _, err := gw1.attach(sessionID{}, Meta{PeerFQDN: "alice", PeerKey: "alice-key"})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	id := sess.ep.id

	if err := gw1.Handoff(id.String(), "bob-key"); err != nil {
		t.Fatalf("handoff: %v", err)
	}
	// The store now records Bob as the creator.
	ps, ok, err := store.Load(id.String())
	if err != nil || !ok {
		t.Fatalf("load persisted: ok=%v err=%v", ok, err)
	}
	if ps.CreatorKey != "bob-key" {
		t.Fatalf("persisted CreatorKey not re-bound: %q", ps.CreatorKey)
	}
	// Simulate gw1 crashing (no clean remove, so the store entry survives).

	// A second gateway fails over from the shared store: Alice is now rejected,
	// Bob is admitted.
	gw2 := NewServer(factory, 2*time.Minute, nil).WithStore(store, MigrateHandshake)
	if _, _, err := gw2.attach(id, Meta{PeerFQDN: "alice", PeerKey: "alice-key"}); !errors.Is(err, errSessionIdentity) {
		t.Fatalf("failover for former owner: want errSessionIdentity, got %v", err)
	}
	sess2, resumed, err := gw2.attach(id, Meta{PeerFQDN: "bob", PeerKey: "bob-key"})
	if err != nil || !resumed {
		t.Fatalf("failover for new owner: resumed=%v err=%v", resumed, err)
	}
	gw2.remove(sess2.ep.id)
}

// TestHandoffUnknownAndEmpty covers the error surface.
func TestHandoffUnknownAndEmpty(t *testing.T) {
	srv := NewServer(func(Meta) (Backend, error) { return newMigBackend(), nil }, time.Minute, nil)
	sess, _, err := srv.attach(sessionID{}, Meta{PeerFQDN: "alice", PeerKey: "alice-key"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.remove(sess.ep.id)
	if err := srv.Handoff(sess.ep.id.String(), ""); err == nil {
		t.Fatalf("empty target key must be rejected")
	}
	other, _ := randID()
	if err := srv.Handoff(other.String(), "bob-key"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("unknown session: want ErrNoSession, got %v", err)
	}
}
