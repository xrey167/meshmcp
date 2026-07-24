package session

import (
	"errors"
	"testing"
	"time"
)

// TestSessionReattachIdentityBinding proves a resumable session can be
// reattached only by the cryptographic identity that opened it — a mesh peer
// that merely learns the session id cannot take it over (P0-1 / F23).
func TestSessionReattachIdentityBinding(t *testing.T) {
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	srv := NewServer(factory, 2*time.Minute, nil)

	// Alice opens a session (zero id → create).
	sess, resumed, err := srv.attach(sessionID{}, Meta{PeerFQDN: "alice", PeerKey: "alice-key"})
	if err != nil || resumed {
		t.Fatalf("open: resumed=%v err=%v", resumed, err)
	}
	id := sess.ep.id
	defer srv.remove(id)

	// Mallory learns the id and tries to reattach — must be rejected.
	if _, _, err := srv.attach(id, Meta{PeerFQDN: "mallory", PeerKey: "mallory-key"}); !errors.Is(err, errSessionIdentity) {
		t.Fatalf("takeover by foreign identity: want errSessionIdentity, got %v", err)
	}

	// Alice reattaches with her own key — must succeed as a resume.
	if _, resumed, err := srv.attach(id, Meta{PeerFQDN: "alice", PeerKey: "alice-key"}); err != nil || !resumed {
		t.Fatalf("legitimate reattach: resumed=%v err=%v", resumed, err)
	}
}

// TestSessionReattachEmptyKeyFailsClosed proves the identity binding fails
// closed when the transport could not attribute a peer (empty PeerKey). A
// session opened by an unattributable peer must never be reattachable by
// another unattributable peer — "" must not match "" — mirroring the
// empty-identity guards on the move/failover paths.
func TestSessionReattachEmptyKeyFailsClosed(t *testing.T) {
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	srv := NewServer(factory, 2*time.Minute, nil)

	// An FQDN-only peer (no resolved pubkey) opens a session.
	sess, resumed, err := srv.attach(sessionID{}, Meta{PeerFQDN: "alice.mesh", PeerKey: ""})
	if err != nil || resumed {
		t.Fatalf("open: resumed=%v err=%v", resumed, err)
	}
	id := sess.ep.id
	defer srv.remove(id)

	// A DIFFERENT unattributable peer learns the id and tries to reattach: the
	// empty key must not match the empty creator key.
	if _, _, err := srv.attach(id, Meta{PeerFQDN: "mallory.mesh", PeerKey: ""}); !errors.Is(err, errSessionIdentity) {
		t.Fatalf("empty-key takeover: want errSessionIdentity, got %v", err)
	}
}

func TestUnknownResumeSessionIsRejected(t *testing.T) {
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	srv := NewServer(factory, time.Minute, nil)
	id, err := randID()
	if err != nil {
		t.Fatal(err)
	}
	if _, resumed, err := srv.attach(id, Meta{PeerFQDN: "alice", PeerKey: "alice-key"}); !errors.Is(err, errSessionNotFound) || resumed {
		t.Fatalf("unknown resume = resumed:%v err:%v, want terminal not-found", resumed, err)
	}
}

// TestSessionRehydrateIdentityBinding proves the identity binding also holds
// across a gateway failover: a rehydrating gateway must reject a reattach from
// any identity other than the session's original creator.
func TestSessionRehydrateIdentityBinding(t *testing.T) {
	store := NewMemStore()
	newID, err := randID()
	if err != nil {
		t.Fatal(err)
	}
	// A session persisted by another gateway, created by alice.
	ps := (&endpoint{id: newID}).snapshot(nil, 0)
	ps.CreatorKey = "alice-key"
	ps.Owner = "gw1"
	if err := store.Save(ps); err != nil {
		t.Fatal(err)
	}

	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	srv := NewServer(factory, 2*time.Minute, nil).WithStore(store, MigrateHandshake)

	// Mallory tries to rehydrate-and-take-over — rejected before any backend spawns.
	if _, _, err := srv.attach(newID, Meta{PeerFQDN: "mallory", PeerKey: "mallory-key"}); !errors.Is(err, errSessionIdentity) {
		t.Fatalf("rehydrate takeover: want errSessionIdentity, got %v", err)
	}

	// Alice legitimately fails over — the session rehydrates.
	sess, resumed, err := srv.attach(newID, Meta{PeerFQDN: "alice", PeerKey: "alice-key"})
	if err != nil || !resumed {
		t.Fatalf("legitimate failover: resumed=%v err=%v", resumed, err)
	}
	srv.remove(sess.ep.id)
}
