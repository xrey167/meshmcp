package session

import "testing"

// TestLeaseDeleteIfOwner verifies that a store entry is only deleted by the
// gateway that still holds the lease — the mechanism that makes a live roam
// between two running gateways safe.
func TestLeaseDeleteIfOwner(t *testing.T) {
	s := NewMemStore()
	_ = s.Save(PersistedSession{ID: "x", Owner: "gw1"})

	// A non-owner delete is a no-op.
	_ = s.DeleteIfOwner("x", "gw2")
	if _, ok, _ := s.Load("x"); !ok {
		t.Fatal("non-owner delete should have been a no-op")
	}

	// gw2 takes over the lease.
	_ = s.Save(PersistedSession{ID: "x", Owner: "gw2"})

	// gw1's stale reaper must not delete the session gw2 now owns.
	_ = s.DeleteIfOwner("x", "gw1")
	if _, ok, _ := s.Load("x"); !ok {
		t.Fatal("superseded gateway must not delete the resumed session")
	}

	// The current owner can delete.
	_ = s.DeleteIfOwner("x", "gw2")
	if _, ok, _ := s.Load("x"); ok {
		t.Fatal("current owner delete should have removed it")
	}
}
