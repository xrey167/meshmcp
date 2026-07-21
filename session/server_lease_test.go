package session

import (
	"testing"
	"time"
)

// TestServerCheckpointFencedAfterTakeover is the split-brain regression: once a
// second gateway takes over a session (an authenticated reattach), the original
// gateway's checkpoint must be FENCED — it cannot overwrite the new owner's
// persisted state, so the same session is never driven by two gateways at once.
func TestServerCheckpointFencedAfterTakeover(t *testing.T) {
	store := NewMemStore()
	nopFactory := func(Meta) (Backend, error) { return nil, nil }
	gw1 := NewServer(nopFactory, time.Minute, nil).WithStore(store, MigrateHandshake)

	id, _ := randID()

	// gw1 opens the session: it holds the lease and checkpoints successfully.
	l1, ok, _ := store.AcquireLease(id.String(), gw1.instance, 0, time.Minute, time.Now())
	if !ok {
		t.Fatal("gw1 should acquire the lease for a fresh session")
	}
	sess := &serverSession{ep: newEndpoint(id), creatorKey: "CREATOR", leaseGen: l1.Generation}
	gw1.checkpoint(sess)
	if _, present, _ := store.Load(id.String()); !present {
		t.Fatal("gw1 checkpoint should have persisted the session")
	}

	// gw2 takes over via an identity-bound reattach (bumps the generation).
	l2, ok, _ := store.TakeoverLease(id.String(), "gw2", l1.Generation, time.Minute, time.Now())
	if !ok {
		t.Fatal("gw2 should take over the session")
	}
	if ok, _ := store.SaveIfOwned(PersistedSession{ID: id.String(), Owner: "gw2", CreatorKey: "CREATOR"}, "gw2", l2.Generation); !ok {
		t.Fatal("gw2 should be able to write after takeover")
	}

	// gw1 checkpoints again — it is fenced and must NOT clobber gw2's ownership.
	gw1.checkpoint(sess)
	cur, _, _ := store.Load(id.String())
	if cur.Owner != "gw2" {
		t.Fatalf("a fenced gateway overwrote the new owner's state: owner=%q, want gw2", cur.Owner)
	}
}
