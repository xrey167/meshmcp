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

// registerSession installs a hand-built live session (with a working backend,
// so remove/Shutdown can close it) into the server's session map.
func registerSession(srv *Server, id sessionID, leaseGen uint64, meta Meta) *serverSession {
	sess := &serverSession{
		ep:         newEndpoint(id),
		backend:    newMigBackend(),
		creatorKey: "CREATOR",
		leaseGen:   leaseGen,
		meta:       meta,
	}
	srv.mu.Lock()
	srv.sessions[id] = sess
	srv.mu.Unlock()
	return sess
}

// TestRenewOnceExtendsLease: the renewal heartbeat pushes the store-observed
// expiry forward while preserving the generation — renewal is liveness, never
// an ownership change.
func TestRenewOnceExtendsLease(t *testing.T) {
	store := NewMemStore()
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	srv := NewServer(factory, time.Minute, nil).WithStore(store, MigrateHandshake)

	id, _ := randID()
	t0 := time.Unix(1000, 0)
	l, ok, err := store.AcquireLease(id.String(), srv.instance, 0, srv.ttl, t0)
	if err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	registerSession(srv, id, l.Generation, Meta{})

	t1 := t0.Add(30 * time.Second)
	srv.renewOnce(t1)

	ps, present, err := store.Load(id.String())
	if err != nil || !present {
		t.Fatalf("load after renew: present=%v err=%v", present, err)
	}
	if ps.Generation != l.Generation {
		t.Fatalf("renewal changed the generation: %d -> %d", l.Generation, ps.Generation)
	}
	if want := t1.Add(srv.ttl).UnixNano(); ps.LeaseExpiry != want {
		t.Fatalf("renewal did not extend the expiry: got %d, want %d", ps.LeaseExpiry, want)
	}
	if srv.Count() != 1 {
		t.Fatalf("renewal must retain the session, count=%d", srv.Count())
	}
	srv.remove(id)
}

// TestRenewOnceFencedYields: a renewal refused because another gateway took the
// session over is the same event as a fenced checkpoint, and gets the same
// answer — yield the session, touch nothing in the store.
func TestRenewOnceFencedYields(t *testing.T) {
	store := NewMemStore()
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	srv := NewServer(factory, time.Minute, nil).WithStore(store, MigrateHandshake)

	id, _ := randID()
	t0 := time.Unix(1000, 0)
	l, _, _ := store.AcquireLease(id.String(), srv.instance, 0, srv.ttl, t0)
	registerSession(srv, id, l.Generation, Meta{})

	// Another gateway takes over (identity-bound reattach elsewhere).
	l2, ok, _ := store.TakeoverLease(id.String(), "gw2", l.Generation, time.Minute, t0.Add(time.Second))
	if !ok {
		t.Fatal("gw2 takeover should succeed")
	}

	srv.renewOnce(t0.Add(2 * time.Second))

	if srv.Count() != 0 {
		t.Fatalf("fenced renewal must yield the session, count=%d", srv.Count())
	}
	ps, present, _ := store.Load(id.String())
	if !present {
		t.Fatal("the yielding gateway deleted the new owner's record")
	}
	if ps.Owner != "gw2" || ps.Generation != l2.Generation {
		t.Fatalf("new owner's record disturbed: owner=%q gen=%d, want gw2/%d", ps.Owner, ps.Generation, l2.Generation)
	}
}

// TestRenewOnceSkipsDegradedSession: a session whose lease acquire failed at
// create (leaseGen 0) has nothing to renew — the tick must not invent a store
// record for it, and must retain it.
func TestRenewOnceSkipsDegradedSession(t *testing.T) {
	store := NewMemStore()
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	srv := NewServer(factory, time.Minute, nil).WithStore(store, MigrateHandshake)

	id, _ := randID()
	registerSession(srv, id, 0, Meta{})

	srv.renewOnce(time.Unix(1000, 0))

	if srv.Count() != 1 {
		t.Fatalf("degraded session must be retained, count=%d", srv.Count())
	}
	if _, present, _ := store.Load(id.String()); present {
		t.Fatal("renewing a degraded (gen 0) session must not create a store record")
	}
	srv.remove(id)
}

// TestShutdownDegradedSessionNeverWrites: a session whose lease acquire failed
// at create (leaseGen 0) holds no fencing generation, so on a lease-capable
// store its checkpoints — including Shutdown's final one — must never write.
// An unfenced Save would overwrite a record another gateway has since taken
// over at generation >= 1 (TakeoverLease accepts generation-0 records),
// regressing the monotonic generation and fencing the LIVE owner out of its
// own session.
func TestShutdownDegradedSessionNeverWrites(t *testing.T) {
	store := NewMemStore()
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	gw1 := NewServer(factory, time.Minute, nil).WithStore(store, MigrateHandshake)

	// A degraded session with no store record at all: Shutdown must not invent
	// one.
	idA, _ := randID()
	registerSession(gw1, idA, 0, Meta{PeerFQDN: "alice.mesh"})

	// A degraded session whose generation-0 record (written by an older,
	// unfenced build) was since taken over by gw2 at generation 1.
	idB, _ := randID()
	if err := store.Save(PersistedSession{ID: idB.String(), Owner: gw1.instance, CreatorKey: "CREATOR"}); err != nil {
		t.Fatal(err)
	}
	registerSession(gw1, idB, 0, Meta{PeerFQDN: "alice.mesh"})
	l2, ok, _ := store.TakeoverLease(idB.String(), "gw2", 0, time.Minute, time.Now())
	if !ok {
		t.Fatal("gw2 takeover of the generation-0 record should succeed")
	}
	if ok, _ := store.SaveIfOwned(PersistedSession{ID: idB.String(), Owner: "gw2", CreatorKey: "CREATOR", SendSeq: 9}, "gw2", l2.Generation); !ok {
		t.Fatal("gw2 should checkpoint after its takeover")
	}

	gw1.Shutdown()

	if _, present, _ := store.Load(idA.String()); present {
		t.Fatal("shutdown of a degraded session must not write an unfenced record")
	}
	cur, present, _ := store.Load(idB.String())
	if !present {
		t.Fatal("gw2's record vanished")
	}
	if cur.Owner != "gw2" || cur.Generation != l2.Generation || cur.SendSeq != 9 {
		t.Fatalf("degraded gw1's shutdown clobbered the live owner: owner=%q gen=%d seq=%d, want gw2/%d/9",
			cur.Owner, cur.Generation, cur.SendSeq, l2.Generation)
	}
}

// TestShutdownReleasesLeases: a clean stop checkpoints and RELEASES each
// session (owner cleared, generation + state preserved) rather than deleting
// it, so a peer gateway claims instantly at the current generation.
func TestShutdownReleasesLeases(t *testing.T) {
	store := NewMemStore()
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	gw1 := NewServer(factory, time.Minute, nil).WithStore(store, MigrateHandshake)

	id, _ := randID()
	t0 := time.Unix(1000, 0)
	l, ok, _ := store.AcquireLease(id.String(), gw1.instance, 0, gw1.ttl, t0)
	if !ok {
		t.Fatal("acquire should succeed")
	}
	registerSession(gw1, id, l.Generation, Meta{PeerFQDN: "alice.mesh", PeerAddr: "100.64.0.9:1"})

	gw1.Shutdown()

	if gw1.Count() != 0 {
		t.Fatalf("shutdown must drain the session map, count=%d", gw1.Count())
	}
	ps, present, err := store.Load(id.String())
	if err != nil || !present {
		t.Fatalf("session state must survive a clean shutdown: present=%v err=%v", present, err)
	}
	if ps.Owner != "" || ps.LeaseExpiry != 0 {
		t.Fatalf("lease not released: owner=%q expiry=%d", ps.Owner, ps.LeaseExpiry)
	}
	if ps.Generation != l.Generation {
		t.Fatalf("release must preserve the generation: got %d, want %d", ps.Generation, l.Generation)
	}
	if ps.CreatorKey != "CREATOR" || ps.PeerFQDN != "alice.mesh" || ps.PeerAddr != "100.64.0.9:1" {
		t.Fatalf("final checkpoint must stamp the creator identity: %+v", ps)
	}

	// A second gateway claims immediately — no expiry wait.
	gw2 := NewServer(factory, time.Minute, nil).WithStore(store, MigrateHandshake)
	l2, ok, err := store.AcquireLease(id.String(), gw2.instance, ps.Generation, gw2.ttl, t0.Add(time.Second))
	if err != nil || !ok {
		t.Fatalf("released lease should be immediately claimable: ok=%v err=%v", ok, err)
	}
	if l2.Generation != l.Generation+1 {
		t.Fatalf("claim after release must bump the generation: %d -> %d", l.Generation, l2.Generation)
	}
}
