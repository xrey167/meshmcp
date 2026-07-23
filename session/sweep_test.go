package session

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// newStandbyServer builds a sweep-enabled server over store.
func newStandbyServer(store SessionStore, ttl time.Duration, factory BackendFactory) *Server {
	return NewServer(factory, ttl, nil).
		WithStore(store, MigrateHandshake).
		WithFailover(FailoverConfig{Enabled: true})
}

// metaFactory records the Meta each spawned backend was given, so a test can
// prove an adoption respawns under the persisted creator identity.
type metaFactory struct {
	mu    sync.Mutex
	metas []Meta
}

func (f *metaFactory) factory(meta Meta) (Backend, error) {
	f.mu.Lock()
	f.metas = append(f.metas, meta)
	f.mu.Unlock()
	return newMigBackend(), nil
}

func (f *metaFactory) spawned() []Meta {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Meta(nil), f.metas...)
}

// TestSweepEligibility drives the full candidate matrix through one sweep:
// only an expired-past-margin lease and a released lease are adopted. A live
// lease, an expired-but-inside-margin lease, a record without the persisted
// creator FQDN, a degraded (generation 0, unfenceable-owner) record, and a
// record written by a newer build (schema this build may misread) are all left
// alone.
func TestSweepEligibility(t *testing.T) {
	store := NewMemStore()
	ttl := time.Minute
	mf := &metaFactory{}
	srv := newStandbyServer(store, ttl, mf.factory)
	now := time.Unix(100000, 0)

	mkid := func() string {
		id, err := randID()
		if err != nil {
			t.Fatal(err)
		}
		return id.String()
	}
	base := func() PersistedSession {
		return PersistedSession{ID: mkid(), Owner: "gw1", CreatorKey: "alice-key", PeerFQDN: "alice.mesh", PeerAddr: "100.64.0.9:1", Generation: 1}
	}

	live := base()
	live.LeaseExpiry = now.Add(ttl).UnixNano()
	insideMargin := base()
	insideMargin.LeaseExpiry = now.Add(-ttl).UnixNano() // expiry+2ttl is still in the future
	pastMargin := base()
	pastMargin.LeaseExpiry = now.Add(-3 * ttl).UnixNano() // expiry+2ttl has passed
	released := base()
	released.Owner, released.LeaseExpiry, released.Generation = "", 0, 3
	noFQDN := base()
	noFQDN.PeerFQDN, noFQDN.LeaseExpiry = "", now.Add(-3*ttl).UnixNano()
	degraded := base()
	degraded.Generation, degraded.LeaseExpiry = 0, 0 // owner never held a lease: not fenceable
	newerSchema := base()
	newerSchema.LeaseExpiry = now.Add(-3 * ttl).UnixNano() // adoptable by age...
	newerSchema.SchemaVersion = sessionSchemaVersion + 1   // ...but a format this build may misread

	all := map[string]PersistedSession{
		"live": live, "insideMargin": insideMargin, "pastMargin": pastMargin,
		"released": released, "noFQDN": noFQDN, "degraded": degraded, "newerSchema": newerSchema,
	}
	for name, ps := range all {
		if err := store.Save(ps); err != nil {
			t.Fatalf("save %s: %v", name, err)
		}
	}

	srv.sweepOnce(now)
	defer srv.Shutdown()

	if got := srv.Count(); got != 2 {
		t.Fatalf("adopted sessions = %d, want 2 (pastMargin + released)", got)
	}
	for _, name := range []string{"pastMargin", "released"} {
		ps, ok, _ := store.Load(all[name].ID)
		if !ok || ps.Owner != srv.instance || ps.Generation != all[name].Generation+1 {
			t.Fatalf("%s: owner=%q gen=%d (ok=%v), want adopted by %q at gen %d", name, ps.Owner, ps.Generation, ok, srv.instance, all[name].Generation+1)
		}
	}
	for _, name := range []string{"live", "insideMargin", "noFQDN", "degraded", "newerSchema"} {
		ps, ok, _ := store.Load(all[name].ID)
		if !ok || ps.Owner != all[name].Owner || ps.Generation != all[name].Generation {
			t.Fatalf("%s: owner=%q gen=%d (ok=%v), must be untouched", name, ps.Owner, ps.Generation, ok)
		}
	}
	// The respawned backends carry the persisted creator identity — the policy
	// Caller a real gateway builds from Meta stays full-fidelity.
	for _, m := range mf.spawned() {
		if m.PeerFQDN != "alice.mesh" || m.PeerKey != "alice-key" || m.PeerAddr != "100.64.0.9:1" {
			t.Fatalf("adopted backend spawned with degraded identity: %+v", m)
		}
	}
}

// startSweepGateway is startFenceServer with a sweep-capable server and a
// caller-chosen client identity (the sweep needs a non-empty creator key).
func startSweepGateway(t *testing.T, store SessionStore, factory BackendFactory, meta Meta) (*Server, string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newStandbyServer(store, 2*time.Minute, factory)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.Handle(c, meta)
		}
	}()
	return srv, ln.Addr().String(), func() { ln.Close() }
}

// establishQuiescent runs the MCP handshake plus one request (id 2) on gw and
// waits for the FINAL ack-driven checkpoint — both responses sent AND acked
// (SendSeq == Acked == 2). An intermediate checkpoint (request dispatched,
// response not yet sent) is a legal but earlier migration point; a failover
// from that instant loses the in-flight response — the pre-existing
// handshake-mode window, which this test is not about. Adoption from the
// quiescent point must be lossless.
func establishQuiescent(t *testing.T, fc *fenceClient, store *MemStore, gw *Server) string {
	t.Helper()
	fc.write(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	fc.waitFor(t, 1)
	// Small pauses keep each message a separate transport frame so the
	// captured handshake stays minimal (same shape as the migration tests).
	time.Sleep(50 * time.Millisecond)
	fc.write(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	time.Sleep(50 * time.Millisecond)
	fc.write(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	fc.waitFor(t, 2)
	sid := fc.client.SessionID()
	waitUntil(t, 5*time.Second, "gw1's final quiescent checkpoint to be durable", func() bool {
		ps, ok, _ := store.Load(sid)
		return ok && ps.Owner == gw.instance && ps.Generation == 1 &&
			bytes.Contains(ps.Replay, []byte("notifications/initialized")) &&
			ps.SendSeq == 2 && ps.Acked == 2
	})
	return sid
}

// TestSweepAdoptionEndToEnd is the paused-not-dead flagship flow:
//
//  1. a real client establishes a session on gw1;
//  2. gw1 "pauses" (it stops renewing — its lease lapses far past the margin);
//  3. gw2's sweep claims the session via the lease CAS and respawns the
//     backend BEFORE the client returns;
//  4. a foreign identity still cannot attach to the adopted session;
//  5. the client reattaches to gw2 and is served by the warm backend;
//  6. gw1 unpauses: its renewal is fenced, it yields, and its remove cannot
//     delete gw2's record — at no point were there two unfenced writers.
func TestSweepAdoptionEndToEnd(t *testing.T) {
	store := NewMemStore()
	clientMeta := Meta{PeerFQDN: "client.mesh", PeerKey: "alice-key", PeerAddr: "100.64.0.9:1"}
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }

	gw1, addr1, stop1 := startSweepGateway(t, store, factory, clientMeta)
	gw2, addr2, stop2 := startSweepGateway(t, store, factory, clientMeta)
	defer stop1()
	defer stop2()

	fc := startFenceClient(t, addr1)
	defer fc.close()
	sid := establishQuiescent(t, fc, store, gw1)
	id, err := parseSessionID(sid)
	if err != nil {
		t.Fatal(err)
	}

	// gw1 pauses: no renewals ever run, so its lease expiry (attach time +
	// ttl) lapses. Time-travel the sweep far past expiry + margin instead of
	// sleeping — safety comes from the CAS, not the clock.
	future := time.Now().Add(gw1.ttl + gw2.sweepMargin() + gw2.ttl)
	gw2.sweepOnce(future)

	if gw2.Count() != 1 {
		t.Fatalf("gw2 adopted sessions = %d, want 1", gw2.Count())
	}
	ps, ok, _ := store.Load(sid)
	if !ok || ps.Owner != gw2.instance || ps.Generation != 2 {
		t.Fatalf("store after adoption: owner=%q gen=%d (ok=%v), want gw2 %q gen 2", ps.Owner, ps.Generation, ok, gw2.instance)
	}

	// Identity binding is untouched: a foreign identity cannot attach to the
	// adopted session.
	if _, _, err := gw2.attach(id, Meta{PeerFQDN: "mallory.mesh", PeerKey: "mallory-key"}); !errors.Is(err, errSessionIdentity) {
		t.Fatalf("foreign attach to adopted session: want errSessionIdentity, got %v", err)
	}

	// The client reattaches to gw2 and lands on the already-warm session.
	fc.d.failoverTo(addr2)
	fc.write(`{"jsonrpc":"2.0","id":3,"method":"after-adoption"}`)
	fc.waitFor(t, 3)

	// gw1 unpauses. Its next renewal is fenced -> it yields; its remove path
	// (DeleteIfOwner) must not delete gw2's record.
	gw1.renewOnce(future)
	waitUntil(t, 5*time.Second, "paused gw1 to yield its fenced session", func() bool {
		return gw1.Count() == 0
	})
	ps, ok, _ = store.Load(sid)
	if !ok {
		t.Fatal("fenced gw1 deleted the adopted session's record")
	}
	if ps.Owner != gw2.instance {
		t.Fatalf("owner after gw1 unpaused = %q, want gw2 %q", ps.Owner, gw2.instance)
	}

	// gw2 keeps serving, unaffected.
	fc.write(`{"jsonrpc":"2.0","id":4,"method":"still-on-gw2"}`)
	fc.waitFor(t, 4)
}

// TestAdoptReloadsFreshCheckpoint: between the sweep's List and its claim the
// (about-to-be-fenced) owner may have checkpointed newer cursors; adoption
// must resume from a post-claim re-Load, not the stale List snapshot.
func TestAdoptReloadsFreshCheckpoint(t *testing.T) {
	store := NewMemStore()
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	srv := newStandbyServer(store, time.Minute, factory)
	now := time.Unix(100000, 0)

	id, _ := randID()
	stale := PersistedSession{
		ID: id.String(), Owner: "gw1", CreatorKey: "alice-key", PeerFQDN: "alice.mesh",
		Generation: 1, LeaseExpiry: now.Add(-time.Hour).UnixNano(), SendSeq: 1, Acked: 1,
	}
	if err := store.Save(stale); err != nil {
		t.Fatal(err)
	}
	// The owner's last checkpoint lands after the sweep's List snapshot.
	fresh := stale
	fresh.SendSeq, fresh.Acked = 7, 7
	if err := store.Save(fresh); err != nil {
		t.Fatal(err)
	}

	srv.adopt(stale, now) // called with the stale snapshot, as sweepOnce would
	defer srv.Shutdown()

	srv.mu.Lock()
	sess, ok := srv.sessions[id]
	srv.mu.Unlock()
	if !ok {
		t.Fatal("adoption did not register the session")
	}
	if got := sess.ep.sendSeq; got != 7 {
		t.Fatalf("adopted send cursor = %d, want 7 (the post-claim re-Load)", got)
	}
}

// TestAdoptedUnclaimedReaped: an adopted session the client never returns for
// is reaped at the server TTL — terminal delete, exactly what the original
// owner's reaper would have done, and the store GC for dead-owner records.
func TestAdoptedUnclaimedReaped(t *testing.T) {
	store := NewMemStore()
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	srv := newStandbyServer(store, 150*time.Millisecond, factory)

	id, _ := randID()
	ps := PersistedSession{
		ID: id.String(), Owner: "gw1", CreatorKey: "alice-key", PeerFQDN: "alice.mesh",
		Generation: 1, LeaseExpiry: time.Now().Add(-time.Hour).UnixNano(),
	}
	if err := store.Save(ps); err != nil {
		t.Fatal(err)
	}

	srv.sweepOnce(time.Now())
	if srv.Count() != 1 {
		t.Fatalf("adopted sessions = %d, want 1", srv.Count())
	}

	waitUntil(t, 5*time.Second, "the unclaimed adopted session to be reaped", func() bool {
		if srv.Count() != 0 {
			return false
		}
		_, ok, _ := store.Load(id.String())
		return !ok
	})
}

// TestAdoptionFailureReleasesLease: when the backend cannot be respawned, the
// claim is released — owner cleared, bumped generation and state preserved —
// so the client's reattach anywhere is unaffected.
func TestAdoptionFailureReleasesLease(t *testing.T) {
	store := NewMemStore()
	factory := func(Meta) (Backend, error) { return nil, errors.New("spawn refused") }
	srv := newStandbyServer(store, time.Minute, factory)
	now := time.Unix(100000, 0)

	id, _ := randID()
	ps := PersistedSession{
		ID: id.String(), Owner: "gw1", CreatorKey: "alice-key", PeerFQDN: "alice.mesh",
		Generation: 1, LeaseExpiry: now.Add(-time.Hour).UnixNano(),
		SendSeq: 5, Acked: 5, Replay: []byte("handshake\n"),
	}
	if err := store.Save(ps); err != nil {
		t.Fatal(err)
	}

	srv.sweepOnce(now)

	if srv.Count() != 0 {
		t.Fatalf("failed adoption must not register a session, count=%d", srv.Count())
	}
	cur, ok, _ := store.Load(id.String())
	if !ok {
		t.Fatal("failed adoption deleted the record")
	}
	if cur.Owner != "" || cur.LeaseExpiry != 0 {
		t.Fatalf("failed adoption must release the lease: owner=%q expiry=%d", cur.Owner, cur.LeaseExpiry)
	}
	if cur.Generation != 2 {
		t.Fatalf("released generation = %d, want 2 (the claim's bump is kept)", cur.Generation)
	}
	if cur.SendSeq != 5 || string(cur.Replay) != "handshake\n" {
		t.Fatalf("failed adoption corrupted the state: %+v", cur)
	}
}
