package session

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// These races are the safety heart of the standby sweep: whatever the
// interleaving, the store's generation CAS admits exactly one writer. Run with
// a high -count to shake orderings (-race is the usual companion elsewhere).

// TestSweepVsRenewRace: a live-but-lapsed owner renewing races a standby
// claiming. Renewal deliberately does not check expiry, so BOTH ops are valid
// — but exactly one may commit: either the owner renewed (sweep refused by the
// now-live lease) or the standby adopted (owner fenced on its renew and
// yields). Never both.
func TestSweepVsRenewRace(t *testing.T) {
	store := NewMemStore()
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	gw1 := NewServer(factory, time.Minute, nil).WithStore(store, MigrateHandshake)
	gw2 := newStandbyServer(store, time.Minute, factory)

	id, _ := randID()
	t0 := time.Unix(1000, 0)
	l, ok, _ := store.AcquireLease(id.String(), gw1.instance, 0, gw1.ttl, t0)
	if !ok {
		t.Fatal("gw1 acquire should succeed")
	}
	if ok, _ := store.SaveIfOwned(PersistedSession{ID: id.String(), CreatorKey: "alice-key", PeerFQDN: "alice.mesh"}, gw1.instance, l.Generation); !ok {
		t.Fatal("gw1 seed checkpoint should succeed")
	}
	registerSession(gw1, id, l.Generation, Meta{PeerFQDN: "alice.mesh", PeerKey: "alice-key"})

	late := t0.Add(10 * gw1.ttl) // far past expiry+margin: both paths want the lease
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); gw1.renewOnce(late) }()
	go func() { defer wg.Done(); gw2.sweepOnce(late) }()
	wg.Wait()
	defer gw1.Shutdown()
	defer gw2.Shutdown()

	ps, ok, _ := store.Load(id.String())
	if !ok {
		t.Fatal("record vanished during the race")
	}
	switch ps.Owner {
	case gw1.instance:
		// Renewal won: generation unchanged, the sweep found a live lease.
		if ps.Generation != l.Generation {
			t.Fatalf("renewal-won generation = %d, want %d", ps.Generation, l.Generation)
		}
		if gw2.Count() != 0 {
			t.Fatal("sweep adopted a session whose owner renewed (split brain)")
		}
		if gw1.Count() != 1 {
			t.Fatal("winning owner wrongly yielded its session")
		}
	case gw2.instance:
		// Claim won: generation bumped, the owner's renew was fenced and it
		// yielded synchronously.
		if ps.Generation != l.Generation+1 {
			t.Fatalf("adoption generation = %d, want %d", ps.Generation, l.Generation+1)
		}
		if gw2.Count() != 1 {
			t.Fatal("winning sweep did not register the adopted session")
		}
		if gw1.Count() != 0 {
			t.Fatal("fenced owner failed to yield after its renew lost")
		}
	default:
		t.Fatalf("unexpected owner %q (want %q or %q)", ps.Owner, gw1.instance, gw2.instance)
	}
}

// TestAdoptVsRehydrateRaceSameGateway: the standby's adopt races the creator's
// own reattach ON THE SAME gateway. s.mu + the map recheck serialize them, and
// a takeover CAS lost to the concurrent adopt is retried INSIDE attach — the
// real client treats any attach rejection as terminal, so a single attach call
// must succeed. Exactly one live session exists afterwards.
func TestAdoptVsRehydrateRaceSameGateway(t *testing.T) {
	store := NewMemStore()
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	gw := newStandbyServer(store, time.Minute, factory)
	now := time.Unix(100000, 0)

	id, _ := randID()
	ps := PersistedSession{
		ID: id.String(), Owner: "gw-dead", CreatorKey: "alice-key", PeerFQDN: "alice.mesh",
		Generation: 1, LeaseExpiry: now.Add(-time.Hour).UnixNano(),
	}
	if err := store.Save(ps); err != nil {
		t.Fatal(err)
	}

	alice := Meta{PeerFQDN: "alice.mesh", PeerKey: "alice-key"}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); gw.adopt(ps, now) }()

	_, resumed, err := gw.attach(id, alice)
	if err != nil {
		t.Fatalf("client reattach failed against a concurrent adopt: %v", err)
	}
	wg.Wait()
	defer gw.Shutdown()

	if !resumed {
		t.Fatal("reattach must resume, never create a fresh session")
	}
	if gw.Count() != 1 {
		t.Fatalf("live sessions = %d, want exactly 1", gw.Count())
	}
	cur, ok, _ := store.Load(id.String())
	if !ok || cur.Owner != gw.instance {
		t.Fatalf("store owner = %q (ok=%v), want %q", cur.Owner, ok, gw.instance)
	}
	if cur.Generation != 2 && cur.Generation != 3 {
		t.Fatalf("generation = %d, want 2 (one winner) or 3 (rehydrate over adopt)", cur.Generation)
	}
}

// TestTwoStandbysSingleAdoption: two standbys sweep the same expired session
// concurrently — the generation CAS admits exactly one adopter.
func TestTwoStandbysSingleAdoption(t *testing.T) {
	store := NewMemStore()
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	gwA := newStandbyServer(store, time.Minute, factory)
	gwB := newStandbyServer(store, time.Minute, factory)
	now := time.Unix(100000, 0)

	id, _ := randID()
	ps := PersistedSession{
		ID: id.String(), Owner: "gw-dead", CreatorKey: "alice-key", PeerFQDN: "alice.mesh",
		Generation: 1, LeaseExpiry: now.Add(-time.Hour).UnixNano(),
	}
	if err := store.Save(ps); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); gwA.sweepOnce(now) }()
	go func() { defer wg.Done(); gwB.sweepOnce(now) }()
	wg.Wait()
	defer gwA.Shutdown()
	defer gwB.Shutdown()

	if total := gwA.Count() + gwB.Count(); total != 1 {
		t.Fatalf("adopted sessions across both standbys = %d, want exactly 1", total)
	}
	cur, ok, _ := store.Load(id.String())
	if !ok || cur.Generation != 2 {
		t.Fatalf("store generation = %d (ok=%v), want exactly one bump to 2", cur.Generation, ok)
	}
	winner := gwA.instance
	if gwB.Count() == 1 {
		winner = gwB.instance
	}
	if cur.Owner != winner {
		t.Fatalf("store owner = %q, want the adopting standby %q", cur.Owner, winner)
	}
}

// racedTakeoverStore fails the first `failures` TakeoverLease calls with a CAS
// loss (ok=false, no error), exactly what a concurrent adopt's generation bump
// produces between attach's Load and its TakeoverLease.
type racedTakeoverStore struct {
	*MemStore
	mu       sync.Mutex
	failures int
	calls    int
}

func (s *racedTakeoverStore) TakeoverLease(id, owner string, expectedGen uint64, ttl time.Duration, now time.Time) (Lease, bool, error) {
	s.mu.Lock()
	s.calls++
	fail := s.failures > 0
	if fail {
		s.failures--
	}
	s.mu.Unlock()
	if fail {
		return Lease{}, false, nil
	}
	return s.MemStore.TakeoverLease(id, owner, expectedGen, ttl, now)
}

func (s *racedTakeoverStore) takeoverCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// TestAttachRetriesTakeoverRace: a transient takeover CAS loss must be
// absorbed server-side by re-Load + retry. The client's transport treats any
// attach rejection as terminal (no redial), so surfacing the race would
// permanently kill a session that sits warm on the adopter — the opposite of
// the failover the sweep exists for.
func TestAttachRetriesTakeoverRace(t *testing.T) {
	store := &racedTakeoverStore{MemStore: NewMemStore(), failures: 1}
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	srv := NewServer(factory, time.Minute, nil).WithStore(store, MigrateHandshake)

	id, _ := randID()
	if err := store.Save(PersistedSession{
		ID: id.String(), Owner: "gw-dead", CreatorKey: "alice-key", PeerFQDN: "alice.mesh", Generation: 1,
	}); err != nil {
		t.Fatal(err)
	}

	sess, resumed, err := srv.attach(id, Meta{PeerFQDN: "alice.mesh", PeerKey: "alice-key"})
	if err != nil {
		t.Fatalf("attach must absorb a transient takeover CAS loss, got %v", err)
	}
	if !resumed || sess == nil {
		t.Fatal("attach must resume the persisted session")
	}
	defer srv.Shutdown()
	if got := store.takeoverCalls(); got != 2 {
		t.Fatalf("TakeoverLease calls = %d, want 2 (one raced, one retried)", got)
	}
	cur, ok, _ := store.Load(id.String())
	if !ok || cur.Owner != srv.instance || cur.Generation != 2 {
		t.Fatalf("owner=%q gen=%d (ok=%v), want %q gen 2", cur.Owner, cur.Generation, ok, srv.instance)
	}
}

// TestAttachTakeoverRaceBounded: a CAS that keeps moving is abandoned after a
// bounded number of retries, and no backend is ever spawned for a session this
// gateway never came to own.
func TestAttachTakeoverRaceBounded(t *testing.T) {
	store := &racedTakeoverStore{MemStore: NewMemStore(), failures: 1 << 20}
	spawned := 0
	factory := func(Meta) (Backend, error) { spawned++; return newMigBackend(), nil }
	srv := NewServer(factory, time.Minute, nil).WithStore(store, MigrateHandshake)

	id, _ := randID()
	if err := store.Save(PersistedSession{
		ID: id.String(), Owner: "gw-dead", CreatorKey: "alice-key", PeerFQDN: "alice.mesh", Generation: 1,
	}); err != nil {
		t.Fatal(err)
	}
	_, _, err := srv.attach(id, Meta{PeerFQDN: "alice.mesh", PeerKey: "alice-key"})
	if !errors.Is(err, errTakeoverRaced) {
		t.Fatalf("exhausted retries must surface the race, got %v", err)
	}
	if got := store.takeoverCalls(); got != takeoverAttempts {
		t.Fatalf("TakeoverLease calls = %d, want %d", got, takeoverAttempts)
	}
	if spawned != 0 || srv.Count() != 0 {
		t.Fatalf("no backend may be spawned for an unowned session (spawned=%d count=%d)", spawned, srv.Count())
	}
}

// blockingListStore parks the first List call until released, simulating a
// sweep blocked mid-store-I/O while the gateway is asked to shut down.
type blockingListStore struct {
	*MemStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingListStore) List() ([]PersistedSession, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return s.MemStore.List()
}

// TestShutdownJoinsMaintenanceLoop: Shutdown must not drain the session map
// while the maintenance goroutine may still be mid-sweep — an adoption landing
// after the drain would leak a live backend subprocess and strand its lease,
// owned by an exited process, until expiry + margin.
func TestShutdownJoinsMaintenanceLoop(t *testing.T) {
	store := &blockingListStore{MemStore: NewMemStore(), entered: make(chan struct{}), release: make(chan struct{})}
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	srv := NewServer(factory, time.Minute, nil).
		WithStore(store, MigrateHandshake).
		WithFailover(FailoverConfig{Enabled: true, SweepInterval: time.Millisecond})

	stop := make(chan struct{})
	srv.StartLeaseMaintenance(stop)
	<-store.entered // the maintenance goroutine is blocked inside sweepOnce's List
	close(stop)

	done := make(chan struct{})
	go func() { srv.Shutdown(); close(done) }()
	select {
	case <-done:
		t.Fatal("Shutdown returned while the maintenance loop was still mid-sweep")
	case <-time.After(50 * time.Millisecond):
	}
	close(store.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown never returned after the maintenance loop exited")
	}
}
