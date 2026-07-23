// Package storetest is the conformance harness for session store
// implementations: every SessionStore/LeaseStore backend (in-memory, file,
// PostgreSQL, ...) must pass the same behavioral contract, so a new backend
// proves the lease CAS and fencing invariants by running these functions
// against a fresh store.
package storetest

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/session"
)

// RunLeaseStoreConformance proves the full lease contract against the
// implementation returned by open. open must return a fresh, empty store on
// every call — subtests do not share state.
func RunLeaseStoreConformance(t *testing.T, open func(t *testing.T) session.LeaseStore) {
	// MutualExclusion: while one gateway holds a live lease, another cannot
	// acquire it — two gateways can never concurrently own a session.
	t.Run("MutualExclusion", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		l1, ok, err := s.AcquireLease("sess", "gw1", 0, time.Minute, now)
		if err != nil || !ok {
			t.Fatalf("gw1 initial acquire should succeed: ok=%v err=%v", ok, err)
		}
		if l1.Generation != 1 {
			t.Fatalf("first generation should be 1, got %d", l1.Generation)
		}
		// gw2 cannot take a live lease, at any expectedGen.
		if _, ok, _ := s.AcquireLease("sess", "gw2", 1, time.Minute, now.Add(time.Second)); ok {
			t.Fatal("gw2 must not acquire a lease gw1 holds live")
		}
		if _, ok, _ := s.AcquireLease("sess", "gw2", 0, time.Minute, now.Add(time.Second)); ok {
			t.Fatal("gw2 must not acquire a live lease with any expectedGen")
		}
	})

	// FencingStaleOwnerCannotWrite: after gw2 takes over an expired lease,
	// gw1's stale generation is fenced out of SaveIfOwned — a superseded owner
	// cannot write or execute.
	t.Run("FencingStaleOwnerCannotWrite", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		l1, _, _ := s.AcquireLease("sess", "gw1", 0, 10*time.Second, now)

		// gw1 can write while it owns the lease.
		if ok, _ := s.SaveIfOwned(session.PersistedSession{ID: "sess"}, "gw1", l1.Generation); !ok {
			t.Fatal("gw1 should be able to write while it owns the lease")
		}

		// Lease expires; gw2 reads the current gen and takes over.
		later := now.Add(11 * time.Second)
		l2, ok, _ := s.AcquireLease("sess", "gw2", l1.Generation, time.Minute, later)
		if !ok {
			t.Fatal("gw2 should take over the expired lease")
		}
		if l2.Generation <= l1.Generation {
			t.Fatalf("generation must increase on takeover: %d -> %d", l1.Generation, l2.Generation)
		}

		// gw1 is now fenced: its stale generation cannot write.
		if ok, _ := s.SaveIfOwned(session.PersistedSession{ID: "sess"}, "gw1", l1.Generation); ok {
			t.Fatal("superseded gw1 must be fenced out of SaveIfOwned")
		}
		// gw2 (current owner) can write.
		if ok, _ := s.SaveIfOwned(session.PersistedSession{ID: "sess"}, "gw2", l2.Generation); !ok {
			t.Fatal("current owner gw2 should be able to write")
		}
	})

	// ConcurrentAcquireSingleWinner: many gateways racing to acquire a fresh
	// lease — exactly one wins (no split brain).
	t.Run("ConcurrentAcquireSingleWinner", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		var winners int64
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				owner := fmt.Sprintf("gw%d", i)
				if _, ok, err := s.AcquireLease("race", owner, 0, time.Minute, now); err == nil && ok {
					atomic.AddInt64(&winners, 1)
				}
			}(i)
		}
		wg.Wait()
		if winners != 1 {
			t.Fatalf("exactly one gateway may acquire a fresh lease, got %d", winners)
		}
	})

	// ConcurrentTakeoverSingleWinner: many gateways racing to take over the
	// SAME expired lease (all with the same expectedGen) — exactly one wins, so
	// a split-brain takeover is impossible.
	t.Run("ConcurrentTakeoverSingleWinner", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		l1, _, _ := s.AcquireLease("sess", "gw1", 0, time.Second, now)
		expired := now.Add(2 * time.Second)
		var winners int64
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				owner := fmt.Sprintf("taker%d", i)
				if _, ok, err := s.AcquireLease("sess", owner, l1.Generation, time.Minute, expired); err == nil && ok {
					atomic.AddInt64(&winners, 1)
				}
			}(i)
		}
		wg.Wait()
		if winners != 1 {
			t.Fatalf("exactly one gateway may take over the expired lease, got %d", winners)
		}
	})

	// Takeover: an identity-bound reattach takes over even a still-LIVE lease
	// (unlike AcquireLease), bumping the generation so the previous owner is
	// fenced — while still enforcing the generation CAS so exactly one of
	// several racing takers wins.
	t.Run("Takeover", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		// gw1 holds a live lease (long TTL — not expired).
		l1, ok, _ := s.AcquireLease("sess", "gw1", 0, time.Hour, now)
		if !ok {
			t.Fatal("gw1 initial acquire should succeed")
		}
		// AcquireLease cannot steal the live lease...
		if _, ok, _ := s.AcquireLease("sess", "gw2", l1.Generation, time.Minute, now.Add(time.Second)); ok {
			t.Fatal("AcquireLease must not steal a live lease")
		}
		// ...but an authenticated reattach (TakeoverLease) can, fencing gw1.
		l2, ok, _ := s.TakeoverLease("sess", "gw2", l1.Generation, time.Minute, now.Add(time.Second))
		if !ok {
			t.Fatal("TakeoverLease should take over a live lease on an identity-bound reattach")
		}
		if l2.Generation <= l1.Generation {
			t.Fatalf("takeover must bump the generation: %d -> %d", l1.Generation, l2.Generation)
		}
		// gw1 is fenced; gw2 owns.
		if ok, _ := s.SaveIfOwned(session.PersistedSession{ID: "sess"}, "gw1", l1.Generation); ok {
			t.Fatal("previous owner must be fenced after takeover")
		}
		if ok, _ := s.SaveIfOwned(session.PersistedSession{ID: "sess"}, "gw2", l2.Generation); !ok {
			t.Fatal("new owner should be able to write after takeover")
		}
		// A stale takeover (wrong expectedGen) must lose the CAS.
		if _, ok, _ := s.TakeoverLease("sess", "gw3", l1.Generation, time.Minute, now.Add(2*time.Second)); ok {
			t.Fatal("a takeover with a stale expectedGen must fail the CAS")
		}
	})

	// ConcurrentTakeoverLiveSingleWinner: many gateways racing to take over the
	// SAME still-live lease (same expectedGen) — exactly one wins, so an
	// authenticated migration can never split-brain into two owners.
	t.Run("ConcurrentTakeoverLiveSingleWinner", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		l1, _, _ := s.AcquireLease("sess", "gw1", 0, time.Hour, now) // live, not expired
		var winners int64
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				owner := fmt.Sprintf("taker%d", i)
				if _, ok, err := s.TakeoverLease("sess", owner, l1.Generation, time.Minute, now); err == nil && ok {
					atomic.AddInt64(&winners, 1)
				}
			}(i)
		}
		wg.Wait()
		if winners != 1 {
			t.Fatalf("exactly one gateway may take over a live lease, got %d", winners)
		}
	})

	// SaveIfOwnedKeepsLease: a state snapshot must never alter the lease.
	// Snapshots carry zero lease fields (endpoint.snapshot sets none), so a
	// backend that persisted ps.LeaseExpiry on save would silently free a live
	// lease and reopen the split-brain window SaveIfOwned exists to close.
	t.Run("SaveIfOwnedKeepsLease", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		l1, ok, _ := s.AcquireLease("sess", "gw1", 0, time.Hour, now)
		if !ok {
			t.Fatal("gw1 initial acquire should succeed")
		}
		if ok, _ := s.SaveIfOwned(session.PersistedSession{ID: "sess", SendSeq: 7}, "gw1", l1.Generation); !ok {
			t.Fatal("owner snapshot should be written")
		}
		if _, ok, _ := s.AcquireLease("sess", "gw2", l1.Generation, time.Minute, now.Add(time.Second)); ok {
			t.Fatal("SaveIfOwned must not free the live lease")
		}
		if _, ok, _ := s.RenewLease("sess", "gw1", l1.Generation, time.Hour, now.Add(time.Second)); !ok {
			t.Fatal("owner renew should still succeed after a snapshot")
		}
	})

	// MissingSession: lease ops against an id that was never created (or was
	// reaped) must fail and must not resurrect a row — only a fresh acquire
	// (expectedGen 0) may create one, so a fenced or reaped gateway's writes
	// cannot bring a deleted session back.
	t.Run("MissingSession", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		if _, ok, _ := s.AcquireLease("ghost", "gw1", 3, time.Minute, now); ok {
			t.Fatal("acquire of a missing session with a nonzero expectedGen must fail")
		}
		if _, ok, _ := s.TakeoverLease("ghost", "gw1", 3, time.Minute, now); ok {
			t.Fatal("takeover of a missing session with a nonzero expectedGen must fail")
		}
		if ok, _ := s.SaveIfOwned(session.PersistedSession{ID: "ghost"}, "gw1", 3); ok {
			t.Fatal("SaveIfOwned on a missing session must fail, not create it")
		}
		if _, ok, _ := s.RenewLease("ghost", "gw1", 3, time.Minute, now); ok {
			t.Fatal("renew of a missing session must fail")
		}
		if ok, _ := s.ReleaseLease("ghost", "gw1", 3); ok {
			t.Fatal("release of a missing session must fail")
		}
		// None of the failures may have created the row: a fresh acquire at
		// expectedGen 0 still succeeds at generation 1.
		l, ok, _ := s.AcquireLease("ghost", "gw1", 0, time.Minute, now)
		if !ok || l.Generation != 1 {
			t.Fatalf("fresh acquire after failed ops: ok=%v gen=%d", ok, l.Generation)
		}
	})

	// RenewAndRelease: renew extends and preserves the generation; release
	// frees the lease; both reject a wrong owner or stale generation.
	t.Run("RenewAndRelease", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		l1, _, _ := s.AcquireLease("sess", "gw1", 0, 10*time.Second, now)

		if _, ok, _ := s.RenewLease("sess", "gw2", l1.Generation, time.Minute, now); ok {
			t.Fatal("renew by a non-owner must fail")
		}
		if _, ok, _ := s.RenewLease("sess", "gw1", l1.Generation+9, time.Minute, now); ok {
			t.Fatal("renew with a stale generation must fail")
		}
		if _, ok, _ := s.RenewLease("sess", "gw1", l1.Generation, time.Minute, now); !ok {
			t.Fatal("owner renew should succeed")
		}

		if ok, _ := s.ReleaseLease("sess", "gw2", l1.Generation); ok {
			t.Fatal("release by a non-owner must fail")
		}
		if ok, _ := s.ReleaseLease("sess", "gw1", l1.Generation); !ok {
			t.Fatal("owner release should succeed")
		}
		// After release, another gateway can acquire (expectedGen == current).
		if _, ok, _ := s.AcquireLease("sess", "gw2", l1.Generation, time.Minute, now.Add(time.Second)); !ok {
			t.Fatal("after release the lease should be acquirable by another gateway")
		}
	})
}

// RunSessionStoreConformance proves the Save/Load/List/DeleteIfOwner contract
// against the implementation returned by open. open must return a fresh,
// empty store on every call.
func RunSessionStoreConformance(t *testing.T, open func(t *testing.T) session.SessionStore) {
	// List: every persisted session is enumerated; a delete is reflected in
	// the next List.
	t.Run("List", func(t *testing.T) {
		s := open(t)
		if l, err := s.List(); err != nil || len(l) != 0 {
			t.Fatalf("empty store: len=%d err=%v", len(l), err)
		}
		for _, id := range []string{"aa", "bb", "cc"} {
			if err := s.Save(session.PersistedSession{ID: id, Owner: "gw1"}); err != nil {
				t.Fatalf("save %s: %v", id, err)
			}
		}
		l, err := s.List()
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		got := map[string]bool{}
		for _, ps := range l {
			got[ps.ID] = true
		}
		if len(got) != 3 || !got["aa"] || !got["bb"] || !got["cc"] {
			t.Fatalf("expected aa,bb,cc; got %v", got)
		}
		if err := s.DeleteIfOwner("bb", "gw1"); err != nil {
			t.Fatal(err)
		}
		l, _ = s.List()
		if len(l) != 2 {
			t.Fatalf("expected 2 after delete, got %d", len(l))
		}
	})

	// RoundTripAndOwnerDelete: a full persisted session round-trips, and the
	// ownership lease is enforced on delete — a non-owner cannot delete, the
	// owner can.
	t.Run("RoundTripAndOwnerDelete", func(t *testing.T) {
		s := open(t)
		ps := session.PersistedSession{
			ID:    "abc123",
			Owner: "gw1",
			// CreatorKey is the identity check on failover reattach; a store
			// that drops it breaks (or worse, bypasses) that check.
			CreatorKey: "wg-pubkey-of-creator",
			// PeerFQDN/PeerAddr feed a standby adoption's backend respawn; a
			// store that drops them silently downgrades the adopted session's
			// policy identity (or, with the sweep's guard, makes every record
			// unadoptable).
			PeerFQDN:        "laptop.mesh.example",
			PeerAddr:        "100.64.0.7:41641",
			SendSeq:         5,
			Acked:           2,
			RecvSeq:         3,
			Replay:          []byte("handshake"),
			ReplayResponses: 1,
			SendBuf: []session.PersistedFrame{
				{Seq: 3, Payload: []byte("x")},
				{Seq: 4, Payload: []byte("yz")},
			},
			Generation: 7,
			// Sub-microsecond nanos: the fencing fields must round-trip
			// exactly, whatever the backend's native time resolution.
			LeaseExpiry: time.Unix(1234, 567891234).UnixNano(),
		}
		if err := s.Save(ps); err != nil {
			t.Fatalf("save: %v", err)
		}

		got, ok, err := s.Load("abc123")
		if err != nil || !ok {
			t.Fatalf("load: ok=%v err=%v", ok, err)
		}
		if got.SendSeq != 5 || got.Acked != 2 || got.RecvSeq != 3 || got.Owner != "gw1" ||
			got.CreatorKey != "wg-pubkey-of-creator" ||
			got.PeerFQDN != "laptop.mesh.example" || got.PeerAddr != "100.64.0.7:41641" ||
			string(got.Replay) != "handshake" || got.ReplayResponses != 1 ||
			got.Generation != 7 || got.LeaseExpiry != ps.LeaseExpiry {
			t.Fatalf("round-trip mismatch: %+v", got)
		}
		if len(got.SendBuf) != 2 || got.SendBuf[0].Seq != 3 || string(got.SendBuf[0].Payload) != "x" ||
			got.SendBuf[1].Seq != 4 || string(got.SendBuf[1].Payload) != "yz" {
			t.Fatalf("send buffer mismatch: %+v", got.SendBuf)
		}

		if err := s.DeleteIfOwner("abc123", "gw2"); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := s.Load("abc123"); !ok {
			t.Fatal("non-owner delete removed the session")
		}
		if err := s.DeleteIfOwner("abc123", "gw1"); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := s.Load("abc123"); ok {
			t.Fatal("owner delete did not remove the session")
		}
	})
}
