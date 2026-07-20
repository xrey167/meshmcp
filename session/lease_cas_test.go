package session

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// leaseStores returns a fresh LeaseStore of each implementation, so every lease
// invariant is proven for both the in-memory and file-backed stores.
func leaseStores(t *testing.T) map[string]LeaseStore {
	t.Helper()
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return map[string]LeaseStore{"mem": NewMemStore(), "file": fs}
}

// TestLeaseMutualExclusion: while one gateway holds a live lease, another
// cannot acquire it — two gateways can never concurrently own a session.
func TestLeaseMutualExclusion(t *testing.T) {
	for name, s := range leaseStores(t) {
		t.Run(name, func(t *testing.T) {
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
	}
}

// TestLeaseFencingStaleOwnerCannotWrite: after gw2 takes over an expired lease,
// gw1's stale generation is fenced out of SaveIfOwned — a superseded owner
// cannot write or execute.
func TestLeaseFencingStaleOwnerCannotWrite(t *testing.T) {
	for name, s := range leaseStores(t) {
		t.Run(name, func(t *testing.T) {
			now := time.Unix(1000, 0)
			l1, _, _ := s.AcquireLease("sess", "gw1", 0, 10*time.Second, now)

			// gw1 can write while it owns the lease.
			if ok, _ := s.SaveIfOwned(PersistedSession{ID: "sess"}, "gw1", l1.Generation); !ok {
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
			if ok, _ := s.SaveIfOwned(PersistedSession{ID: "sess"}, "gw1", l1.Generation); ok {
				t.Fatal("superseded gw1 must be fenced out of SaveIfOwned")
			}
			// gw2 (current owner) can write.
			if ok, _ := s.SaveIfOwned(PersistedSession{ID: "sess"}, "gw2", l2.Generation); !ok {
				t.Fatal("current owner gw2 should be able to write")
			}
		})
	}
}

// TestLeaseConcurrentAcquireSingleWinner: many gateways racing to acquire a
// fresh lease — exactly one wins (no split brain).
func TestLeaseConcurrentAcquireSingleWinner(t *testing.T) {
	for name, s := range leaseStores(t) {
		t.Run(name, func(t *testing.T) {
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
	}
}

// TestLeaseConcurrentTakeoverSingleWinner: many gateways racing to take over the
// SAME expired lease (all with the same expectedGen) — exactly one wins, so a
// split-brain takeover is impossible.
func TestLeaseConcurrentTakeoverSingleWinner(t *testing.T) {
	for name, s := range leaseStores(t) {
		t.Run(name, func(t *testing.T) {
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
	}
}

// TestLeaseRenewAndRelease: renew extends and preserves the generation; release
// frees the lease; both reject a wrong owner or stale generation.
func TestLeaseRenewAndRelease(t *testing.T) {
	for name, s := range leaseStores(t) {
		t.Run(name, func(t *testing.T) {
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
}
