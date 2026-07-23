// Package replaytest is the conformance harness for replay-protection stores:
// every NonceStore and DPoPReplayStore backend (in-memory, PostgreSQL, ...)
// must pass the same single-use contract, so a new backend proves it by
// running these functions against a fresh store.
package replaytest

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// RunNonceStoreConformance proves the delegation-nonce contract against the
// implementation returned by open. open must return a fresh, empty store on
// every call.
func RunNonceStoreConformance(t *testing.T, open func(t *testing.T) policy.NonceStore) {
	// SingleUse: the first Use of a nonce succeeds; a replay within the
	// nonce's lifetime fails.
	t.Run("SingleUse", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		expiry := now.Add(time.Minute)
		if !s.Use("n1", expiry, now) {
			t.Fatal("first use of a nonce must succeed")
		}
		if s.Use("n1", expiry, now.Add(time.Second)) {
			t.Fatal("replay of a live nonce must fail")
		}
		// A distinct nonce is unaffected.
		if !s.Use("n2", expiry, now.Add(time.Second)) {
			t.Fatal("an unrelated nonce must still be usable")
		}
	})

	// ConcurrentUseSingleWinner: many verifiers racing the SAME nonce — the
	// first-use decision must be atomic (check-then-act would let a captured
	// token replay on every racing hop), so exactly one sees true.
	t.Run("ConcurrentUseSingleWinner", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		expiry := now.Add(time.Minute)
		var winners int64
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if s.Use("n1", expiry, now) {
					atomic.AddInt64(&winners, 1)
				}
			}()
		}
		wg.Wait()
		if winners != 1 {
			t.Fatalf("exactly one concurrent Use may succeed, got %d", winners)
		}
	})

	// ExpiredReusable: once a nonce's expiry has passed the store may forget
	// it — the token itself is expired by then, so reuse of the string is
	// harmless and retention stays bounded.
	t.Run("ExpiredReusable", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		if !s.Use("n1", now.Add(10*time.Second), now) {
			t.Fatal("first use of a nonce must succeed")
		}
		if !s.Use("n1", now.Add(time.Minute), now.Add(11*time.Second)) {
			t.Fatal("a nonce whose expiry has passed must be usable again")
		}
	})
}

// RunDPoPReplayStoreConformance proves the DPoP jti/nonce contract against
// the implementation returned by open. open must return a fresh, empty store
// on every call.
func RunDPoPReplayStoreConformance(t *testing.T, open func(t *testing.T) policy.DPoPReplayStore) {
	// JTISingleUse: the first UseJTI succeeds; a replay within the freshness
	// window fails.
	t.Run("JTISingleUse", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		expiry := now.Add(time.Minute)
		if !s.UseJTI("j1", expiry, now) {
			t.Fatal("first use of a jti must succeed")
		}
		if s.UseJTI("j1", expiry, now.Add(time.Second)) {
			t.Fatal("replay of a live jti must fail")
		}
		if !s.UseJTI("j2", expiry, now.Add(time.Second)) {
			t.Fatal("an unrelated jti must still be usable")
		}
	})

	// ConcurrentUseJTISingleWinner: many verifiers racing the SAME jti —
	// exactly one sees true, so a captured proof cannot pass on two gateways.
	t.Run("ConcurrentUseJTISingleWinner", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		expiry := now.Add(time.Minute)
		var winners int64
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if s.UseJTI("j1", expiry, now) {
					atomic.AddInt64(&winners, 1)
				}
			}()
		}
		wg.Wait()
		if winners != 1 {
			t.Fatalf("exactly one concurrent UseJTI may succeed, got %d", winners)
		}
	})

	// IssueThenConsume: an issued nonce is consumable exactly once — the
	// second consume (replay) fails.
	t.Run("IssueThenConsume", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		nonce, err := s.IssueNonce(now.Add(time.Minute), now)
		if err != nil || nonce == "" {
			t.Fatalf("IssueNonce: nonce=%q err=%v", nonce, err)
		}
		if !s.ConsumeNonce(nonce, now.Add(time.Second)) {
			t.Fatal("an issued, unexpired nonce must be consumable")
		}
		if s.ConsumeNonce(nonce, now.Add(2*time.Second)) {
			t.Fatal("double-consume of a nonce must fail")
		}
	})

	// ConcurrentConsumeSingleWinner: many racers consuming the SAME issued
	// nonce — the validate-and-burn must be one atomic step, so exactly one
	// consume succeeds.
	t.Run("ConcurrentConsumeSingleWinner", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		nonce, err := s.IssueNonce(now.Add(time.Minute), now)
		if err != nil {
			t.Fatalf("IssueNonce: %v", err)
		}
		var winners int64
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if s.ConsumeNonce(nonce, now.Add(time.Second)) {
					atomic.AddInt64(&winners, 1)
				}
			}()
		}
		wg.Wait()
		if winners != 1 {
			t.Fatalf("exactly one concurrent ConsumeNonce may succeed, got %d", winners)
		}
	})

	// ConsumeRejects: an unknown, empty, or expired nonce never consumes —
	// the store fails closed.
	t.Run("ConsumeRejects", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		if s.ConsumeNonce("never-issued", now) {
			t.Fatal("an unknown nonce must not consume")
		}
		if s.ConsumeNonce("", now) {
			t.Fatal("an empty nonce must not consume")
		}
		nonce, err := s.IssueNonce(now.Add(10*time.Second), now)
		if err != nil {
			t.Fatalf("IssueNonce: %v", err)
		}
		if s.ConsumeNonce(nonce, now.Add(11*time.Second)) {
			t.Fatal("an expired nonce must not consume")
		}
	})
}
