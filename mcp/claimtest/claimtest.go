// Package claimtest is the conformance harness for idempotency claim stores:
// every mcp.ClaimStore backend (in-memory, PostgreSQL, ...) must pass the
// same atomic-claim contract, so a new backend proves it by running this
// function against a fresh store.
package claimtest

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/mcp"
)

// RunClaimStoreConformance proves the idempotency-claim contract against the
// implementation returned by open. open must return a fresh, empty store on
// every call.
func RunClaimStoreConformance(t *testing.T, open func(t *testing.T) mcp.ClaimStore) {
	// FirstClaimWins: the first Claim of a key wins; a second sees the claim
	// pending (not done) while the winner has not completed.
	t.Run("FirstClaimWins", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		expiry := now.Add(time.Minute)
		won, done, _, err := s.Claim("k1", expiry, now)
		if err != nil || !won || done {
			t.Fatalf("first claim: won=%v done=%v err=%v, want won", won, done, err)
		}
		won, done, _, err = s.Claim("k1", expiry, now.Add(time.Second))
		if err != nil || won || done {
			t.Fatalf("duplicate claim: won=%v done=%v err=%v, want pending", won, done, err)
		}
	})

	// ConcurrentClaimSingleWinner: many claimants racing the SAME key — the
	// claim must be atomic (check-then-act would double-execute), so exactly
	// one sees won.
	t.Run("ConcurrentClaimSingleWinner", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		expiry := now.Add(time.Minute)
		var winners int64
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if won, _, _, err := s.Claim("k1", expiry, now); err == nil && won {
					atomic.AddInt64(&winners, 1)
				}
			}()
		}
		wg.Wait()
		if winners != 1 {
			t.Fatalf("exactly one concurrent Claim may win, got %d", winners)
		}
	})

	// CompleteThenReplay: after Complete, a replay of the key sees done with
	// the exact recorded payload.
	t.Run("CompleteThenReplay", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		expiry := now.Add(time.Minute)
		if won, _, _, err := s.Claim("k1", expiry, now); err != nil || !won {
			t.Fatalf("first claim must win, err=%v", err)
		}
		payload := []byte(`{"result":{"content":[{"type":"text","text":"ok"}]}}`)
		if err := s.Complete("k1", payload, expiry, now.Add(time.Second)); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		won, done, res, err := s.Claim("k1", expiry, now.Add(2*time.Second))
		if err != nil || won || !done || !bytes.Equal(res, payload) {
			t.Fatalf("replay: won=%v done=%v res=%q err=%v, want recorded payload", won, done, res, err)
		}
	})

	// UncacheableOutcome: Complete with an empty payload marks the claim done
	// with no result — replays must see done and an empty result, never win.
	t.Run("UncacheableOutcome", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		expiry := now.Add(time.Minute)
		if won, _, _, err := s.Claim("k1", expiry, now); err != nil || !won {
			t.Fatalf("first claim must win, err=%v", err)
		}
		if err := s.Complete("k1", nil, expiry, now.Add(time.Second)); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		won, done, res, err := s.Claim("k1", expiry, now.Add(2*time.Second))
		if err != nil || won || !done || len(res) != 0 {
			t.Fatalf("replay: won=%v done=%v res=%q err=%v, want done with empty result", won, done, res, err)
		}
	})

	// DistinctKeysIndependent: a claim on one key never affects another.
	t.Run("DistinctKeysIndependent", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		expiry := now.Add(time.Minute)
		if won, _, _, err := s.Claim("k1", expiry, now); err != nil || !won {
			t.Fatalf("first claim of k1 must win, err=%v", err)
		}
		if won, _, _, err := s.Claim("k2", expiry, now); err != nil || !won {
			t.Fatalf("first claim of k2 must win, err=%v", err)
		}
	})

	// ExpiredReclaimable: once a claim's expiry has passed the store may
	// forget it — the dedup horizon is the TTL, so a later claim wins again
	// and retention stays bounded.
	t.Run("ExpiredReclaimable", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		if won, _, _, err := s.Claim("k1", now.Add(10*time.Second), now); err != nil || !won {
			t.Fatalf("first claim must win, err=%v", err)
		}
		_ = s.Complete("k1", []byte(`{"err":"x"}`), now.Add(10*time.Second), now.Add(time.Second))
		won, done, _, err := s.Claim("k1", now.Add(time.Minute), now.Add(11*time.Second))
		if err != nil || !won || done {
			t.Fatalf("expired key: won=%v done=%v err=%v, want reclaimable", won, done, err)
		}
	})

	// CompleteAbsentIsNoop: completing an expired/absent claim must not
	// resurrect it.
	t.Run("CompleteAbsentIsNoop", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		if err := s.Complete("never-claimed", []byte(`{"err":"x"}`), now.Add(time.Minute), now); err != nil {
			t.Fatalf("Complete on absent claim must be a no-op, got %v", err)
		}
		won, done, _, err := s.Claim("never-claimed", now.Add(time.Minute), now)
		if err != nil || !won || done {
			t.Fatalf("absent key after stray Complete: won=%v done=%v err=%v, want a fresh win", won, done, err)
		}
	})

	// ExpiredCompleteIsNoop: a winner completing only AFTER its claim expired
	// records nothing — the dedup horizon passed mid-flight.
	t.Run("ExpiredCompleteIsNoop", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		e1 := now.Add(10 * time.Second)
		if won, _, _, err := s.Claim("k1", e1, now); err != nil || !won {
			t.Fatalf("first claim must win, err=%v", err)
		}
		if err := s.Complete("k1", []byte(`{"err":"late"}`), e1, now.Add(11*time.Second)); err != nil {
			t.Fatalf("late Complete: %v", err)
		}
		won, done, _, err := s.Claim("k1", now.Add(time.Minute), now.Add(12*time.Second))
		if err != nil || !won || done {
			t.Fatalf("late Complete must not resurrect an expired claim: won=%v done=%v err=%v, want a fresh win", won, done, err)
		}
	})

	// StaleGenerationCompleteIsNoop: a winner whose execution outlived its TTL
	// must never mark the SUCCESSOR's live claim for the same key done — the
	// expiry passed to Complete identifies exactly one claim generation.
	t.Run("StaleGenerationCompleteIsNoop", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		e1 := now.Add(10 * time.Second)
		if won, _, _, err := s.Claim("k1", e1, now); err != nil || !won {
			t.Fatalf("first claim must win, err=%v", err)
		}
		now2 := now.Add(11 * time.Second) // e1 has passed; a successor re-claims
		e2 := now2.Add(time.Minute)
		if won, _, _, err := s.Claim("k1", e2, now2); err != nil || !won {
			t.Fatalf("successor claim must win, err=%v", err)
		}
		if err := s.Complete("k1", []byte(`{"err":"stale"}`), e1, now2.Add(time.Second)); err != nil {
			t.Fatalf("stale Complete: %v", err)
		}
		won, done, _, err := s.Claim("k1", e2, now2.Add(2*time.Second))
		if err != nil || won || done {
			t.Fatalf("successor's claim must stay pending after a stale Complete: won=%v done=%v err=%v", won, done, err)
		}
		payload := []byte(`{"err":"live"}`)
		if err := s.Complete("k1", payload, e2, now2.Add(3*time.Second)); err != nil {
			t.Fatalf("live Complete: %v", err)
		}
		won, done, res, err := s.Claim("k1", e2, now2.Add(4*time.Second))
		if err != nil || won || !done || !bytes.Equal(res, payload) {
			t.Fatalf("live generation's outcome must land: won=%v done=%v res=%q err=%v", won, done, res, err)
		}
	})

	// CompletedOutcomeImmutable: a second Complete for the same generation
	// must not overwrite the recorded terminal outcome.
	t.Run("CompletedOutcomeImmutable", func(t *testing.T) {
		s := open(t)
		now := time.Unix(1000, 0)
		expiry := now.Add(time.Minute)
		if won, _, _, err := s.Claim("k1", expiry, now); err != nil || !won {
			t.Fatalf("first claim must win, err=%v", err)
		}
		first := []byte(`{"err":"first"}`)
		if err := s.Complete("k1", first, expiry, now.Add(time.Second)); err != nil {
			t.Fatalf("Complete: %v", err)
		}
		if err := s.Complete("k1", []byte(`{"err":"second"}`), expiry, now.Add(2*time.Second)); err != nil {
			t.Fatalf("second Complete: %v", err)
		}
		won, done, res, err := s.Claim("k1", expiry, now.Add(3*time.Second))
		if err != nil || won || !done || !bytes.Equal(res, first) {
			t.Fatalf("recorded outcome must be immutable: won=%v done=%v res=%q err=%v", won, done, res, err)
		}
	})
}
