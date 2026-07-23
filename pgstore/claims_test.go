package pgstore

import (
	"bytes"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/mcp"
	"github.com/xrey167/meshmcp/mcp/claimtest"
)

// Store satisfies mcp.ClaimStore structurally (pgstore does not import mcp
// outside tests); this assertion keeps the shapes locked together.
var _ mcp.ClaimStore = (*Store)(nil)

func TestPGClaimStoreConformance(t *testing.T) {
	requireDSN(t)
	claimtest.RunClaimStoreConformance(t, func(t *testing.T) mcp.ClaimStore { return openTestStore(t) })
}

// TestPGClaimCompleteWallClockExpiry: Complete's generation guard compares
// the stored expiry for EQUALITY, so a nanosecond-precision wall-clock expiry
// must round-trip PostgreSQL's microsecond timestamptz deterministically —
// Claim (insert) and Complete (compare) encode the same time.Time identically.
// The conformance harness uses whole-second times, so this is the one case it
// cannot catch.
func TestPGClaimCompleteWallClockExpiry(t *testing.T) {
	requireDSN(t)
	s := openTestStore(t)
	now := time.Now()
	expiry := now.Add(time.Minute)
	if won, _, _, err := s.Claim("k-wall", expiry, now); err != nil || !won {
		t.Fatalf("claim: won=%v err=%v", won, err)
	}
	payload := []byte(`{"err":"wall"}`)
	if err := s.Complete("k-wall", payload, expiry, time.Now()); err != nil {
		t.Fatalf("complete: %v", err)
	}
	won, done, res, err := s.Claim("k-wall", expiry, time.Now())
	if err != nil || won || !done || !bytes.Equal(res, payload) {
		t.Fatalf("wall-clock expiry must round-trip the generation guard: won=%v done=%v res=%q err=%v", won, done, res, err)
	}
}
