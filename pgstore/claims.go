package pgstore

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Idempotency claim store, satisfying mcp.ClaimStore structurally (pgstore
// deliberately does not import mcp; the conformance test asserts the
// interface). FAIL CLOSED: any database error is returned and the caller
// refuses to execute — an unreachable store must never allow a
// possibly-duplicate execution.

// Claim atomically claims key until expiry: the primary-key insert is the
// atomic first-claimant decision. On conflict the existing claim's state is
// reported (done + recorded result, or pending).
func (s *Store) Claim(key string, expiry, now time.Time) (won, done bool, result []byte, err error) {
	s.evictExpired(s.idemClaims, now)
	res, err := s.db.Exec(
		fmt.Sprintf(`INSERT INTO %s (key, expiry) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, s.idemClaims),
		key, expiry,
	)
	if err != nil {
		return false, false, nil, fmt.Errorf("pgstore: idempotency claim: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, false, nil, fmt.Errorf("pgstore: idempotency claim: %w", err)
	}
	if n == 1 {
		return true, false, nil, nil
	}
	// Conflict: read the live claim. An expired row is ignored (and a row
	// vanishing between insert and select reads as pending — the caller
	// re-claims and the next attempt decides).
	err = s.db.QueryRow(
		fmt.Sprintf(`SELECT done, result FROM %s WHERE key = $1 AND expiry >= $2`, s.idemClaims),
		key, now,
	).Scan(&done, &result)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil, nil
	}
	if err != nil {
		return false, false, nil, fmt.Errorf("pgstore: idempotency claim: %w", err)
	}
	return false, done, result, nil
}

// Complete records the claim's terminal outcome (nil result = executed but
// uncacheable). The WHERE guard makes it a no-op for an absent, already-done,
// expired, or different-generation claim (expiry must equal the exact value
// the winning Claim stored — timestamps round-trip at microsecond precision,
// identically on insert and compare): a stale completer whose execution
// outlived its TTL must never mark a successor's live claim done, an expired
// row's dedup horizon has passed so it is not resurrected, and a recorded
// terminal outcome is immutable.
func (s *Store) Complete(key string, result []byte, expiry, now time.Time) error {
	if _, err := s.db.Exec(
		fmt.Sprintf(`UPDATE %s SET done = TRUE, result = $2 WHERE key = $1 AND NOT done AND expiry = $3 AND expiry >= $4`, s.idemClaims),
		key, result, expiry, now,
	); err != nil {
		return fmt.Errorf("pgstore: idempotency complete: %w", err)
	}
	return nil
}
