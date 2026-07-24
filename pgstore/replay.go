package pgstore

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

// Replay-protection stores. Every boolean-returning op treats a database
// error as a replay (false) — FAIL CLOSED, mirroring policy.IsRevoked: an
// unreachable store must never wave a possibly-replayed credential through.

// evictExpired opportunistically drops rows whose expiry has passed, bounding
// retention like MemNonceStore/MemDPoPReplayStore. Failure is harmless: an
// expired row is already logically dead.
func (s *Store) evictExpired(table string, now time.Time) {
	_, _ = s.db.Exec(fmt.Sprintf(`DELETE FROM %s WHERE expiry < $1`, table), now)
}

// Use implements policy.NonceStore for delegation tokens: the first use of a
// nonce wins the insert, a replay conflicts and returns false.
func (s *Store) Use(nonce string, expiry, now time.Time) bool {
	s.evictExpired(s.nonces, now)
	res, err := s.db.Exec(
		fmt.Sprintf(`INSERT INTO %s (nonce, expiry) VALUES ($1, $2) ON CONFLICT (nonce) DO NOTHING`, s.nonces),
		nonce, expiry,
	)
	if err != nil {
		return false
	}
	n, err := res.RowsAffected()
	return err == nil && n == 1
}

// RedeemPaymentRef claims a settlement reference hash for single use across the
// fleet: the first redemption wins the insert (true), a replay conflicts
// (false). A database error is returned so the caller can fail closed with a
// distinct "store unavailable" outcome (retryable) versus a definite replay.
// expiry bounds retention (the on-chain authorization is dead by then).
func (s *Store) RedeemPaymentRef(refHash string, expiry, now time.Time) (bool, error) {
	s.evictExpired(s.paymentRefs, now)
	res, err := s.db.Exec(
		fmt.Sprintf(`INSERT INTO %s (refhash, expiry) VALUES ($1, $2) ON CONFLICT (refhash) DO NOTHING`, s.paymentRefs),
		refHash, expiry,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *Store) UseJTI(jti string, expiry, now time.Time) bool {
	s.evictExpired(s.dpopJTIs, now)
	res, err := s.db.Exec(
		fmt.Sprintf(`INSERT INTO %s (jti, expiry) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING`, s.dpopJTIs),
		jti, expiry,
	)
	if err != nil {
		return false
	}
	n, err := res.RowsAffected()
	return err == nil && n == 1
}

func (s *Store) IssueNonce(expiry, now time.Time) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("pgstore: dpop nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(b[:])
	s.evictExpired(s.dpopNonces, now)
	if _, err := s.db.Exec(
		fmt.Sprintf(`INSERT INTO %s (nonce, expiry) VALUES ($1, $2)`, s.dpopNonces),
		nonce, expiry,
	); err != nil {
		return "", fmt.Errorf("pgstore: dpop nonce: %w", err)
	}
	return nonce, nil
}

func (s *Store) ConsumeNonce(nonce string, now time.Time) bool {
	if nonce == "" {
		return false
	}
	// Single-use: the DELETE both validates (unexpired) and burns the nonce.
	res, err := s.db.Exec(
		fmt.Sprintf(`DELETE FROM %s WHERE nonce = $1 AND expiry >= $2`, s.dpopNonces),
		nonce, now,
	)
	if err != nil {
		return false
	}
	n, err := res.RowsAffected()
	return err == nil && n == 1
}

func (s *Store) Len() int {
	var n int
	if err := s.db.QueryRow(
		fmt.Sprintf(`SELECT (SELECT count(*) FROM %s) + (SELECT count(*) FROM %s)`, s.dpopJTIs, s.dpopNonces),
	).Scan(&n); err != nil {
		return 0
	}
	return n
}
