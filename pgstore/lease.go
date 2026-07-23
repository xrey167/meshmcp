package pgstore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xrey167/meshmcp/session"
)

func (s *Store) AcquireLease(id, owner string, expectedGen uint64, ttl time.Duration, now time.Time) (session.Lease, bool, error) {
	return s.casLease(id, owner, expectedGen, ttl, now, false)
}

func (s *Store) TakeoverLease(id, owner string, expectedGen uint64, ttl time.Duration, now time.Time) (session.Lease, bool, error) {
	return s.casLease(id, owner, expectedGen, ttl, now, true)
}

// casLease is the transactional mirror of session's canAcquire/canTakeover:
// SELECT ... FOR UPDATE serializes racers on an existing row, and the
// ON CONFLICT DO NOTHING insert arbitrates a fresh id, so among several
// racing acquirers exactly one wins. takeover skips the liveness check
// (identity-bound reattach) but keeps the generation CAS. Liveness and
// expiry use the caller-passed now, never the database clock.
func (s *Store) casLease(id, owner string, expectedGen uint64, ttl time.Duration, now time.Time, takeover bool) (session.Lease, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return session.Lease{}, false, err
	}
	defer tx.Rollback()

	var curOwner string
	var curGen, curExp int64
	err = tx.QueryRow(
		fmt.Sprintf(`SELECT owner, generation, lease_expiry FROM %s WHERE id = $1 FOR UPDATE`, s.sessions),
		id,
	).Scan(&curOwner, &curGen, &curExp)
	exp := now.Add(ttl)

	if err == sql.ErrNoRows {
		if expectedGen != 0 {
			return session.Lease{}, false, nil
		}
		payload, err := json.Marshal(session.PersistedSession{
			ID: id, Owner: owner, Generation: 1, LeaseExpiry: exp.UnixNano(),
			SchemaVersion: session.SessionSchemaVersion, // mirror FileStore's write stamp
		})
		if err != nil {
			return session.Lease{}, false, err
		}
		res, err := tx.Exec(
			fmt.Sprintf(`INSERT INTO %s (id, owner, generation, lease_expiry, payload) VALUES ($1, $2, 1, $3, $4) ON CONFLICT (id) DO NOTHING`, s.sessions),
			id, owner, exp.UnixNano(), payload,
		)
		if err != nil {
			return session.Lease{}, false, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return session.Lease{}, false, err
		}
		if n == 0 {
			return session.Lease{}, false, nil // another gateway won the insert race
		}
		if err := tx.Commit(); err != nil {
			return session.Lease{}, false, err
		}
		return session.Lease{SessionID: id, Owner: owner, Generation: 1, Expiry: exp}, true, nil
	}
	if err != nil {
		return session.Lease{}, false, err
	}

	if !takeover {
		if live := now.UnixNano() < curExp; live && curOwner != owner {
			return session.Lease{}, false, nil // a live lease is held by another gateway
		}
	}
	if uint64(curGen) != expectedGen {
		return session.Lease{}, false, nil // the generation moved under us (lost the CAS race)
	}
	newGen := uint64(curGen) + 1
	if _, err := tx.Exec(
		fmt.Sprintf(`UPDATE %s SET owner = $2, generation = $3, lease_expiry = $4 WHERE id = $1`, s.sessions),
		id, owner, int64(newGen), exp.UnixNano(),
	); err != nil {
		return session.Lease{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return session.Lease{}, false, err
	}
	return session.Lease{SessionID: id, Owner: owner, Generation: newGen, Expiry: exp}, true, nil
}

func (s *Store) RenewLease(id, owner string, gen uint64, ttl time.Duration, now time.Time) (session.Lease, bool, error) {
	exp := now.Add(ttl)
	res, err := s.db.Exec(
		fmt.Sprintf(`UPDATE %s SET lease_expiry = $4 WHERE id = $1 AND owner = $2 AND generation = $3`, s.sessions),
		id, owner, int64(gen), exp.UnixNano(),
	)
	if err != nil {
		return session.Lease{}, false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return session.Lease{}, false, err
	}
	return session.Lease{SessionID: id, Owner: owner, Generation: gen, Expiry: exp}, true, nil
}

func (s *Store) ReleaseLease(id, owner string, gen uint64) (bool, error) {
	// Free the lease; keep generation + state (the next acquirer must present
	// the current generation as expectedGen).
	res, err := s.db.Exec(
		fmt.Sprintf(`UPDATE %s SET owner = '', lease_expiry = 0 WHERE id = $1 AND owner = $2 AND generation = $3`, s.sessions),
		id, owner, int64(gen),
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	return true, nil
}

func (s *Store) SaveIfOwned(ps session.PersistedSession, owner string, gen uint64) (bool, error) {
	// The conditional UPDATE is the fence: rowcount 0 means (owner, gen) no
	// longer hold the lease. lease_expiry is untouched — the caller cannot
	// change lease fields via save.
	ps.Owner, ps.Generation = owner, gen
	ps.SchemaVersion = session.SessionSchemaVersion // mirror FileStore's write stamp
	payload, err := json.Marshal(ps)
	if err != nil {
		return false, err
	}
	res, err := s.db.Exec(
		fmt.Sprintf(`UPDATE %s SET payload = $4 WHERE id = $1 AND owner = $2 AND generation = $3`, s.sessions),
		ps.ID, owner, int64(gen), payload,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	return true, nil
}
