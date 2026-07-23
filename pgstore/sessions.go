package pgstore

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/xrey167/meshmcp/session"
)

// scanPersisted rebuilds a PersistedSession from a row. The columns are the
// CAS source of truth, so they override whatever the payload carries.
func scanPersisted(id, owner string, gen, exp int64, payload []byte) (session.PersistedSession, error) {
	var ps session.PersistedSession
	if err := json.Unmarshal(payload, &ps); err != nil {
		return session.PersistedSession{}, err
	}
	ps.ID, ps.Owner, ps.Generation, ps.LeaseExpiry = id, owner, uint64(gen), exp
	return ps, nil
}

func (s *Store) Save(ps session.PersistedSession) error {
	// Stamp the format version like FileStore.Save, so an older build reading
	// this row after a schema bump can recognize it as too new to trust.
	ps.SchemaVersion = session.SessionSchemaVersion
	payload, err := json.Marshal(ps)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		fmt.Sprintf(`INSERT INTO %s (id, owner, generation, lease_expiry, payload) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (id) DO UPDATE SET owner = EXCLUDED.owner, generation = EXCLUDED.generation, lease_expiry = EXCLUDED.lease_expiry, payload = EXCLUDED.payload`, s.sessions),
		ps.ID, ps.Owner, int64(ps.Generation), ps.LeaseExpiry, payload,
	)
	return err
}

func (s *Store) Load(id string) (session.PersistedSession, bool, error) {
	var owner string
	var gen, exp int64
	var payload []byte
	err := s.db.QueryRow(
		fmt.Sprintf(`SELECT owner, generation, lease_expiry, payload FROM %s WHERE id = $1`, s.sessions),
		id,
	).Scan(&owner, &gen, &exp, &payload)
	if err == sql.ErrNoRows {
		return session.PersistedSession{}, false, nil
	}
	if err != nil {
		return session.PersistedSession{}, false, err
	}
	ps, err := scanPersisted(id, owner, gen, exp, payload)
	if err != nil {
		return session.PersistedSession{}, false, err
	}
	if ps.SchemaVersion > session.SessionSchemaVersion {
		// Written by a newer build: treat as no resumable session so the client
		// reconnects fresh (mirror FileStore) rather than resuming against a
		// format this build may misread.
		return session.PersistedSession{}, false, nil
	}
	return ps, true, nil
}

func (s *Store) DeleteIfOwner(id, owner string) error {
	// Owner mismatch or missing row is a silent no-op, mirroring FileStore: a
	// reaper on a superseded gateway must not delete a resumed session.
	_, err := s.db.Exec(
		fmt.Sprintf(`DELETE FROM %s WHERE id = $1 AND owner = $2`, s.sessions),
		id, owner,
	)
	return err
}

// List enumerates every persisted session. Rows whose payload fails to parse
// are skipped (mirroring FileStore's tolerance of unparseable files), so one
// bad record never turns enumeration into an error.
func (s *Store) List() ([]session.PersistedSession, error) {
	rows, err := s.db.Query(
		fmt.Sprintf(`SELECT id, owner, generation, lease_expiry, payload FROM %s`, s.sessions),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []session.PersistedSession
	for rows.Next() {
		var id, owner string
		var gen, exp int64
		var payload []byte
		if err := rows.Scan(&id, &owner, &gen, &exp, &payload); err != nil {
			return nil, err
		}
		// Skip newer-format rows like any unreadable one (mirror FileStore):
		// the standby sweep adopts from List, and an older build must never
		// respawn a session from a checkpoint it may misread.
		if ps, err := scanPersisted(id, owner, gen, exp, payload); err == nil && ps.ID != "" &&
			ps.SchemaVersion <= session.SessionSchemaVersion {
			out = append(out, ps)
		}
	}
	return out, rows.Err()
}
