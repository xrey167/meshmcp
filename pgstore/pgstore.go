// Package pgstore backs the session lease store and the replay-protection
// stores with PostgreSQL. Unlike FileStore (single-node development), the
// lease compare-and-swap here is a real distributed CAS: every lease op is a
// row-locked transaction, so it is safe for cross-gateway HA (see
// session.LeaseStore's durability note).
package pgstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

// openTimeout bounds the initial ping and schema apply. pgx sets no default
// connect timeout, so without this a black-holed database host would stall
// serve/doctor for the OS TCP timeout instead of failing promptly.
const openTimeout = 10 * time.Second

var (
	_ session.SessionStore   = (*Store)(nil)
	_ session.LeaseStore     = (*Store)(nil)
	_ policy.NonceStore      = (*Store)(nil)
	_ policy.DPoPReplayStore = (*Store)(nil)
)

// Store is a PostgreSQL-backed SessionStore, LeaseStore, NonceStore, and
// DPoPReplayStore. Safe for concurrent use (database/sql pools connections;
// atomicity comes from the database, not process-local locks).
type Store struct {
	db *sql.DB
	// Table names, fixed at Open. A non-empty prefix (tests) keeps parallel
	// runs against a shared database from colliding.
	sessions, nonces, dpopNonces, dpopJTIs string
}

// Open connects to PostgreSQL, verifies the connection, and applies the
// idempotent embedded schema (CREATE TABLE IF NOT EXISTS).
func Open(dsn string) (*Store, error) {
	return open(dsn, "")
}

// open is Open with a table-name prefix, used by tests to isolate runs.
func open(dsn, prefix string) (*Store, error) {
	if err := validPrefix(prefix); err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("pgstore: open: %w", err)
	}
	s := &Store{
		db:         db,
		sessions:   prefix + "sessions",
		nonces:     prefix + "nonces",
		dpopNonces: prefix + "dpop_nonces",
		dpopJTIs:   prefix + "dpop_jtis",
	}
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("pgstore: ping: %w", err)
	}
	for _, ddl := range []string{
		fmt.Sprintf(ddlSessions, s.sessions),
		fmt.Sprintf(ddlNonces, s.nonces),
		fmt.Sprintf(ddlDPoPNonces, s.dpopNonces),
		fmt.Sprintf(ddlDPoPJTIs, s.dpopJTIs),
	} {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			db.Close()
			return nil, fmt.Errorf("pgstore: schema: %w", err)
		}
	}
	return s, nil
}

// Check verifies the database is reachable without touching the schema — the
// side-effect-free pre-flight probe behind `meshmcp doctor`, safe to run with
// a credential that lacks DDL privileges. Only Open (serve) applies schema.
func Check(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("pgstore: open: %w", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), openTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("pgstore: ping: %w", err)
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

// validPrefix restricts the table prefix to a safe SQL identifier fragment,
// because table names are interpolated (placeholders cannot name tables).
func validPrefix(prefix string) error {
	for i, r := range prefix {
		switch {
		case r >= 'a' && r <= 'z', r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return fmt.Errorf("pgstore: table prefix %q must not start with a digit", prefix)
			}
		default:
			return fmt.Errorf("pgstore: table prefix %q may only contain [a-z0-9_]", prefix)
		}
	}
	return nil
}
