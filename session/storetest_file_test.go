package session_test

import (
	"testing"

	"github.com/xrey167/meshmcp/session"
	"github.com/xrey167/meshmcp/session/storetest"
)

// The built-in stores must pass the shared conformance harness — the same
// contract any external backend (e.g. PostgreSQL) is held to.

func TestMemStoreConformance(t *testing.T) {
	storetest.RunLeaseStoreConformance(t, func(t *testing.T) session.LeaseStore {
		return session.NewMemStore()
	})
	storetest.RunSessionStoreConformance(t, func(t *testing.T) session.SessionStore {
		return session.NewMemStore()
	})
}

// TestMemStoreSessionMigration keeps the public-API migration harness honest
// on every run (no external database needed); pgstore runs the same harness
// against live PostgreSQL when MESHMCP_TEST_PG_DSN is set.
func TestMemStoreSessionMigration(t *testing.T) {
	storetest.RunSessionMigration(t, func(t *testing.T) session.SessionStore {
		return session.NewMemStore()
	})
}

// TestMemStoreSessionLiveMove exercises the deliberate prepare->ready->commit
// live-session MOVE (v2) against the public API on every run; pgstore runs the
// same harness against live PostgreSQL when MESHMCP_TEST_PG_DSN is set.
func TestMemStoreSessionLiveMove(t *testing.T) {
	storetest.RunSessionLiveMove(t, func(t *testing.T) session.SessionStore {
		return session.NewMemStore()
	})
}

func TestFileStoreConformance(t *testing.T) {
	storetest.RunLeaseStoreConformance(t, func(t *testing.T) session.LeaseStore {
		s, err := session.NewFileStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
	storetest.RunSessionStoreConformance(t, func(t *testing.T) session.SessionStore {
		s, err := session.NewFileStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}
