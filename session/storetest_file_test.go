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
