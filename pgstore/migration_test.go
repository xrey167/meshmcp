package pgstore

import (
	"testing"

	"github.com/xrey167/meshmcp/session"
	"github.com/xrey167/meshmcp/session/storetest"
)

// TestPGSessionMigratesAcrossGateways proves the end-to-end failover flow —
// crash gateway 1, reattach to gateway 2, rehydrate + lease takeover — over a
// live PostgreSQL store, i.e. across what would be separate hosts in
// production. This is the server-level counterpart of the store-level CAS
// conformance run in pgstore_test.go.
func TestPGSessionMigratesAcrossGateways(t *testing.T) {
	storetest.RunSessionMigration(t, func(t *testing.T) session.SessionStore {
		return openTestStore(t)
	})
}
