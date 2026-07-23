package pgstore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/policy/replaytest"
	"github.com/xrey167/meshmcp/session"
	"github.com/xrey167/meshmcp/session/storetest"
)

const testDSNEnv = "MESHMCP_TEST_PG_DSN"

// openTestStore opens a Store with a random table prefix, so parallel runs
// against a shared database never collide, and drops the tables on cleanup.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv(testDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping PostgreSQL integration test", testDSNEnv)
	}
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	st, err := open(dsn, fmt.Sprintf("cf_%s_", hex.EncodeToString(b[:])))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		for _, tbl := range []string{st.sessions, st.nonces, st.dpopNonces, st.dpopJTIs} {
			st.db.Exec("DROP TABLE IF EXISTS " + tbl)
		}
		st.Close()
	})
	return st
}

func requireDSN(t *testing.T) {
	t.Helper()
	if os.Getenv(testDSNEnv) == "" {
		t.Skipf("%s not set; skipping PostgreSQL integration test", testDSNEnv)
	}
}

func TestPGLeaseStoreConformance(t *testing.T) {
	requireDSN(t)
	storetest.RunLeaseStoreConformance(t, func(t *testing.T) session.LeaseStore { return openTestStore(t) })
}

func TestPGSessionStoreConformance(t *testing.T) {
	requireDSN(t)
	storetest.RunSessionStoreConformance(t, func(t *testing.T) session.SessionStore { return openTestStore(t) })
}

func TestPGNonceStoreConformance(t *testing.T) {
	requireDSN(t)
	replaytest.RunNonceStoreConformance(t, func(t *testing.T) policy.NonceStore { return openTestStore(t) })
}

func TestPGDPoPReplayStoreConformance(t *testing.T) {
	requireDSN(t)
	replaytest.RunDPoPReplayStoreConformance(t, func(t *testing.T) policy.DPoPReplayStore { return openTestStore(t) })
}

func TestOpenRejectsBadPrefix(t *testing.T) {
	// Prefix validation runs before any connection, so no database is needed.
	for _, prefix := range []string{"1bad", "bad-prefix", "Bad", "drop table;"} {
		if _, err := open("host=unused", prefix); err == nil {
			t.Fatalf("prefix %q should be rejected", prefix)
		}
	}
	if err := validPrefix("cf_ab12_"); err != nil {
		t.Fatalf("valid prefix rejected: %v", err)
	}
}
