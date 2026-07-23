package edge

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/pgstore"
	"github.com/xrey167/meshmcp/policy"
)

// fakeReplayStore is a DPoPReplayStore that records nothing and admits
// everything; tests only need its identity to prove injection.
type fakeReplayStore struct{}

func (fakeReplayStore) UseJTI(string, time.Time, time.Time) bool        { return true }
func (fakeReplayStore) IssueNonce(time.Time, time.Time) (string, error) { return "n", nil }
func (fakeReplayStore) ConsumeNonce(string, time.Time) bool             { return true }
func (fakeReplayStore) Len() int                                        { return 0 }

// newDPoPTestServer is newTestServer with control over the replay-store config
// field and the injected store.
func newDPoPTestServer(t *testing.T, dsn string, replay policy.DPoPReplayStore) (*Server, error) {
	t.Helper()
	dir := t.TempDir()
	cfg := validConfig()
	cfg.StateDir = dir
	cfg.AuditLog = filepath.Join(dir, "audit.jsonl")
	cfg.SigningKey = filepath.Join(dir, "key.json")
	cfg.OAuth.DPoPReplayStore = dsn

	signer, err := policy.GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return New(cfg, Options{
		Now:         func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		Signer:      signer,
		AuditWriter: &discardWriter{}, // shared test helper (mcp_test.go)
		DPoPReplay:  replay,
	})
}

func TestNewDefaultsToMemReplayStore(t *testing.T) {
	srv, err := newDPoPTestServer(t, "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v := srv.DPoPVerifier()
	if v == nil {
		t.Fatal("DPoPVerifier() = nil")
	}
	if _, ok := v.Replay.(*policy.MemDPoPReplayStore); !ok {
		t.Fatalf("default replay store = %T, want *policy.MemDPoPReplayStore", v.Replay)
	}
}

func TestNewInjectsProvidedReplayStore(t *testing.T) {
	fake := fakeReplayStore{}
	srv, err := newDPoPTestServer(t, "postgres://meshmcp@db.internal/meshmcp", fake)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := srv.DPoPVerifier().Replay; got != policy.DPoPReplayStore(fake) {
		t.Fatalf("replay store = %T, want the injected fake", got)
	}
}

// TestNewFailsClosedWhenReplayStoreMissing: a configured shared store that is
// not actually supplied must refuse construction, never silently degrade to
// per-process replay tracking.
func TestNewFailsClosedWhenReplayStoreMissing(t *testing.T) {
	_, err := newDPoPTestServer(t, "postgres://meshmcp@db.internal/meshmcp", nil)
	if err == nil || !strings.Contains(err.Error(), "dpop_replay_store") {
		t.Fatalf("want fail-closed construction error, got %v", err)
	}
}

// TestJTIReplayRejectedAcrossServers proves the cross-instance property the
// shared store exists for: two separately-constructed edges sharing one replay
// store reject a proof the other has already accepted.
func TestJTIReplayRejectedAcrossServers(t *testing.T) {
	shared := policy.NewMemDPoPReplayStore()
	a, err := newDPoPTestServer(t, "postgres://meshmcp@db.internal/meshmcp", shared)
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	b, err := newDPoPTestServer(t, "postgres://meshmcp@db.internal/meshmcp", shared)
	if err != nil {
		t.Fatalf("New b: %v", err)
	}
	assertSharedReplay(t, a, b)
}

// TestPGCrossInstanceJTIReplay is the live-database version: two edges, each
// with its OWN pgstore connection to the same database, must still agree on
// spent JTIs. Gated on MESHMCP_TEST_PG_DSN (pgstore's integration-test knob).
func TestPGCrossInstanceJTIReplay(t *testing.T) {
	dsn := os.Getenv("MESHMCP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("MESHMCP_TEST_PG_DSN not set; skipping PostgreSQL integration test")
	}
	storeA, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open a: %v", err)
	}
	defer storeA.Close()
	storeB, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open b: %v", err)
	}
	defer storeB.Close()

	a, err := newDPoPTestServer(t, dsn, storeA)
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	b, err := newDPoPTestServer(t, dsn, storeB)
	if err != nil {
		t.Fatalf("New b: %v", err)
	}
	assertSharedReplay(t, a, b)
}

// assertSharedReplay signs one DPoP proof, verifies it on a, then requires b
// to reject the identical proof as a jti replay.
func assertSharedReplay(t *testing.T, a, b *Server) {
	t.Helper()
	signer, err := policy.GenerateDPoPSigner()
	if err != nil {
		t.Fatalf("dpop signer: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	proof, err := signer.Proof(http.MethodPost, "https://mcp.example.com/token", now, "", "")
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	req := policy.DPoPVerifyRequest{
		Proof:  proof,
		Method: http.MethodPost,
		URL:    "https://mcp.example.com/token",
		Now:    now,
	}
	if err := a.DPoPVerifier().Verify(req); err != nil {
		t.Fatalf("first use on a: %v", err)
	}
	err = b.DPoPVerifier().Verify(req)
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("replay on b: want jti-replay rejection, got %v", err)
	}
}
