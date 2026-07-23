package air

import (
	"path/filepath"
	"testing"
	"time"
)

func openTestGrantStore(t *testing.T) *GrantStore {
	t.Helper()
	gs, err := OpenGrantStore(filepath.Join(t.TempDir(), "grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	return gs
}

// TestMoveGrantSingleUse proves the core authorization contract of a live-session
// move: a move grant authorizes exactly one commit and is then gone (a second
// move of the same session to the same destination is denied by default).
func TestMoveGrantSingleUse(t *testing.T) {
	gs := openTestGrantStore(t)
	now := time.Unix(1000, 0)
	const dest = "wg-destination-key"
	const sess = "cf44afe7a38f3bce8b7a16f0d5768bb6"

	if _, err := GrantMoveTarget(gs, dest, sess, "operator", now); err != nil {
		t.Fatalf("GrantMoveTarget: %v", err)
	}
	// Non-consuming check (as at prepare) sees it.
	if !CheckMoveGrant(gs, dest, sess) {
		t.Fatal("CheckMoveGrant should see the fresh grant")
	}
	// First commit consumes it.
	consumed, err := ConsumeMoveGrant(gs, dest, sess, now)
	if err != nil || !consumed {
		t.Fatalf("first consume: consumed=%v err=%v, want true", consumed, err)
	}
	// It is now gone: the check and a second consume both fail (deny-by-default).
	if CheckMoveGrant(gs, dest, sess) {
		t.Fatal("grant must be gone after being consumed")
	}
	if consumed, _ := ConsumeMoveGrant(gs, dest, sess, now); consumed {
		t.Fatal("a second move must not be authorized by a spent single-use grant")
	}
}

// TestMoveGrantScopedToSession proves a grant for one session never authorizes a
// different session, nor a different destination.
func TestMoveGrantScopedToSession(t *testing.T) {
	gs := openTestGrantStore(t)
	now := time.Unix(1000, 0)
	if _, err := GrantMoveTarget(gs, "dest-A", "session-1", "operator", now); err != nil {
		t.Fatal(err)
	}
	if CheckMoveGrant(gs, "dest-A", "session-2") {
		t.Fatal("a grant for session-1 must not authorize session-2")
	}
	if CheckMoveGrant(gs, "dest-B", "session-1") {
		t.Fatal("a grant for dest-A must not authorize dest-B")
	}
	if consumed, _ := ConsumeMoveGrant(gs, "dest-A", "session-2", now); consumed {
		t.Fatal("consuming the wrong session must not succeed")
	}
	// The correct (dest, session) still consumes.
	if consumed, _ := ConsumeMoveGrant(gs, "dest-A", "session-1", now); !consumed {
		t.Fatal("the exact (dest, session) grant must consume")
	}
}

// TestMoveGrantUnauthorizedByDefault proves that with no grant written, a move is
// denied.
func TestMoveGrantUnauthorizedByDefault(t *testing.T) {
	gs := openTestGrantStore(t)
	if CheckMoveGrant(gs, "dest", "sess") {
		t.Fatal("no grant should exist")
	}
	if consumed, _ := ConsumeMoveGrant(gs, "dest", "sess", time.Unix(1, 0)); consumed {
		t.Fatal("deny-by-default: no grant means no authorization")
	}
}

// TestMoveGrantRevoke proves an operator can withdraw an unspent grant.
func TestMoveGrantRevoke(t *testing.T) {
	gs := openTestGrantStore(t)
	now := time.Unix(1000, 0)
	if _, err := GrantMoveTarget(gs, "dest", "sess", "operator", now); err != nil {
		t.Fatal(err)
	}
	removed, err := RevokeMoveGrant(gs, "dest", "sess")
	if err != nil || !removed {
		t.Fatalf("revoke: removed=%v err=%v, want true", removed, err)
	}
	if consumed, _ := ConsumeMoveGrant(gs, "dest", "sess", now); consumed {
		t.Fatal("a revoked grant must not authorize a move")
	}
}

// TestMoveGrantPersists proves a written move grant survives reopening the store
// (durable operator authorization).
func TestMoveGrantPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grants.json")
	gs, err := OpenGrantStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GrantMoveTarget(gs, "dest", "sess", "operator", time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenGrantStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckMoveGrant(reopened, "dest", "sess") {
		t.Fatal("move grant did not survive store reopen")
	}
}
