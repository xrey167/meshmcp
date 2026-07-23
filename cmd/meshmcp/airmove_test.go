package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
)

// TestAirMoveGrantWritesConsumableGrant proves the CLI writes a move grant the
// destination can consume exactly once at commit (the invariant-3 single-use
// authorization), and that revoke and validation behave.
func TestAirMoveGrantWritesConsumableGrant(t *testing.T) {
	store := filepath.Join(t.TempDir(), "grants.json")
	const dest = "wg-destination-gateway-key"
	const sess = "cf44afe7a38f3bce8b7a16f0d5768bb6"

	if err := cmdAirMoveGrant([]string{"--grant-store", store, "--by", "op@mesh", "pubkey:" + dest, sess}); err != nil {
		t.Fatalf("air move grant: %v", err)
	}

	// The destination side sees and consumes it exactly once.
	gs, err := air.OpenGrantStore(store)
	if err != nil {
		t.Fatal(err)
	}
	if !air.CheckMoveGrant(gs, dest, sess) {
		t.Fatal("written grant not visible to the destination")
	}
	if consumed, _ := air.ConsumeMoveGrant(gs, dest, sess, time.Unix(1000, 0)); !consumed {
		t.Fatal("destination should consume the grant once")
	}
	if consumed, _ := air.ConsumeMoveGrant(gs, dest, sess, time.Unix(1000, 0)); consumed {
		t.Fatal("grant must be single-use")
	}
}

func TestAirMoveGrantListAndRevoke(t *testing.T) {
	store := filepath.Join(t.TempDir(), "grants.json")
	const dest = "wg-dest"
	const sess = "00112233445566778899aabbccddeeff"
	if err := cmdAirMoveGrant([]string{"--grant-store", store, dest, sess}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := cmdAirMoveGrantList([]string{"--grant-store", store}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if err := cmdAirMoveGrantRevoke([]string{"--grant-store", store, dest, sess}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	gs, err := air.OpenGrantStore(store)
	if err != nil {
		t.Fatal(err)
	}
	if air.CheckMoveGrant(gs, dest, sess) {
		t.Fatal("grant should be gone after revoke")
	}
	// Revoking a missing grant is an error the CLI surfaces.
	if err := cmdAirMoveGrantRevoke([]string{"--grant-store", store, dest, sess}); err == nil {
		t.Fatal("revoke of a missing grant should error")
	}
}

func TestAirMoveGrantRejectsBadArgs(t *testing.T) {
	store := filepath.Join(t.TempDir(), "grants.json")
	// Non-hex session id.
	if err := cmdAirMoveGrant([]string{"--grant-store", store, "dest", "not-hex-id!"}); err == nil {
		t.Fatal("non-hex session id should be rejected")
	}
	// Missing grant store.
	if err := cmdAirMoveGrant([]string{"dest", "00ff"}); err == nil {
		t.Fatal("missing --grant-store should be rejected")
	}
	// Wrong arg count.
	if err := cmdAirMoveGrant([]string{"--grant-store", store, "dest"}); err == nil {
		t.Fatal("missing session id should be rejected")
	}
}

func TestAirMoveDispatch(t *testing.T) {
	if err := cmdAirMove([]string{"bogus"}); err == nil {
		t.Fatal("unknown subcommand should error")
	}
	if err := cmdAirMove([]string{"help"}); err != nil {
		t.Fatalf("help should not error: %v", err)
	}
}
