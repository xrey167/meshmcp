package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/air"
)

// Air Move is the operator-facing surface of the v1-of-v2 LIVE SESSION MOVE: a
// deliberate prepare -> ready -> commit relocation of one live session's
// ownership from a source gateway to a destination gateway, with the source
// serving until a single generation-fenced commit CAS, abort at every pre-commit
// step, and crash-recovery to exactly one owner. The safety-critical engine lives
// in the session package (session.Server.MoveSessionTo / ServeMoveControl,
// exercised by session/move_test.go's crash matrix and the storetest live-move
// conformance); it is a gateway-to-gateway operation between two running
// meshmcp gateways.
//
// What this CLI ships in v1 is the one discrete OPERATOR action in that flow: the
// single-use destination authorization. Live-session move is gated (invariant 3)
// on the destination being the creator-identity-verified reattach OR an
// explicitly-granted single-use target — never an arbitrary peer. `air move grant`
// writes that "this destination may receive this one session, once" grant into
// the destination's grant store; the destination CONSUMES it exactly once at
// commit (air.ConsumeMoveGrant), so a second move of the same session is denied
// by default. The prepare/ready/commit transfer itself is driven by the gateway,
// not a standalone CLI (the source is a long-running gateway that already owns the
// live session).
func cmdAirMove(args []string) error {
	if len(args) == 0 {
		return airMoveUsage()
	}
	switch args[0] {
	case "grant":
		return cmdAirMoveGrant(args[1:])
	case "help", "-h", "--help":
		return airMoveUsage()
	default:
		return fmt.Errorf("air move: unknown subcommand %q (want grant)", args[0])
	}
}

func airMoveUsage() error {
	fmt.Fprintln(os.Stderr, bold("meshmcp air move")+dim(" — live session move (v2): single-use destination authorization"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  "+bold("air move grant")+"        --grant-store <file> <dest-key> <session-id> [--by <operator>]")
	fmt.Fprintln(os.Stderr, "                        "+dim("authorize a destination to receive one session, once (deny-by-default)"))
	fmt.Fprintln(os.Stderr, "  "+bold("air move grant list")+"   --grant-store <file> [--json]")
	fmt.Fprintln(os.Stderr, "  "+bold("air move grant revoke")+" --grant-store <file> <dest-key> <session-id>")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, dim("The prepare->ready->commit transfer is a gateway-to-gateway operation driven by"))
	fmt.Fprintln(os.Stderr, dim("session.Server (MoveSessionTo / ServeMoveControl). The destination consumes this"))
	fmt.Fprintln(os.Stderr, dim("single-use grant at commit; the source keeps serving until the fenced CAS."))
	return nil
}

func cmdAirMoveGrant(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "list", "ls":
			return cmdAirMoveGrantList(args[1:])
		case "revoke", "rm":
			return cmdAirMoveGrantRevoke(args[1:])
		}
	}
	fs := flag.NewFlagSet("air move grant", flag.ExitOnError)
	storePath := fs.String("grant-store", "", "destination grant store file (required)")
	by := fs.String("by", "", "operator identity approving the grant (recorded)")
	asJSON := fs.Bool("json", false, "print the written grant as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 || *storePath == "" {
		return errors.New("usage: meshmcp air move grant --grant-store <file> <dest-key> <session-id> [--by <operator>]")
	}
	destKey, sessionID := normalizeKey(fs.Arg(0)), strings.TrimSpace(fs.Arg(1))
	if err := validateMoveArgs(destKey, sessionID); err != nil {
		return fmt.Errorf("air move grant: %w", err)
	}
	gs, err := air.OpenGrantStore(*storePath)
	if err != nil {
		return fmt.Errorf("air move grant: %w", err)
	}
	grantedBy := strings.TrimSpace(*by)
	if grantedBy == "" {
		grantedBy = "operator"
	}
	g, err := air.GrantMoveTarget(gs, destKey, sessionID, grantedBy, time.Now())
	if err != nil {
		return fmt.Errorf("air move grant: %w", err)
	}
	if *asJSON {
		return printHandoffJSON(g)
	}
	fmt.Println(okLine("authorized %s to receive session %s", shortKey(destKey), sessionID) + dim(" · single-use (consumed at commit)"))
	return nil
}

func cmdAirMoveGrantList(args []string) error {
	fs := flag.NewFlagSet("air move grant list", flag.ExitOnError)
	storePath := fs.String("grant-store", "", "destination grant store file (required)")
	asJSON := fs.Bool("json", false, "print the move grants as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *storePath == "" {
		return errors.New("usage: meshmcp air move grant list --grant-store <file> [--json]")
	}
	gs, err := air.OpenGrantStore(*storePath)
	if err != nil {
		return fmt.Errorf("air move grant list: %w", err)
	}
	var moves []air.Grant
	for _, g := range gs.Grants() {
		if g.Verb == air.MoveVerb {
			moves = append(moves, g)
		}
	}
	if *asJSON {
		return printHandoffJSON(moves)
	}
	if len(moves) == 0 {
		fmt.Println(dim("no live-session move grants"))
		return nil
	}
	rows := make([][]cell, 0, len(moves))
	for _, g := range moves {
		rows = append(rows, []cell{
			styled(g.Scope, bold),
			styled(shortKey(g.Identity), dim),
			styled("once", amber),
			styled(g.GrantedBy, dim),
		})
	}
	renderTable(os.Stdout, []string{"session", "destination", "kind", "granted by"}, rows)
	return nil
}

func cmdAirMoveGrantRevoke(args []string) error {
	fs := flag.NewFlagSet("air move grant revoke", flag.ExitOnError)
	storePath := fs.String("grant-store", "", "destination grant store file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 || *storePath == "" {
		return errors.New("usage: meshmcp air move grant revoke --grant-store <file> <dest-key> <session-id>")
	}
	destKey, sessionID := normalizeKey(fs.Arg(0)), strings.TrimSpace(fs.Arg(1))
	if err := validateMoveArgs(destKey, sessionID); err != nil {
		return fmt.Errorf("air move grant revoke: %w", err)
	}
	gs, err := air.OpenGrantStore(*storePath)
	if err != nil {
		return fmt.Errorf("air move grant revoke: %w", err)
	}
	removed, err := air.RevokeMoveGrant(gs, destKey, sessionID)
	if err != nil {
		return fmt.Errorf("air move grant revoke: %w", err)
	}
	if !removed {
		return fmt.Errorf("air move grant revoke: no move grant for %s / %s", shortKey(destKey), sessionID)
	}
	fmt.Println(okLine("revoked move authorization for session %s", sessionID) + dim(" · "+shortKey(destKey)))
	return nil
}

// normalizeKey strips an optional pubkey: prefix (as the handoff/grant CLIs do).
func normalizeKey(k string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(k), "pubkey:"))
}

// validateMoveArgs bounds the destination key and session id so a malformed or
// hostile value never lands in the grant store (the store also validates, but a
// clear CLI error is friendlier). The session id is the exact grant scope.
func validateMoveArgs(destKey, sessionID string) error {
	if destKey == "" || len(destKey) > 256 || handoffHasControl(destKey) {
		return errors.New("invalid destination key")
	}
	if sessionID == "" || len(sessionID) > 128 || handoffHasControl(sessionID) {
		return errors.New("invalid session id")
	}
	for _, c := range sessionID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return errors.New("session id must be hex (the session's logical id)")
		}
	}
	return nil
}
