package air

import "time"

// Live-session move (v2) reuses the grant store as its single-use destination
// authorization, with no new store. A move grant is the "explicitly-granted
// single-use target" arm of the session identity invariant: it says exactly
// "this destination gateway may receive this one session, once". It is written by
// the operator, CHECKED (non-consuming) when the destination pre-warms, and
// CONSUMED exactly once when the destination commits the ownership swap — so a
// second move of the same session to the same destination is denied by default.
//
// The binding is a thin, fixed convention over Grant's (identity, verb, scope):
//   - identity = the DESTINATION gateway's WireGuard public key (the target),
//   - verb     = MoveVerb ("move"),
//   - scope    = the exact session id being moved.
//
// It confers nothing else: a move grant for one session never authorizes another
// (scope is the exact id), and it never widens any endpoint/steer ACL — exactly
// the grant store's existing boundary.

// MoveVerb namespaces live-session-move grants in the shared grant store, keeping
// them disjoint from every other verb's grants.
const MoveVerb = "move"

// GrantMoveTarget writes a single-use grant authorizing destKey to receive
// sessionID exactly once. grantedBy is the operator identity approving it. It is
// always Once=true: a live-session move is a one-shot ownership transfer, never a
// standing capability.
func GrantMoveTarget(gs *GrantStore, destKey, sessionID, grantedBy string, now time.Time) (Grant, error) {
	return gs.Add(destKey, MoveVerb, sessionID, true, grantedBy, now)
}

// CheckMoveGrant reports (without consuming) whether destKey is authorized to
// receive sessionID — the fast, non-mutating check a destination makes when it
// pre-warms, so an unauthorized move is refused before any backend is spawned.
func CheckMoveGrant(gs *GrantStore, destKey, sessionID string) bool {
	return gs.Check(destKey, MoveVerb, sessionID)
}

// ConsumeMoveGrant consumes the single-use move grant for (destKey, sessionID) at
// commit time and reports whether one was present. It is the deny-by-default
// authorization gate wired into session commit: consumed=false means no matching
// grant (unauthorized, or already spent), and the commit must refuse. The second
// call for the same session finds the grant gone.
func ConsumeMoveGrant(gs *GrantStore, destKey, sessionID string, now time.Time) (bool, error) {
	_, consumed, err := gs.ConsumeOnceMatching(destKey, MoveVerb, func(scope string) bool {
		return scope == sessionID
	}, now)
	return consumed, err
}

// RevokeMoveGrant removes an unspent move grant (operator changed their mind
// before the destination committed). removed is false when none existed.
func RevokeMoveGrant(gs *GrantStore, destKey, sessionID string) (bool, error) {
	return gs.Remove(destKey, MoveVerb, sessionID)
}
