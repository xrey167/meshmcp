// Package checkpoint is the shared checkpoint format + Store — spine primitive
// S5 of the Air Knowledge System. It is the ONE resumable-state primitive used
// by BOTH session-resume and agent-graph runs: a single Checkpoint type and a
// single Store, so neither pillar grows its own half-correct persistence.
//
// The type is deliberately GENERIC. It does not know what a session or an
// agent-graph state *is* — it holds run identity, a monotonic Step cursor, an
// opaque serialized State payload, the CreatorKey identity binding, timestamps,
// and an optional pending pre-execution Intent. A caller (a future
// air-agent-graph runner, a session snapshot) serializes its own typed state
// into State and reads it back on resume. Keeping the payload opaque is what
// lets one primitive serve every pillar instead of coupling to one.
//
// Two properties are security-critical and are the reason this is its own
// audited primitive rather than a field on PersistedSession:
//
//   - Identity binding (the CreatorKey pattern, mirrored from
//     session.PersistedSession.CreatorKey). A checkpoint is bound to the
//     WireGuard identity that created it, and ONLY that identity may resume it.
//     Store.Load refuses any caller whose key differs from the checkpoint's
//     CreatorKey — deny-by-default — so a run id alone can never be used to take
//     over another identity's buffered state. This is enforced in the Store, not
//     here; see store.go.
//
//   - The pre-execution Intent (idempotency). Before a side-effecting node runs,
//     the caller records an Intent describing the op it is about to perform. If
//     the process crashes between the effect and the checkpoint of its result, a
//     reload surfaces the still-pending Intent, and the caller consults it to
//     avoid blindly re-firing an op that may already have happened. The Intent is
//     cleared only after the effect is confirmed. This closes the
//     double-fire-on-resume window.
//
// It is a library: it touches the filesystem (persistence is its job) but does
// NO mesh/network. It imports policy (for AuditSink/AuditRecord) and air/know
// (for the graph.checkpoint audit verb) only.
package checkpoint

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Checkpoint is one persisted, resumable point of a run. It is generic over what
// the run *is*: State is an opaque payload the caller serializes and interprets.
//
// The zero value is not a valid checkpoint — RunID and CreatorKey are required
// (see validate). A Checkpoint is treated as an immutable value: the Store never
// mutates a caller's Checkpoint in place, and read-modify-write ops
// (BeginIntent/CommitIntent) construct a new value rather than editing the old.
type Checkpoint struct {
	// RunID identifies the run this checkpoint belongs to. It is the storage key
	// (one file per RunID) so it must be a single safe path element — no
	// separators, no "." or ".." — which validate enforces.
	RunID string `json:"run_id"`
	// CreatorKey is the WireGuard public key of the identity that created the run.
	// It is the identity binding: only a caller presenting this exact key may
	// resume the checkpoint (Store.Load) or advance it (BeginIntent/CommitIntent).
	CreatorKey string `json:"creator_key"`
	// Step is a monotonic cursor into the run (a node index, a sequence number).
	// The caller owns its meaning; the Store only persists it.
	Step int `json:"step"`
	// State is the opaque serialized run state. The Store round-trips these bytes
	// exactly and never inspects them. Kept as json.RawMessage so a caller's own
	// JSON state nests without a second layer of string-escaping.
	State json.RawMessage `json:"state,omitempty"`
	// Intent, when non-nil, is a side-effecting op that was recorded as
	// about-to-run but has NOT been confirmed complete. A pending Intent observed
	// on resume means "this op may have already fired — do not blindly re-run it."
	Intent *Intent `json:"intent,omitempty"`
	// CreatedAt / UpdatedAt are Unix seconds. CreatedAt is stamped on first Save
	// and preserved across later saves; UpdatedAt moves on every write.
	CreatedAt int64 `json:"created_at"`
	UpdatedAt int64 `json:"updated_at"`
}

// Intent is the pre-execution record of a side-effecting operation, written
// BEFORE the effect runs and cleared AFTER it is confirmed. It describes the op
// precisely enough that, on resume, the caller can decide whether the effect
// already happened and must not be repeated (idempotency), rather than
// double-firing an email, a payment, or an external write.
type Intent struct {
	// NodeID identifies the side-effecting node/step about to execute.
	NodeID string `json:"node_id"`
	// IdempotencyKey is the caller's stable key for this exact effect. On resume
	// the caller replays the op under the same key so a downstream that honors
	// idempotency keys collapses the retry, or the caller checks whether an effect
	// tagged with this key already landed.
	IdempotencyKey string `json:"idempotency_key"`
	// ArgsHash is a hash of the op's arguments, so a resumed caller can confirm the
	// pending intent describes the same call it is about to make (and not a stale
	// or mismatched one) before treating it as already-fired.
	ArgsHash string `json:"args_hash"`
	// RecordedAt is when the intent was written (Unix seconds).
	RecordedAt int64 `json:"recorded_at"`
}

// Sentinel errors. Callers and tests match with errors.Is.
var (
	// ErrIdentityMismatch is returned when a caller's key is not exactly the
	// checkpoint's CreatorKey (including a blank caller key). This is the core
	// security property: resuming or advancing another identity's run is refused.
	ErrIdentityMismatch = errors.New("checkpoint: caller key does not match checkpoint creator")
	// ErrNotFound is returned by ops that require an existing checkpoint
	// (BeginIntent/CommitIntent) when no checkpoint exists for the run id.
	ErrNotFound = errors.New("checkpoint: no checkpoint for run id")
	// ErrInvalid is returned when a Checkpoint or its fields fail validation
	// (empty/unsafe RunID, blank CreatorKey).
	ErrInvalid = errors.New("checkpoint: invalid checkpoint")
)

// validate rejects a checkpoint that cannot be safely stored or securely bound:
// a RunID that is empty or not a single safe path element (so it can never
// escape the store directory via "..", a separator, etc.), and a blank
// CreatorKey (an unbound checkpoint would be resumable by anyone, defeating the
// identity binding).
func validate(cp Checkpoint) error {
	if err := validateRunID(cp.RunID); err != nil {
		return err
	}
	if strings.TrimSpace(cp.CreatorKey) == "" {
		return fmt.Errorf("%w: blank CreatorKey", ErrInvalid)
	}
	return nil
}

// validateRunID enforces that runID is usable as a single filename with no path
// traversal: non-empty, equal to its own base element, and not "." / "..". This
// is a security check — RunID is attacker-influenceable and becomes a filesystem
// path, so a "../../etc/foo" run id must never write outside the store dir.
func validateRunID(runID string) error {
	if runID == "" {
		return fmt.Errorf("%w: empty RunID", ErrInvalid)
	}
	if strings.ContainsRune(runID, '/') || strings.ContainsRune(runID, '\\') ||
		strings.ContainsRune(runID, filepath.Separator) {
		return fmt.Errorf("%w: RunID contains a path separator: %q", ErrInvalid, runID)
	}
	if runID == "." || runID == ".." || filepath.Base(runID) != runID {
		return fmt.Errorf("%w: RunID is not a safe path element: %q", ErrInvalid, runID)
	}
	return nil
}
