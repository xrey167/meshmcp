package checkpoint

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xrey167/meshmcp/air/know"
	"github.com/xrey167/meshmcp/policy"
)

// filePerm is the mode for checkpoint files. 0600 (owner-only) because a
// checkpoint holds identity-bound, resumable run state — it must not be
// world-readable the way ordinary session files (0644) are.
const filePerm os.FileMode = 0o600

// Store persists checkpoints atomically, one file per RunID, and enforces the
// two security guarantees of S5: identity binding on every read/advance, and the
// pre-execution intent that closes the double-fire-on-resume window.
//
// Concurrency is serialized PER RunID by a keyed lock: read-modify-write ops
// (Save, BeginIntent, CommitIntent) on the same run never interleave, while
// distinct runs proceed independently. Load takes no lock — the atomic rename in
// writeFileAtomic already gives every reader a complete snapshot — so a resume
// can never observe a torn write regardless of concurrent saves.
//
// A Store must be created with New and must not be copied (it holds locks).
type Store struct {
	dir  string
	sink policy.AuditSink
	nowf func() int64

	mu    sync.Mutex             // guards locks
	locks map[string]*sync.Mutex // per-RunID serialization
}

// New builds a Store rooted at dir, creating it if needed. audit may be nil
// (auditing becomes a no-op), but a real policy.AuditSink — typically a
// policy.AuditLog — is expected in production so checkpoint saves and resumes
// land on the shared, verifiable ledger via the graph.checkpoint verb.
func New(dir string, audit policy.AuditSink) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("checkpoint: create store dir: %w", err)
	}
	return &Store{
		dir:   dir,
		sink:  audit,
		nowf:  func() int64 { return time.Now().Unix() },
		locks: map[string]*sync.Mutex{},
	}, nil
}

// WithClock overrides the timestamp source (Unix seconds), for deterministic
// tests. It returns the Store for chaining and must be called before use.
func (s *Store) WithClock(now func() int64) *Store {
	if now != nil {
		s.nowf = now
	}
	return s
}

func (s *Store) path(runID string) string { return filepath.Join(s.dir, runID+".json") }

// runLock returns the per-RunID mutex, creating it on first use. The map grows
// with the number of distinct run ids seen; for the checkpoint primitive that is
// bounded by active runs and is not reclaimed here.
func (s *Store) runLock(runID string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	lk := s.locks[runID]
	if lk == nil {
		lk = &sync.Mutex{}
		s.locks[runID] = lk
	}
	return lk
}

// readFile loads the checkpoint at runID. ok is false (with a nil error) when no
// checkpoint exists yet. It does not enforce identity — callers layer that on.
func (s *Store) readFile(runID string) (Checkpoint, bool, error) {
	b, err := os.ReadFile(s.path(runID))
	if os.IsNotExist(err) {
		return Checkpoint{}, false, nil
	}
	if err != nil {
		return Checkpoint{}, false, fmt.Errorf("checkpoint: read: %w", err)
	}
	var cp Checkpoint
	if err := json.Unmarshal(b, &cp); err != nil {
		return Checkpoint{}, false, fmt.Errorf("checkpoint: parse: %w", err)
	}
	return cp, true, nil
}

// writeFile persists cp atomically at 0600. Caller holds cp.RunID's lock.
func (s *Store) writeFile(cp Checkpoint) error {
	b, err := json.Marshal(cp)
	if err != nil {
		return fmt.Errorf("checkpoint: marshal: %w", err)
	}
	if err := writeFileAtomic(s.path(cp.RunID), b, filePerm); err != nil {
		return fmt.Errorf("checkpoint: write: %w", err)
	}
	return nil
}

// Save persists cp, all-or-nothing. It stamps timestamps (CreatedAt on first
// save, preserved thereafter; UpdatedAt on every save) and audits a
// graph.checkpoint record on success.
//
// Save also enforces the identity binding on OVERWRITE: if a checkpoint already
// exists for cp.RunID under a DIFFERENT CreatorKey, the save is refused with
// ErrIdentityMismatch. Without this, an attacker who guessed a run id could
// clobber another identity's run state by writing a fresh checkpoint over it —
// so the binding is checked on the write path, not only on resume.
func (s *Store) Save(cp Checkpoint) error {
	if err := validate(cp); err != nil {
		return err
	}
	lk := s.runLock(cp.RunID)
	lk.Lock()
	defer lk.Unlock()

	prev, existed, err := s.readFile(cp.RunID)
	if err != nil {
		return err
	}
	if existed && prev.CreatorKey != cp.CreatorKey {
		s.auditDeny(cp.RunID, cp.CreatorKey, "save over checkpoint owned by another identity")
		return ErrIdentityMismatch
	}

	now := s.nowf()
	out := cp // copy; never mutate the caller's value
	out.UpdatedAt = now
	switch {
	case out.CreatedAt != 0:
		// caller supplied an explicit creation time — respect it
	case existed:
		out.CreatedAt = prev.CreatedAt // preserve original creation time
	default:
		out.CreatedAt = now
	}

	if err := s.writeFile(out); err != nil {
		return err
	}
	return s.auditAllow(out.RunID, out.CreatorKey, "save")
}

// Load reads the checkpoint for runID and enforces the identity binding: the
// caller MUST present callerKey exactly equal to the checkpoint's CreatorKey.
// A blank callerKey, or any key other than the creator's, is refused with
// ErrIdentityMismatch and audited as a deny — resuming another identity's run
// is impossible, by construction, deny-by-default.
//
// ok is false (nil error) when no checkpoint exists for runID. On an allowed
// load a graph.checkpoint record is audited (the resume event).
func (s *Store) Load(runID, callerKey string) (Checkpoint, bool, error) {
	if err := validateRunID(runID); err != nil {
		return Checkpoint{}, false, err
	}
	cp, ok, err := s.readFile(runID)
	if err != nil {
		return Checkpoint{}, false, err
	}
	if !ok {
		return Checkpoint{}, false, nil
	}
	if callerKey == "" || callerKey != cp.CreatorKey {
		s.auditDeny(runID, callerKey, "resume of checkpoint owned by another identity")
		return Checkpoint{}, false, ErrIdentityMismatch
	}
	if err := s.auditAllow(runID, cp.CreatorKey, "resume"); err != nil {
		return Checkpoint{}, false, err
	}
	return cp, true, nil
}

// BeginIntent records intent as the pending pre-execution op on the run's
// checkpoint, written and fsynced BEFORE the caller performs the side effect. It
// enforces the identity binding (callerKey must be the creator) and requires an
// existing checkpoint (ErrNotFound otherwise). intent.RecordedAt is stamped if
// unset.
//
// The guarantee: once BeginIntent returns, the intent is durable. If the process
// then crashes before the effect's result is checkpointed, a later Load surfaces
// this pending Intent so the caller does not blindly re-fire the op.
func (s *Store) BeginIntent(runID, callerKey string, intent Intent) error {
	if err := validateRunID(runID); err != nil {
		return err
	}
	lk := s.runLock(runID)
	lk.Lock()
	defer lk.Unlock()

	cp, ok, err := s.boundLoad(runID, callerKey)
	if err != nil || !ok {
		return err
	}
	now := s.nowf()
	pending := intent
	if pending.RecordedAt == 0 {
		pending.RecordedAt = now
	}
	out := cp // copy; construct a new value rather than mutating
	out.Intent = &pending
	out.UpdatedAt = now
	if err := s.writeFile(out); err != nil {
		return err
	}
	return s.auditAllow(runID, cp.CreatorKey, "begin-intent")
}

// CommitIntent clears the pending Intent after the side effect is confirmed
// complete, atomically. It enforces the identity binding and requires an
// existing checkpoint. Clearing an already-clear intent is a no-op success, so a
// double commit (e.g. a retried confirmation) is safe.
func (s *Store) CommitIntent(runID, callerKey string) error {
	if err := validateRunID(runID); err != nil {
		return err
	}
	lk := s.runLock(runID)
	lk.Lock()
	defer lk.Unlock()

	cp, ok, err := s.boundLoad(runID, callerKey)
	if err != nil || !ok {
		return err
	}
	if cp.Intent == nil {
		return nil // nothing pending; idempotent
	}
	out := cp // copy
	out.Intent = nil
	out.UpdatedAt = s.nowf()
	if err := s.writeFile(out); err != nil {
		return err
	}
	return s.auditAllow(runID, cp.CreatorKey, "commit-intent")
}

// boundLoad reads the checkpoint and enforces the identity binding for the
// read-modify-write ops. It returns ErrNotFound when the checkpoint is missing
// (those ops require it to already exist) and ErrIdentityMismatch when callerKey
// is blank or not the creator's, auditing the deny. Caller holds the run lock.
func (s *Store) boundLoad(runID, callerKey string) (Checkpoint, bool, error) {
	cp, ok, err := s.readFile(runID)
	if err != nil {
		return Checkpoint{}, false, err
	}
	if !ok {
		return Checkpoint{}, false, ErrNotFound
	}
	if callerKey == "" || callerKey != cp.CreatorKey {
		s.auditDeny(runID, callerKey, "intent op on checkpoint owned by another identity")
		return Checkpoint{}, false, ErrIdentityMismatch
	}
	return cp, true, nil
}

// auditAllow appends an allow graph.checkpoint record; a nil sink is a no-op.
func (s *Store) auditAllow(runID, key, reason string) error {
	return s.appendAudit(runID, key, "allow", reason)
}

// auditDeny appends a deny graph.checkpoint record (a refused resume/overwrite —
// a security event worth recording). Its error is intentionally dropped: a deny
// decision must stand even if the audit write itself fails, and the caller
// already receives ErrIdentityMismatch.
func (s *Store) auditDeny(runID, key, reason string) {
	_ = s.appendAudit(runID, key, "deny", reason)
}

func (s *Store) appendAudit(runID, key, decision, reason string) error {
	if s.sink == nil {
		return nil
	}
	return s.sink.Append(know.Checkpoint(know.Event{
		Peer:     key,
		Corpus:   runID,
		Decision: decision,
		Reason:   reason,
	}))
}
