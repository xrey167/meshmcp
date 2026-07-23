package policy

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// RotatingFileSink is an opt-in, size-based rotating file sink for the audit
// ledger (S51). It sits BELOW AuditLog as its io.Writer: when appending the
// next record would push the active file past maxBytes, the sink seals the
// active file (fsync + close), renames it to <path>.<UTC timestamp>, and
// reopens a fresh <path> — all before the record is written, so every record
// lives whole in exactly one file.
//
// Chain continuity is honest, not cosmetic: the hash chain (seq / prev_hash)
// lives in AuditLog, ABOVE this sink, so rotation never resets it. The first
// record of the new active file simply carries the next seq and a prev_hash
// pointing at the sealed archive's last record — the new file is a chain
// SEGMENT seeded from the previous head. Consequences:
//
//   - Verifying the FULL history means concatenating the archived segments in
//     name order followed by the active file, and running VerifyChain over the
//     concatenation ("cat audit.jsonl.* audit.jsonl | meshmcp audit verify -").
//   - A segment alone does not verify from genesis (its first record is
//     mid-chain); restart-resume verifies the active segment against the
//     newest archive's head via VerifyForRepairFrom (see seedAuditFromExisting).
//
// A rotation failure is surfaced as a write error, so a fail-closed audit
// denies calls rather than writing records it could not seal.
type RotatingFileSink struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	f        *os.File
	size     int64
	now      func() time.Time
}

// auditArchiveTimeFormat is Windows-safe (no colons) and lexicographically
// sortable, so archives order correctly by name.
const auditArchiveTimeFormat = "20060102T150405Z"

// OpenRotatingFileSink opens (creating if needed) path for append with
// size-based rotation at maxBytes (> 0). now may be nil (wall clock).
func OpenRotatingFileSink(path string, maxBytes int64, now func() time.Time) (*RotatingFileSink, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("audit rotation: max bytes must be > 0 (got %d)", maxBytes)
	}
	if now == nil {
		now = time.Now
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &RotatingFileSink{path: path, maxBytes: maxBytes, f: f, size: st.Size(), now: now}, nil
}

// Write appends b, rotating first when the active file is non-empty and the
// append would exceed the budget. A single record larger than maxBytes still
// lands (in a file of its own) — the ledger never drops a record to rotate.
func (s *RotatingFileSink) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.size > 0 && s.size+int64(len(b)) > s.maxBytes {
		if err := s.rotateLocked(); err != nil {
			return 0, fmt.Errorf("audit rotation: %w", err)
		}
	}
	n, err := s.f.Write(b)
	s.size += int64(n)
	return n, err
}

// Sync fsyncs the active file (AuditLog's WithSync durability contract).
func (s *RotatingFileSink) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Sync()
}

// Close closes the active file.
func (s *RotatingFileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// rotateLocked seals the active file and starts a fresh one. Seal = fsync then
// close, so the archived segment is complete and durable BEFORE the handoff;
// only then is it renamed and a new active file opened.
func (s *RotatingFileSink) rotateLocked() error {
	// Pick the archive name BEFORE sealing, so a probe failure returns with the
	// active file still open and healthy (the write proceeds past budget and a
	// later rotation retries) instead of leaving a closed handle behind.
	base := s.path + "." + s.now().UTC().Format(auditArchiveTimeFormat)
	archive := base
	// Same-second rotations get a zero-padded ordinal so names stay unique and
	// lexicographic order stays chronological. A non-NotExist Stat error is a
	// rotation error — never spin on it (the sink mutex is held, and a hang
	// here would block every audited call instead of failing closed). The
	// ordinal is capped at 999: auditArchivePattern matches exactly three
	// digits, and a wider name would be invisible to restart seeding.
	for i := 1; ; i++ {
		_, err := os.Stat(archive)
		if os.IsNotExist(err) {
			break
		}
		if err != nil {
			return fmt.Errorf("probe archive name %s: %w", archive, err)
		}
		if i > 999 {
			return fmt.Errorf("too many same-second rotations (last tried %s)", archive)
		}
		archive = fmt.Sprintf("%s-%03d", base, i)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("seal (fsync) active segment: %w", err)
	}
	if err := s.f.Close(); err != nil {
		return fmt.Errorf("seal (close) active segment: %w", err)
	}
	if err := os.Rename(s.path, archive); err != nil {
		// Best effort to keep writing to the (still sealed but unrenamed)
		// active file; if reopening fails too, subsequent writes error and a
		// fail-closed audit denies calls.
		if f, rerr := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); rerr == nil {
			s.f = f
		}
		return fmt.Errorf("archive %s: %w", archive, err)
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("reopen active segment: %w", err)
	}
	s.f = f
	s.size = 0
	return nil
}
