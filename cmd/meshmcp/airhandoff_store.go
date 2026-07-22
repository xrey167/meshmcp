package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/session"
)

const (
	// defaultHandoffInboxLimit bounds persistent metadata and private context on
	// a receiver whose operator did not choose an explicit limit. Handoff
	// records are deliberately not evicted automatically: silently deleting a
	// receipt would make continuation history incomplete.
	defaultHandoffInboxLimit = 256

	// The cross-process advisory lock is held only while reading or atomically
	// replacing tiny JSON records. The acquisition timeout keeps contention
	// bounded; the kernel releases the lock automatically if a process dies.
	defaultHandoffLockTimeout = 3 * time.Second
	handoffLockPoll           = 10 * time.Millisecond
	handoffLockName           = ".handoff-inbox.lock"

	// maxHandoffNote keeps terminal/UI text bounded and cheap to persist. Notes
	// are display-only and may never contain control bytes.
	maxHandoffNote = 500

	// The pure Air wire type is already bounded. This additional storage cap
	// leaves generous room for transport attribution and JSON formatting while
	// refusing a corrupted record large enough to exhaust memory on Get/List.
	maxHandoffRecordBytes = 2 << 20
)

var (
	errHandoffInboxFull      = errors.New("air handoff inbox is full")
	errHandoffNotFound       = errors.New("air handoff record not found")
	errHandoffIDCollision    = errors.New("air handoff id already belongs to different content")
	errHandoffSourceMismatch = errors.New("air handoff id already belongs to a different source identity")
)

// handoffInbox is the durable receive-side state for Air Continuity offers.
// The directory is private (0700), each record is private (0600), and every
// read-modify-write operation is serialized both in-process and across
// processes. The lock is advisory only within this implementation; record
// replacement remains atomic independently via same-directory temp+rename.
type handoffInbox struct {
	dir        string
	maxRecords int

	mu          sync.Mutex
	lockTimeout time.Duration
}

// newHandoffInbox opens (or creates) a private handoff directory. Omitting max
// uses a conservative default; zero also means default so an omitted YAML value
// cannot accidentally disable the bound. More than one limit or a negative
// limit is rejected instead of being interpreted ambiguously.
func newHandoffInbox(dir string, max ...int) (*handoffInbox, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("air handoff inbox directory is required")
	}
	if len(max) > 1 {
		return nil, errors.New("air handoff inbox accepts at most one record limit")
	}
	limit := defaultHandoffInboxLimit
	if len(max) == 1 {
		if max[0] < 0 {
			return nil, errors.New("air handoff inbox record limit must not be negative")
		}
		if max[0] > 0 {
			limit = max[0]
		}
	}
	abs, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return nil, fmt.Errorf("air handoff inbox path: %w", err)
	}
	if err := ensurePrivateHandoffDir(abs); err != nil {
		return nil, err
	}
	if err := secureExistingHandoffRecords(abs); err != nil {
		return nil, err
	}
	archiveDir := filepath.Join(abs, "archive")
	if info, err := os.Lstat(archiveDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("air handoff archive %q is not a real directory", archiveDir)
		}
		if err := ensurePrivateHandoffDir(archiveDir); err != nil {
			return nil, err
		}
		if err := secureExistingHandoffRecords(archiveDir); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect air handoff archive: %w", err)
	}
	return &handoffInbox{
		dir: abs, maxRecords: limit,
		lockTimeout: defaultHandoffLockTimeout,
	}, nil
}

func ensurePrivateHandoffDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create air handoff inbox: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect air handoff inbox: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("air handoff inbox %q is not a real directory", dir)
	}
	// MkdirAll honors the mode only for a newly-created component. Tighten an
	// existing directory too, so previous permissive modes do not persist.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure air handoff inbox: %w", err)
	}
	return nil
}

func secureExistingHandoffRecords(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read air handoff inbox permissions: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), ".json")
		if id, err := canonicalHandoffID(base); err != nil || id != base {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect air handoff record permissions: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("air handoff record %s is not a regular file", base)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("secure air handoff record %s: %w", base, err)
		}
	}
	return nil
}

// Put admits a target-bound, unexpired, integrity-checked offer and stamps the
// source identity from the authenticated mesh transport. It returns created=false
// only for a byte-identical replay by the same verified WireGuard key. A reused
// id with different content or a different source is a collision, never an
// update, even when the descriptive FQDN/address changed after roaming.
func (s *handoffInbox) Put(offer air.HandoffOffer, meta session.Meta, localTargetKey string, now time.Time) (air.HandoffRecord, bool, error) {
	if meta.PeerKey == "" {
		return air.HandoffRecord{}, false, errors.New("air handoff source identity is not transport-verified")
	}
	if err := offer.Validate(now, localTargetKey); err != nil {
		return air.HandoffRecord{}, false, fmt.Errorf("validate air handoff offer: %w", err)
	}
	id, err := canonicalHandoffID(offer.Capsule.ID)
	if err != nil {
		return air.HandoffRecord{}, false, err
	}
	rec := air.HandoffRecord{
		Offer:      offer,
		State:      air.HandoffOffered,
		SourcePeer: meta.PeerFQDN,
		SourceKey:  meta.PeerKey,
		SourceAddr: meta.PeerAddr,
		ReceivedAt: now,
		UpdatedAt:  now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.acquireDiskLock()
	if err != nil {
		return air.HandoffRecord{}, false, err
	}
	defer lock.release()

	existing, found, err := s.readUnlocked(id)
	if err != nil {
		return air.HandoffRecord{}, false, err
	}
	if found {
		// Source identity is checked first. An attacker who guesses an existing
		// id must not gain even an oracle for whether its content hash matched.
		if existing.SourceKey != meta.PeerKey {
			return air.HandoffRecord{}, false, errHandoffSourceMismatch
		}
		if existing.Offer.ContentHash != offer.ContentHash {
			return air.HandoffRecord{}, false, errHandoffIDCollision
		}
		return existing, false, nil
	}
	archived, found, err := s.readRecordFileUnlocked(id, filepath.Join(s.archiveDir(), id+".json"))
	if err != nil {
		return air.HandoffRecord{}, false, err
	}
	if found {
		if archived.SourceKey != meta.PeerKey {
			return air.HandoffRecord{}, false, errHandoffSourceMismatch
		}
		if archived.Offer.ContentHash != offer.ContentHash {
			return air.HandoffRecord{}, false, errHandoffIDCollision
		}
		return archived, false, nil
	}

	count, err := s.recordCountUnlocked()
	if err != nil {
		return air.HandoffRecord{}, false, err
	}
	if count >= s.maxRecords {
		return air.HandoffRecord{}, false, fmt.Errorf("%w (limit %d)", errHandoffInboxFull, s.maxRecords)
	}
	if err := s.writeUnlocked(id, rec); err != nil {
		return air.HandoffRecord{}, false, err
	}
	return rec, true, nil
}

// Get returns one persisted record. A syntactically invalid id is an error,
// while a valid but absent id returns found=false.
func (s *handoffInbox) Get(id string) (air.HandoffRecord, bool, error) {
	canonical, err := canonicalHandoffID(id)
	if err != nil {
		return air.HandoffRecord{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.acquireDiskLock()
	if err != nil {
		return air.HandoffRecord{}, false, err
	}
	defer lock.release()
	return s.readUnlocked(canonical)
}

// List returns every record newest-first. Equal receipt times are ordered by
// canonical id, making repeated reads stable across filesystems whose ReadDir
// enumeration order differs.
func (s *handoffInbox) List() ([]air.HandoffRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.acquireDiskLock()
	if err != nil {
		return nil, err
	}
	defer lock.release()

	ids, err := s.recordIDsUnlocked()
	if err != nil {
		return nil, err
	}
	out := make([]air.HandoffRecord, 0, len(ids))
	for _, id := range ids {
		rec, found, err := s.readUnlocked(id)
		if err != nil {
			return nil, err
		}
		if found {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ReceivedAt.Equal(out[j].ReceivedAt) {
			return out[i].ReceivedAt.After(out[j].ReceivedAt)
		}
		return strings.ToLower(out[i].Offer.Capsule.ID) < strings.ToLower(out[j].Offer.Capsule.ID)
	})
	if out == nil {
		out = []air.HandoffRecord{}
	}
	return out, nil
}

// Transition applies Air's pure state machine and persists the resulting
// state. Expiry is materialized before any requested transition: in particular,
// accepting an expired offer fails but leaves an explicit expired record on
// disk for the next process to observe.
func (s *handoffInbox) Transition(id string, next air.HandoffState, now time.Time, note string) (air.HandoffRecord, error) {
	if next == air.HandoffDispatching || next == air.HandoffContinued {
		return air.HandoffRecord{}, errors.New("air handoff delivery states require a destination receipt")
	}
	canonical, err := canonicalHandoffID(id)
	if err != nil {
		return air.HandoffRecord{}, err
	}
	if now.IsZero() {
		return air.HandoffRecord{}, errors.New("air handoff transition requires a clock")
	}
	if err := validateHandoffNote(note); err != nil {
		return air.HandoffRecord{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.acquireDiskLock()
	if err != nil {
		return air.HandoffRecord{}, err
	}
	defer lock.release()

	rec, found, err := s.readUnlocked(canonical)
	if err != nil {
		return air.HandoffRecord{}, err
	}
	if !found {
		return air.HandoffRecord{}, errHandoffNotFound
	}
	if now.Before(rec.UpdatedAt) {
		return rec, errors.New("air handoff transition timestamp predates its last update")
	}
	if rec.EffectiveState(now) == air.HandoffExpired && rec.State != air.HandoffExpired {
		if err := rec.Transition(air.HandoffExpired, now, "offer expired"); err != nil {
			return air.HandoffRecord{}, fmt.Errorf("expire air handoff: %w", err)
		}
		if err := s.writeUnlocked(canonical, rec); err != nil {
			return air.HandoffRecord{}, err
		}
		if next != air.HandoffExpired {
			return rec, errors.New("air handoff offer has expired")
		}
		return rec, nil
	}
	if rec.State == air.HandoffExpired && next != air.HandoffExpired {
		return rec, errors.New("air handoff offer has expired")
	}

	before := rec
	if err := rec.Transition(next, now, note); err != nil {
		return before, err
	}
	// Pure idempotent transitions preserve UpdatedAt and Note. Avoid even an
	// identical disk replacement so retries do not perturb file metadata.
	if recordsEqual(before, rec) {
		return rec, nil
	}
	if err := s.writeUnlocked(canonical, rec); err != nil {
		return air.HandoffRecord{}, err
	}
	return rec, nil
}

// ClaimDelivery atomically reserves one continuation attempt and persists the
// exact destination identity, address, and receiver-selected tool before any
// context leaves this device.
func (s *handoffInbox) ClaimDelivery(id, agentAddr, agentKey, tool string, now time.Time) (air.HandoffRecord, error) {
	canonical, err := canonicalHandoffID(id)
	if err != nil {
		return air.HandoffRecord{}, err
	}
	attempt := air.HandoffDeliveryAttempt{AgentAddr: agentAddr, AgentKey: agentKey, Tool: tool, ClaimedAt: now}
	if err := attempt.Validate(); err != nil {
		return air.HandoffRecord{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.acquireDiskLock()
	if err != nil {
		return air.HandoffRecord{}, err
	}
	defer lock.release()

	rec, found, err := s.readUnlocked(canonical)
	if err != nil {
		return air.HandoffRecord{}, err
	}
	if !found {
		return air.HandoffRecord{}, errHandoffNotFound
	}
	if now.Before(rec.UpdatedAt) {
		return rec, errors.New("air handoff delivery claim timestamp predates its last update")
	}
	if rec.EffectiveState(now) == air.HandoffExpired && rec.State != air.HandoffExpired {
		if err := rec.Transition(air.HandoffExpired, now, "offer expired"); err != nil {
			return air.HandoffRecord{}, fmt.Errorf("expire air handoff: %w", err)
		}
		if err := s.writeUnlocked(canonical, rec); err != nil {
			return air.HandoffRecord{}, err
		}
		return rec, errors.New("air handoff offer has expired")
	}
	if rec.State != air.HandoffAccepted {
		return rec, fmt.Errorf("air handoff must be accepted before delivery (state %s)", rec.State)
	}
	if err := rec.ClaimDelivery(attempt, now); err != nil {
		return rec, err
	}
	if err := s.writeUnlocked(canonical, rec); err != nil {
		return air.HandoffRecord{}, err
	}
	return rec, nil
}

// AcknowledgeDelivery records the destination application's positive steer
// ACK. It says the inbox strictly validated, audited, and enqueued the steer;
// it intentionally says nothing about the eventual tool result.
func (s *handoffInbox) AcknowledgeDelivery(id string, now time.Time) (air.HandoffRecord, error) {
	canonical, err := canonicalHandoffID(id)
	if err != nil {
		return air.HandoffRecord{}, err
	}
	if now.IsZero() {
		return air.HandoffRecord{}, errors.New("air handoff delivery acknowledgement requires a clock")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.acquireDiskLock()
	if err != nil {
		return air.HandoffRecord{}, err
	}
	defer lock.release()

	rec, found, err := s.readUnlocked(canonical)
	if err != nil {
		return air.HandoffRecord{}, err
	}
	if !found {
		return air.HandoffRecord{}, errHandoffNotFound
	}
	if now.Before(rec.UpdatedAt) {
		return rec, errors.New("air handoff delivery acknowledgement timestamp predates its last update")
	}
	if rec.State != air.HandoffDispatching || len(rec.DeliveryAttempts) == 0 {
		return rec, fmt.Errorf("air handoff has no claimed delivery to acknowledge (state %s)", rec.State)
	}
	if err := rec.AcknowledgeDelivery(now); err != nil {
		return rec, err
	}
	if err := s.writeUnlocked(canonical, rec); err != nil {
		return air.HandoffRecord{}, err
	}
	return rec, nil
}

// Rearm explicitly acknowledges an unknown dispatch outcome and makes the
// accepted capsule eligible for one new atomic claim. It is intentionally not
// an ordinary Transition so retries of `accept` cannot re-arm work.
func (s *handoffInbox) Rearm(id string, now time.Time, note string) (air.HandoffRecord, error) {
	canonical, err := canonicalHandoffID(id)
	if err != nil {
		return air.HandoffRecord{}, err
	}
	if now.IsZero() {
		return air.HandoffRecord{}, errors.New("air handoff rearm requires a clock")
	}
	if strings.TrimSpace(note) == "" {
		return air.HandoffRecord{}, errors.New("air handoff rearm requires an operator note")
	}
	if err := validateHandoffNote(note); err != nil {
		return air.HandoffRecord{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.acquireDiskLock()
	if err != nil {
		return air.HandoffRecord{}, err
	}
	defer lock.release()

	rec, found, err := s.readUnlocked(canonical)
	if err != nil {
		return air.HandoffRecord{}, err
	}
	if !found {
		return air.HandoffRecord{}, errHandoffNotFound
	}
	if now.Before(rec.UpdatedAt) {
		return rec, errors.New("air handoff rearm timestamp predates its last update")
	}
	before := rec
	if err := rec.Rearm(now, note); err != nil {
		return before, err
	}
	if err := s.writeUnlocked(canonical, rec); err != nil {
		return air.HandoffRecord{}, err
	}
	return rec, nil
}

// Archive moves old terminal records out of the active quota while preserving
// them as private JSON receipts. Archived IDs remain replay/collision tombstones
// so pruning cannot make the same work appear new again.
func (s *handoffInbox) Archive(now time.Time, olderThan time.Duration) ([]string, error) {
	if now.IsZero() || olderThan < 0 {
		return nil, errors.New("air handoff archive requires a clock and non-negative age")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := s.acquireDiskLock()
	if err != nil {
		return nil, err
	}
	defer lock.release()

	archiveDir := s.archiveDir()
	if err := ensurePrivateHandoffDir(archiveDir); err != nil {
		return nil, err
	}
	if err := secureExistingHandoffRecords(archiveDir); err != nil {
		return nil, err
	}
	ids, err := s.recordIDsUnlocked()
	if err != nil {
		return nil, err
	}
	cutoff := now.Add(-olderThan)
	archived := make([]string, 0)
	for _, id := range ids {
		rec, found, err := s.readUnlocked(id)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		expiredUnknownDispatch := rec.State == air.HandoffDispatching && !now.Before(rec.Offer.Capsule.ExpiresAt)
		if expiredUnknownDispatch {
			// Preserve the unknown state and destination attempt history, but let
			// an expired claim leave the bounded active quota after retention.
			if rec.Offer.Capsule.ExpiresAt.After(cutoff) {
				continue
			}
		} else if rec.EffectiveState(now) == air.HandoffExpired && rec.State != air.HandoffExpired {
			// Age an implicit expiry from ExpiresAt, not the much older last
			// accept/offer timestamp; newly expired work deserves the full
			// operator-selected retention window.
			if rec.Offer.Capsule.ExpiresAt.After(cutoff) {
				continue
			}
			if err := rec.Transition(air.HandoffExpired, now, "offer expired before archive"); err != nil {
				return nil, err
			}
			if err := s.writeUnlocked(id, rec); err != nil {
				return nil, err
			}
		} else if rec.UpdatedAt.After(cutoff) {
			continue
		}
		switch rec.State {
		case air.HandoffDeclined, air.HandoffContinued, air.HandoffExpired:
		case air.HandoffDispatching:
			if !expiredUnknownDispatch {
				continue
			}
		default:
			continue
		}
		dst := filepath.Join(archiveDir, id+".json")
		if _, err := os.Lstat(dst); err == nil {
			return nil, fmt.Errorf("air handoff archive already contains %s", id)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		if err := os.Rename(s.recordPath(id), dst); err != nil {
			return nil, fmt.Errorf("archive air handoff %s: %w", id, err)
		}
		archived = append(archived, id)
	}
	if len(archived) > 0 {
		if err := syncHandoffDirectory(archiveDir); err != nil {
			return nil, err
		}
		if err := syncHandoffDirectory(s.dir); err != nil {
			return nil, err
		}
	}
	return archived, nil
}

func validateHandoffNote(note string) error {
	if len(note) > maxHandoffNote {
		return fmt.Errorf("air handoff note is %d bytes, over the %d-byte limit", len(note), maxHandoffNote)
	}
	for _, r := range note {
		if r < 0x20 || r == 0x7f {
			return errors.New("air handoff note must not contain control characters")
		}
	}
	return nil
}

func recordsEqual(a, b air.HandoffRecord) bool {
	// The struct contains slices/RawMessages through Offer, so it is not
	// comparable. JSON is its durable canonical representation and Go's encoder
	// orders map keys, making this an exact check for an idempotent transition.
	ab, aerr := json.Marshal(a)
	bb, berr := json.Marshal(b)
	return aerr == nil && berr == nil && string(ab) == string(bb)
}

func canonicalHandoffID(id string) (string, error) {
	if len(id) != 32 {
		return "", fmt.Errorf("invalid air handoff id %q: want 32 lowercase hex characters", safeIDForError(id))
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", fmt.Errorf("invalid air handoff id %q: want 32 lowercase hex characters", safeIDForError(id))
		}
	}
	return id, nil
}

// safeIDForError avoids reflecting control bytes or an unbounded attacker
// string into logs/UI through a returned validation error.
func safeIDForError(id string) string {
	const max = 40
	var b strings.Builder
	for _, r := range id {
		if b.Len() >= max {
			b.WriteString("…")
			break
		}
		if r < 0x20 || r == 0x7f {
			b.WriteByte('?')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (s *handoffInbox) recordPath(id string) string {
	// id has already passed canonicalHandoffID, so this join can add exactly one
	// child under s.dir and never interpret a separator or volume prefix.
	return filepath.Join(s.dir, id+".json")
}

func (s *handoffInbox) archiveDir() string { return filepath.Join(s.dir, "archive") }

func (s *handoffInbox) readUnlocked(id string) (air.HandoffRecord, bool, error) {
	return s.readRecordFileUnlocked(id, s.recordPath(id))
}

func (s *handoffInbox) readRecordFileUnlocked(id, path string) (air.HandoffRecord, bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return air.HandoffRecord{}, false, nil
	}
	if err != nil {
		return air.HandoffRecord{}, false, fmt.Errorf("inspect air handoff %s: %w", id, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return air.HandoffRecord{}, false, fmt.Errorf("air handoff record %s is not a regular file", id)
	}
	if info.Size() > maxHandoffRecordBytes {
		return air.HandoffRecord{}, false, fmt.Errorf("air handoff record %s exceeds the storage limit", id)
	}
	f, err := os.Open(path)
	if err != nil {
		return air.HandoffRecord{}, false, fmt.Errorf("open air handoff %s: %w", id, err)
	}
	opened, statErr := f.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		f.Close()
		return air.HandoffRecord{}, false, fmt.Errorf("air handoff record %s changed while opening", id)
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxHandoffRecordBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return air.HandoffRecord{}, false, fmt.Errorf("read air handoff %s: %w", id, readErr)
	}
	if closeErr != nil {
		return air.HandoffRecord{}, false, fmt.Errorf("close air handoff %s: %w", id, closeErr)
	}
	if len(data) > maxHandoffRecordBytes {
		return air.HandoffRecord{}, false, fmt.Errorf("air handoff record %s exceeds the storage limit", id)
	}
	var rec air.HandoffRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return air.HandoffRecord{}, false, fmt.Errorf("decode air handoff %s: %w", id, err)
	}
	if err := validateStoredHandoffRecord(id, rec); err != nil {
		return air.HandoffRecord{}, false, err
	}
	return rec, true, nil
}

func validateStoredHandoffRecord(id string, rec air.HandoffRecord) error {
	embedded, err := canonicalHandoffID(rec.Offer.Capsule.ID)
	if err != nil || embedded != id {
		return fmt.Errorf("air handoff record %s has a mismatched embedded id", id)
	}
	sealed, err := air.SealHandoff(rec.Offer.Capsule)
	if err != nil {
		return fmt.Errorf("air handoff record %s has an invalid capsule: %w", id, err)
	}
	storedCapsule, err := json.Marshal(rec.Offer.Capsule)
	if err != nil {
		return fmt.Errorf("air handoff record %s has an invalid capsule: %w", id, err)
	}
	canonicalCapsule, err := json.Marshal(sealed.Capsule)
	if err != nil {
		return fmt.Errorf("air handoff record %s has an invalid canonical capsule: %w", id, err)
	}
	if string(storedCapsule) != string(canonicalCapsule) {
		return fmt.Errorf("air handoff record %s capsule is not canonical", id)
	}
	if sealed.ContentHash != rec.Offer.ContentHash {
		return fmt.Errorf("air handoff record %s content hash mismatch", id)
	}
	if rec.SourceKey == "" {
		return fmt.Errorf("air handoff record %s has no verified source key", id)
	}
	switch rec.State {
	case air.HandoffOffered, air.HandoffAccepted, air.HandoffDispatching, air.HandoffDeclined, air.HandoffContinued, air.HandoffExpired:
	default:
		return fmt.Errorf("air handoff record %s has unknown state %q", id, rec.State)
	}
	if rec.ReceivedAt.IsZero() {
		return fmt.Errorf("air handoff record %s has no receipt timestamp", id)
	}
	if rec.UpdatedAt.IsZero() {
		return fmt.Errorf("air handoff record %s has no update timestamp", id)
	}
	if rec.UpdatedAt.Before(rec.ReceivedAt) {
		return fmt.Errorf("air handoff record %s update timestamp predates receipt", id)
	}
	if !rec.ReceivedAt.Before(rec.Offer.Capsule.ExpiresAt) {
		return fmt.Errorf("air handoff record %s receipt timestamp is outside the offer lifetime", id)
	}
	if err := validateHandoffNote(rec.Note); err != nil {
		return fmt.Errorf("air handoff record %s: %w", id, err)
	}
	if len(rec.DeliveryAttempts) > air.HandoffMaxDeliveryAttempts {
		return fmt.Errorf("air handoff record %s has too many delivery attempts", id)
	}
	for i, attempt := range rec.DeliveryAttempts {
		if err := attempt.Validate(); err != nil {
			return fmt.Errorf("air handoff record %s delivery attempt %d: %w", id, i, err)
		}
		if attempt.ClaimedAt.Before(rec.ReceivedAt) || attempt.ClaimedAt.After(rec.UpdatedAt) || !attempt.ClaimedAt.Before(rec.Offer.Capsule.ExpiresAt) {
			return fmt.Errorf("air handoff record %s delivery attempt %d is outside its receipt history", id, i)
		}
		if i > 0 && attempt.ClaimedAt.Before(rec.DeliveryAttempts[i-1].ClaimedAt) {
			return fmt.Errorf("air handoff record %s delivery attempts are out of order", id)
		}
		if attempt.AcknowledgedAt != nil && (i != len(rec.DeliveryAttempts)-1 || rec.State != air.HandoffContinued || !attempt.AcknowledgedAt.Equal(rec.UpdatedAt) || !attempt.AcknowledgedAt.Before(rec.Offer.Capsule.ExpiresAt)) {
			return fmt.Errorf("air handoff record %s has an inconsistent delivery acknowledgement", id)
		}
	}
	if (rec.State == air.HandoffOffered || rec.State == air.HandoffDeclined) && len(rec.DeliveryAttempts) != 0 {
		return fmt.Errorf("air handoff record %s has delivery attempts before consent", id)
	}
	if (rec.State == air.HandoffAccepted || rec.State == air.HandoffExpired) && len(rec.DeliveryAttempts) > 0 && rec.DeliveryAttempts[len(rec.DeliveryAttempts)-1].AcknowledgedAt != nil {
		return fmt.Errorf("air handoff record %s has a terminal delivery acknowledgement in state %s", id, rec.State)
	}
	if rec.State == air.HandoffDispatching && (len(rec.DeliveryAttempts) == 0 || rec.DeliveryAttempts[len(rec.DeliveryAttempts)-1].AcknowledgedAt != nil) {
		return fmt.Errorf("air handoff record %s has no pending delivery receipt", id)
	}
	if rec.State == air.HandoffContinued && (len(rec.DeliveryAttempts) == 0 || rec.DeliveryAttempts[len(rec.DeliveryAttempts)-1].AcknowledgedAt == nil) {
		return fmt.Errorf("air handoff record %s has no acknowledged delivery receipt", id)
	}
	return nil
}

func (s *handoffInbox) writeUnlocked(id string, rec air.HandoffRecord) error {
	if err := validateStoredHandoffRecord(id, rec); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode air handoff %s: %w", id, err)
	}
	if len(data) > maxHandoffRecordBytes {
		return fmt.Errorf("air handoff record %s exceeds the storage limit", id)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(s.dir, ".handoff-"+id+"-*.tmp")
	if err != nil {
		return fmt.Errorf("create air handoff temp file: %w", err)
	}
	tmpName := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure air handoff temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write air handoff temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync air handoff temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close air handoff temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.recordPath(id)); err != nil {
		return fmt.Errorf("install air handoff %s: %w", id, err)
	}
	keep = true
	if err := syncHandoffDirectory(s.dir); err != nil {
		return err
	}
	return nil
}

func syncHandoffDirectory(dir string) error {
	// Windows has durable file flushes and replace-by-rename, but does not
	// expose fsync for an open directory. The record itself was synced before
	// rename above; sync the directory entry on platforms that support it.
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open air handoff directory for sync: %w", err)
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return fmt.Errorf("sync air handoff directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close air handoff directory: %w", closeErr)
	}
	return nil
}

func (s *handoffInbox) recordCountUnlocked() (int, error) {
	ids, err := s.recordIDsUnlocked()
	return len(ids), err
}

func (s *handoffInbox) recordIDsUnlocked() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("read air handoff inbox: %w", err)
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), ".json")
		id, err := canonicalHandoffID(base)
		if err != nil || id != base {
			// Only filenames produced from canonical validated IDs belong to this
			// store. Unrelated files do not consume quota or enter List.
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// handoffDiskLock holds a real OS advisory lock on an open descriptor. Kernel
// ownership prevents stale-file check/remove races and is released on process
// death, while the persistent file gives every process a stable lock target.
type handoffDiskLock struct {
	file *os.File
}

func (s *handoffInbox) acquireDiskLock() (*handoffDiskLock, error) {
	path := filepath.Join(s.dir, handoffLockName)
	return acquireHandoffPathLock(path, s.lockTimeout)
}

func acquireHandoffPathLock(path string, timeout time.Duration) (*handoffDiskLock, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("air handoff lock path is not a regular file")
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect air handoff lock: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open air handoff inbox lock: %w", err)
	}
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("opened air handoff lock is not a regular file")
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(current, opened) {
		f.Close()
		return nil, errors.New("air handoff lock path changed while opening")
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, fmt.Errorf("secure air handoff inbox lock: %w", err)
	}
	if timeout <= 0 {
		timeout = defaultHandoffLockTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		locked, err := tryHandoffFileLock(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("acquire air handoff inbox lock: %w", err)
		}
		if locked {
			return &handoffDiskLock{file: f}, nil
		}
		if !time.Now().Before(deadline) {
			f.Close()
			return nil, fmt.Errorf("timed out acquiring air handoff lock after %s", timeout)
		}
		time.Sleep(handoffLockPoll)
	}
}

func (l *handoffDiskLock) release() {
	if l == nil || l.file == nil {
		return
	}
	_ = unlockHandoffFile(l.file)
	_ = l.file.Close()
	l.file = nil
}
