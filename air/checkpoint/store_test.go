package checkpoint

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

const (
	keyAlice = "wg:alice-pubkey"
	keyBob   = "wg:bob-pubkey"
)

// capSink is a policy.AuditSink that captures every record for assertions.
type capSink struct {
	mu   sync.Mutex
	recs []policy.AuditRecord
}

func (c *capSink) Append(rec policy.AuditRecord) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, rec)
	return nil
}

func (c *capSink) records() []policy.AuditRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]policy.AuditRecord(nil), c.recs...)
}

func newStore(t *testing.T, sink policy.AuditSink) *Store {
	t.Helper()
	s, err := New(t.TempDir(), sink)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s.WithClock(func() int64 { return 1000 })
}

// --- Atomic persistence & round-trip ---

func TestSaveLoad_RoundTripsStateExactly(t *testing.T) {
	s := newStore(t, nil)
	state := json.RawMessage(`{"nodes":["a","b"],"cursor":42,"nested":{"x":1.5}}`)
	cp := Checkpoint{RunID: "run-1", CreatorKey: keyAlice, Step: 7, State: state}
	if err := s.Save(cp); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := s.Load("run-1", keyAlice)
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	if got.Step != 7 {
		t.Errorf("Step = %d, want 7", got.Step)
	}
	if string(got.State) != string(state) {
		t.Errorf("State = %s, want %s", got.State, state)
	}
	if got.CreatedAt != 1000 || got.UpdatedAt != 1000 {
		t.Errorf("timestamps = (%d,%d), want (1000,1000)", got.CreatedAt, got.UpdatedAt)
	}
}

func TestSave_IsAllOrNothing_NoPartialAtCanonicalPath(t *testing.T) {
	// A reader of the canonical path must never see a torn write. Because Save
	// writes to <run>.json.tmp and renames, the canonical file, if present, always
	// parses as a complete checkpoint. Prove that no .tmp survives a successful
	// save and the canonical file is whole.
	dir := t.TempDir()
	s, err := New(dir, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.WithClock(func() int64 { return 1000 })
	if err := s.Save(Checkpoint{RunID: "atomic", CreatorKey: keyAlice, State: json.RawMessage(`{"k":1}`)}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "atomic.json.tmp")); !os.IsNotExist(err) {
		t.Errorf("temp file survived save: err=%v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "atomic.json"))
	if err != nil {
		t.Fatalf("read canonical: %v", err)
	}
	var cp Checkpoint
	if err := json.Unmarshal(b, &cp); err != nil {
		t.Fatalf("canonical file is not a complete checkpoint: %v", err)
	}
}

func TestSave_PreservesCreatedAtAcrossSteps(t *testing.T) {
	s, err := New(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := int64(500)
	s.WithClock(func() int64 { return now })
	if err := s.Save(Checkpoint{RunID: "r", CreatorKey: keyAlice, Step: 1}); err != nil {
		t.Fatalf("Save 1: %v", err)
	}
	now = 900
	if err := s.Save(Checkpoint{RunID: "r", CreatorKey: keyAlice, Step: 2}); err != nil {
		t.Fatalf("Save 2: %v", err)
	}
	got, _, _ := s.Load("r", keyAlice)
	if got.CreatedAt != 500 {
		t.Errorf("CreatedAt = %d, want preserved 500", got.CreatedAt)
	}
	if got.UpdatedAt != 900 {
		t.Errorf("UpdatedAt = %d, want 900", got.UpdatedAt)
	}
}

func TestLoad_MissingReturnsNotOk(t *testing.T) {
	s := newStore(t, nil)
	_, ok, err := s.Load("nope", keyAlice)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if ok {
		t.Error("ok = true for missing checkpoint, want false")
	}
}

// --- Identity binding (the core security property) ---

func TestLoad_ByCreatorKey_Succeeds(t *testing.T) {
	s := newStore(t, nil)
	if err := s.Save(Checkpoint{RunID: "r", CreatorKey: keyAlice}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, ok, err := s.Load("r", keyAlice); err != nil || !ok {
		t.Fatalf("Load by creator: ok=%v err=%v", ok, err)
	}
}

func TestLoad_ByDifferentKey_Refused(t *testing.T) {
	s := newStore(t, nil)
	if err := s.Save(Checkpoint{RunID: "r", CreatorKey: keyAlice}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	_, ok, err := s.Load("r", keyBob)
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("err = %v, want ErrIdentityMismatch", err)
	}
	if ok {
		t.Error("ok = true resuming another identity's run — MUST be impossible")
	}
}

func TestLoad_BlankKey_Refused(t *testing.T) {
	s := newStore(t, nil)
	if err := s.Save(Checkpoint{RunID: "r", CreatorKey: keyAlice}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, _, err := s.Load("r", ""); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("blank key: err = %v, want ErrIdentityMismatch", err)
	}
}

func TestSave_OverwriteByDifferentKey_Refused(t *testing.T) {
	s := newStore(t, nil)
	if err := s.Save(Checkpoint{RunID: "r", CreatorKey: keyAlice, Step: 1}); err != nil {
		t.Fatalf("Save alice: %v", err)
	}
	// Bob tries to clobber Alice's run by writing a fresh checkpoint over it.
	err := s.Save(Checkpoint{RunID: "r", CreatorKey: keyBob, Step: 99})
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("overwrite: err = %v, want ErrIdentityMismatch", err)
	}
	// Alice's state must be intact.
	got, _, _ := s.Load("r", keyAlice)
	if got.Step != 1 || got.CreatorKey != keyAlice {
		t.Errorf("Alice's checkpoint was altered: %+v", got)
	}
}

func TestSave_BlankCreatorKey_Rejected(t *testing.T) {
	s := newStore(t, nil)
	if err := s.Save(Checkpoint{RunID: "r", CreatorKey: ""}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestSave_UnsafeRunID_Rejected(t *testing.T) {
	s := newStore(t, nil)
	for _, bad := range []string{"", ".", "..", "a/b", "a\\b", "../escape"} {
		if err := s.Save(Checkpoint{RunID: bad, CreatorKey: keyAlice}); !errors.Is(err, ErrInvalid) {
			t.Errorf("RunID %q: err = %v, want ErrInvalid", bad, err)
		}
	}
}

// --- Intent idempotency ---

func TestBeginIntent_SurfacesPendingOnResumeAfterCrash(t *testing.T) {
	s := newStore(t, nil)
	if err := s.Save(Checkpoint{RunID: "r", CreatorKey: keyAlice, Step: 3}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	intent := Intent{NodeID: "send-email", IdempotencyKey: "idem-123", ArgsHash: "h(abc)"}
	if err := s.BeginIntent("r", keyAlice, intent); err != nil {
		t.Fatalf("BeginIntent: %v", err)
	}
	// Simulate a crash BEFORE CommitIntent: a fresh reload surfaces the intent so
	// the caller knows the op may already have fired and must not blindly re-run.
	got, ok, err := s.Load("r", keyAlice)
	if err != nil || !ok {
		t.Fatalf("Load: ok=%v err=%v", ok, err)
	}
	if got.Intent == nil {
		t.Fatal("pending Intent not surfaced on resume — double-fire window open")
	}
	if got.Intent.NodeID != "send-email" || got.Intent.IdempotencyKey != "idem-123" || got.Intent.ArgsHash != "h(abc)" {
		t.Errorf("Intent = %+v, want the recorded op", got.Intent)
	}
	if got.Intent.RecordedAt != 1000 {
		t.Errorf("Intent.RecordedAt = %d, want stamped 1000", got.Intent.RecordedAt)
	}
}

func TestCommitIntent_ClearsPending(t *testing.T) {
	s := newStore(t, nil)
	if err := s.Save(Checkpoint{RunID: "r", CreatorKey: keyAlice}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.BeginIntent("r", keyAlice, Intent{NodeID: "n", IdempotencyKey: "k"}); err != nil {
		t.Fatalf("BeginIntent: %v", err)
	}
	if err := s.CommitIntent("r", keyAlice); err != nil {
		t.Fatalf("CommitIntent: %v", err)
	}
	got, _, _ := s.Load("r", keyAlice)
	if got.Intent != nil {
		t.Errorf("Intent = %+v after commit, want nil", got.Intent)
	}
	// A double commit is a safe no-op.
	if err := s.CommitIntent("r", keyAlice); err != nil {
		t.Errorf("double CommitIntent: %v, want nil", err)
	}
}

func TestIntentOps_EnforceIdentityBinding(t *testing.T) {
	s := newStore(t, nil)
	if err := s.Save(Checkpoint{RunID: "r", CreatorKey: keyAlice}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.BeginIntent("r", keyBob, Intent{NodeID: "n"}); !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("BeginIntent by Bob: err = %v, want ErrIdentityMismatch", err)
	}
	if err := s.CommitIntent("r", keyBob); !errors.Is(err, ErrIdentityMismatch) {
		t.Errorf("CommitIntent by Bob: err = %v, want ErrIdentityMismatch", err)
	}
}

func TestIntentOps_RequireExistingCheckpoint(t *testing.T) {
	s := newStore(t, nil)
	if err := s.BeginIntent("ghost", keyAlice, Intent{NodeID: "n"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("BeginIntent on missing: err = %v, want ErrNotFound", err)
	}
	if err := s.CommitIntent("ghost", keyAlice); !errors.Is(err, ErrNotFound) {
		t.Errorf("CommitIntent on missing: err = %v, want ErrNotFound", err)
	}
}

// --- Audit ---

func TestAudit_EmittedOnSaveAndResume(t *testing.T) {
	sink := &capSink{}
	s := newStore(t, sink)
	if err := s.Save(Checkpoint{RunID: "r", CreatorKey: keyAlice}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, _, err := s.Load("r", keyAlice); err != nil {
		t.Fatalf("Load: %v", err)
	}
	recs := sink.records()
	if len(recs) != 2 {
		t.Fatalf("got %d audit records, want 2 (save, resume)", len(recs))
	}
	for _, r := range recs {
		if r.Method != "graph.checkpoint" {
			t.Errorf("Method = %q, want graph.checkpoint", r.Method)
		}
		if r.Backend != "air-know" {
			t.Errorf("Backend = %q, want air-know", r.Backend)
		}
		if r.Tool != "r" {
			t.Errorf("Tool(corpus) = %q, want run id r", r.Tool)
		}
		if r.Decision != "allow" {
			t.Errorf("Decision = %q, want allow", r.Decision)
		}
	}
}

func TestAudit_DenyRecordedOnRefusedResume(t *testing.T) {
	sink := &capSink{}
	s := newStore(t, sink)
	if err := s.Save(Checkpoint{RunID: "r", CreatorKey: keyAlice}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, _, err := s.Load("r", keyBob); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("Load by Bob: %v", err)
	}
	var denies int
	for _, r := range sink.records() {
		if r.Decision == "deny" {
			denies++
		}
	}
	if denies != 1 {
		t.Errorf("deny records = %d, want 1 (the refused resume)", denies)
	}
}

// --- Concurrency ---

func TestConcurrentSaves_DistinctRunIDs_NoCorruption(t *testing.T) {
	s := newStore(t, nil)
	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "run-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
			state := json.RawMessage(`{"i":` + strconv.Itoa(i) + `}`)
			if err := s.Save(Checkpoint{RunID: id, CreatorKey: keyAlice, Step: i, State: state}); err != nil {
				t.Errorf("Save %s: %v", id, err)
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		id := "run-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		got, ok, err := s.Load(id, keyAlice)
		if err != nil || !ok {
			t.Fatalf("Load %s: ok=%v err=%v", id, ok, err)
		}
		if string(got.State) != `{"i":`+strconv.Itoa(i)+`}` {
			t.Errorf("%s State = %s, corrupted", id, got.State)
		}
	}
}

func TestConcurrentIntentOps_SameRunID_Serialized(t *testing.T) {
	s := newStore(t, nil)
	if err := s.Save(Checkpoint{RunID: "r", CreatorKey: keyAlice}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Hammer Begin/Commit on one run from many goroutines. The per-RunID lock must
	// keep every read-modify-write atomic — no torn file, no lost update panic.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_ = s.BeginIntent("r", keyAlice, Intent{NodeID: "n", IdempotencyKey: strconv.Itoa(i)})
			} else {
				_ = s.CommitIntent("r", keyAlice)
			}
		}(i)
	}
	wg.Wait()
	// The file remains a valid, loadable checkpoint.
	if _, ok, err := s.Load("r", keyAlice); err != nil || !ok {
		t.Fatalf("Load after concurrent intent ops: ok=%v err=%v", ok, err)
	}
}
