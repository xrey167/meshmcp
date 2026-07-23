package session

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// TestFileStoreStolenLockAbortsCommit: a holder paused inside a store critical
// section whose lock was stolen as stale must NOT commit — its rename would
// reinstall a stale image (old owner, old generation) over whatever the
// stealing process committed, regressing the fencing generation. The paused
// holder's write is aborted, the committed record stays intact, and no temp
// file is left behind.
func TestFileStoreStolenLockAbortsCommit(t *testing.T) {
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The state the CURRENT lock holder committed (an adoption at gen 6).
	if err := fs.Save(PersistedSession{ID: "sess", Owner: "gw2", Generation: 6}); err != nil {
		t.Fatal(err)
	}

	// A paused holder: it acquired the lock, read (gw1, gen 5)... and stalled.
	paused := fs.lock()
	if err := paused.acquire(); err != nil {
		t.Fatal(err)
	}
	// The staleness window passes; another process steals the lock and now
	// holds it under its own token.
	if err := os.Remove(paused.path); err != nil {
		t.Fatal(err)
	}
	thief := fs.lock()
	if err := thief.acquire(); err != nil {
		t.Fatal(err)
	}
	defer thief.release()

	// The paused holder resumes mid-critical-section and tries to commit.
	err = fs.writeLocked(&paused, PersistedSession{ID: "sess", Owner: "gw1", Generation: 5})
	if !errors.Is(err, errLockStolen) {
		t.Fatalf("stolen-lock commit: err=%v, want errLockStolen", err)
	}

	got, ok, err := fs.Load("sess")
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if got.Owner != "gw2" || got.Generation != 6 {
		t.Fatalf("stale image committed over the new owner: owner=%q gen=%d, want gw2/6", got.Owner, got.Generation)
	}
	entries, err := os.ReadDir(fs.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("aborted commit left temp file %s", e.Name())
		}
	}
	// The paused holder's release must not delete the thief's lock either
	// (token read-verify-delete, unchanged behavior).
	paused.release()
	if _, err := os.Stat(thief.path); err != nil {
		t.Fatalf("paused holder's release removed the thief's lock: %v", err)
	}
}

// TestStandbySweepRefusedOverFileStore: the autonomous sweep must not run over
// FileStore — a stale-lock steal from a paused-not-dead holder can regress the
// generation an adoption committed, the split-brain the sweep must never
// create. The renewal heartbeat (no new writer) still runs.
func TestStandbySweepRefusedOverFileStore(t *testing.T) {
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	factory := func(Meta) (Backend, error) { return newMigBackend(), nil }
	srv := newStandbyServer(fs, time.Minute, factory)
	stop := make(chan struct{})
	srv.StartLeaseMaintenance(stop)
	close(stop)
	srv.Shutdown() // joins the maintenance goroutine before inspecting state
	if srv.failover.Enabled {
		t.Fatal("standby sweep must be disabled over a FileStore")
	}
	if srv.maintDone == nil {
		t.Fatal("the renewal heartbeat must still run over a FileStore")
	}
}
