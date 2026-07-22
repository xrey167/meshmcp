package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/session"
)

const testTargetKey = "target-wireguard-key"

func testHandoffOffer(t *testing.T, id string, now time.Time, ttl time.Duration, goal string) air.HandoffOffer {
	t.Helper()
	capsule := air.ContextCapsule{
		Version:   air.HandoffVersion,
		ID:        id,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		TargetKey: testTargetKey,
		Work:      air.WorkRef{Kind: air.WorkKind("task"), ID: "task-17"},
		Goal:      goal,
		Summary:   "continue the governed task",
	}
	offer, err := air.SealHandoff(capsule)
	if err != nil {
		t.Fatalf("seal handoff: %v", err)
	}
	return offer
}

func testSource() session.Meta {
	return session.Meta{
		PeerFQDN: "source.mesh.test",
		PeerKey:  "source-wireguard-key",
		PeerAddr: "100.64.0.8:43210",
	}
}

func TestHandoffInboxPersistsIdentityBoundOfferSecurely(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	dir := filepath.Join(t.TempDir(), "handoffs")
	inbox, err := newHandoffInbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("a", 32), now, time.Hour, "continue on workstation")

	rec, created, err := inbox.Put(offer, testSource(), testTargetKey, now)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !created {
		t.Fatal("first put must create a record")
	}
	if rec.State != air.HandoffOffered {
		t.Fatalf("state = %q, want offered", rec.State)
	}
	if rec.SourcePeer != testSource().PeerFQDN || rec.SourceKey != testSource().PeerKey || rec.SourceAddr != testSource().PeerAddr {
		t.Fatalf("source metadata was not stamped from transport: %+v", rec)
	}
	if !rec.ReceivedAt.Equal(now) || !rec.UpdatedAt.Equal(now) {
		t.Fatalf("timestamps = received %v updated %v, want %v", rec.ReceivedAt, rec.UpdatedAt, now)
	}

	if runtime.GOOS != "windows" {
		assertPerm(t, dir, 0o700)
		assertPerm(t, filepath.Join(dir, offer.Capsule.ID+".json"), 0o600)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".handoff-inbox.lock") {
			names = append(names, entry.Name())
		}
	}
	if len(names) != 1 || names[0] != offer.Capsule.ID+".json" {
		t.Fatalf("record filenames = %v, want only the validated id", names)
	}

	// Re-open from disk: persistence must not depend on one process's memory.
	reopened, err := newHandoffInbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := reopened.Get(offer.Capsule.ID)
	if err != nil || !ok {
		t.Fatalf("get after reopen: ok=%v err=%v", ok, err)
	}
	if got.SourceKey != testSource().PeerKey || got.Offer.ContentHash != offer.ContentHash {
		t.Fatalf("reopened record differs: %+v", got)
	}

	// Reopening repairs a legacy or externally loosened record before it can
	// be read again.
	if runtime.GOOS != "windows" {
		recordPath := filepath.Join(dir, offer.Capsule.ID+".json")
		if err := os.Chmod(recordPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := newHandoffInbox(dir); err != nil {
			t.Fatalf("reopen and secure record: %v", err)
		}
		assertPerm(t, recordPath, 0o600)
	}
}

func TestHandoffInboxRejectsTamperedPersistentRecords(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		mutate func(*air.HandoffRecord)
		want   string
	}{
		{
			name: "capsule content no longer matches hash",
			mutate: func(rec *air.HandoffRecord) {
				rec.Offer.Capsule.Goal = "tampered continuation goal"
			},
			want: "content hash mismatch",
		},
		{
			name: "capsule version is not canonical",
			mutate: func(rec *air.HandoffRecord) {
				rec.Offer.Capsule.Version = 0
			},
			want: "capsule is not canonical",
		},
		{
			name: "capsule sensitivity is not canonical",
			mutate: func(rec *air.HandoffRecord) {
				rec.Offer.Capsule.Sensitivity = ""
			},
			want: "capsule is not canonical",
		},
		{
			name: "unknown state",
			mutate: func(rec *air.HandoffRecord) {
				rec.State = air.HandoffState("executing")
			},
			want: "unknown state",
		},
		{
			name: "zero receipt timestamp",
			mutate: func(rec *air.HandoffRecord) {
				rec.ReceivedAt = time.Time{}
			},
			want: "receipt timestamp",
		},
		{
			name: "update predates receipt",
			mutate: func(rec *air.HandoffRecord) {
				rec.UpdatedAt = rec.ReceivedAt.Add(-time.Second)
			},
			want: "update timestamp predates receipt",
		},
		{
			name: "receipt is outside offer lifetime",
			mutate: func(rec *air.HandoffRecord) {
				rec.ReceivedAt = rec.Offer.Capsule.ExpiresAt
				rec.UpdatedAt = rec.ReceivedAt
			},
			want: "receipt timestamp is outside",
		},
		{
			name: "dispatching has no destination receipt",
			mutate: func(rec *air.HandoffRecord) {
				rec.State = air.HandoffDispatching
			},
			want: "no pending delivery receipt",
		},
		{
			name: "continued has no acknowledged receipt",
			mutate: func(rec *air.HandoffRecord) {
				rec.State = air.HandoffContinued
			},
			want: "no acknowledged delivery receipt",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			inbox, err := newHandoffInbox(dir)
			if err != nil {
				t.Fatal(err)
			}
			id := strings.Repeat(string("abcdef0123456789"[i]), 32)
			offer := testHandoffOffer(t, id, now, time.Hour, "original goal")
			if _, _, err := inbox.Put(offer, testSource(), testTargetKey, now); err != nil {
				t.Fatal(err)
			}

			path := filepath.Join(dir, id+".json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var rec air.HandoffRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				t.Fatal(err)
			}
			tt.mutate(&rec)
			raw, err = json.Marshal(rec)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}

			if _, _, err := inbox.Get(id); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Get tampered record error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestHandoffInboxReplayCollisionAndSourceBinding(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	inbox, err := newHandoffInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("b", 32)
	offer := testHandoffOffer(t, id, now, time.Hour, "goal one")
	source := testSource()
	first, created, err := inbox.Put(offer, source, testTargetKey, now)
	if err != nil || !created {
		t.Fatalf("first put: created=%v err=%v", created, err)
	}

	// Same verified key is an idempotent replay even if descriptive network
	// metadata changed after roaming. The original attribution is retained.
	roamed := source
	roamed.PeerFQDN = "source-renamed.mesh.test"
	roamed.PeerAddr = "100.64.0.8:54321"
	replay, created, err := inbox.Put(offer, roamed, testTargetKey, now.Add(time.Minute))
	if err != nil || created {
		t.Fatalf("idempotent replay: created=%v err=%v", created, err)
	}
	if replay.SourcePeer != first.SourcePeer || !replay.ReceivedAt.Equal(first.ReceivedAt) {
		t.Fatalf("replay rewrote original attribution: first=%+v replay=%+v", first, replay)
	}

	collision := testHandoffOffer(t, id, now, time.Hour, "different content under the same id")
	if _, _, err := inbox.Put(collision, source, testTargetKey, now.Add(2*time.Minute)); err == nil {
		t.Fatal("same id with a different content hash must be rejected")
	}

	other := source
	other.PeerKey = "different-source-key"
	if _, _, err := inbox.Put(offer, other, testTargetKey, now.Add(2*time.Minute)); err == nil {
		t.Fatal("same offer replayed by a different verified identity must be rejected")
	}

	unverified := source
	unverified.PeerKey = ""
	if _, _, err := inbox.Put(testHandoffOffer(t, strings.Repeat("c", 32), now, time.Hour, "unverified"), unverified, testTargetKey, now); err == nil {
		t.Fatal("an unverified source identity must be rejected")
	}
}

func TestHandoffInboxExpiryAndTransitions(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	inbox, err := newHandoffInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("d", 32), now, time.Minute, "continue")
	if _, _, err := inbox.Put(offer, testSource(), testTargetKey, now); err != nil {
		t.Fatal(err)
	}

	accepted, err := inbox.Transition(offer.Capsule.ID, air.HandoffAccepted, now.Add(30*time.Second), "accepted by owner")
	if err != nil || accepted.State != air.HandoffAccepted || accepted.Note != "accepted by owner" {
		t.Fatalf("accept: record=%+v err=%v", accepted, err)
	}
	if _, err := inbox.Transition(offer.Capsule.ID, air.HandoffContinued, now.Add(20*time.Second), "out-of-order delivery"); err == nil {
		t.Fatal("transition timestamp before the last update must fail")
	}
	if _, err := inbox.Transition(offer.Capsule.ID, air.HandoffContinued, now.Add(40*time.Second), "skipped dispatch claim"); err == nil {
		t.Fatal("accepted handoff skipped dispatching state")
	}
	claimed, err := inbox.ClaimDelivery(offer.Capsule.ID, "100.64.0.31:9120", "agent-key", "resume_analysis", now.Add(40*time.Second))
	if err != nil || claimed.State != air.HandoffDispatching {
		t.Fatalf("claim: record=%+v err=%v", claimed, err)
	}
	continued, err := inbox.AcknowledgeDelivery(offer.Capsule.ID, now.Add(50*time.Second))
	if err != nil || continued.State != air.HandoffContinued {
		t.Fatalf("continue: record=%+v err=%v", continued, err)
	}
	if len(continued.DeliveryAttempts) != 1 || continued.DeliveryAttempts[0].AgentKey != "agent-key" || continued.DeliveryAttempts[0].Tool != "resume_analysis" || continued.DeliveryAttempts[0].AcknowledgedAt == nil {
		t.Fatalf("destination receipt was not persisted: %+v", continued.DeliveryAttempts)
	}
	if _, err := inbox.Transition(offer.Capsule.ID, air.HandoffAccepted, now.Add(55*time.Second), "go backwards"); err == nil {
		t.Fatal("invalid backward transition must fail")
	}
	unchanged, ok, err := inbox.Get(offer.Capsule.ID)
	if err != nil || !ok || unchanged.State != air.HandoffContinued {
		t.Fatalf("invalid transition mutated the record: %+v ok=%v err=%v", unchanged, ok, err)
	}
	if _, err := inbox.Transition(offer.Capsule.ID, air.HandoffContinued, now.Add(-time.Second), "clock moved backwards"); err == nil {
		t.Fatal("transition timestamp before receipt must fail")
	}

	// An expired offer cannot be accepted. The derived expiry must be made
	// durable so a restart observes an explicit terminal state.
	expiring := testHandoffOffer(t, strings.Repeat("e", 32), now, time.Minute, "expires")
	if _, _, err := inbox.Put(expiring, testSource(), testTargetKey, now); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Transition(expiring.Capsule.ID, air.HandoffAccepted, now.Add(2*time.Minute), "too late"); err == nil {
		t.Fatal("accepting an expired offer must fail")
	}
	expired, ok, err := inbox.Get(expiring.Capsule.ID)
	if err != nil || !ok || expired.State != air.HandoffExpired {
		t.Fatalf("expired state was not persisted: %+v ok=%v err=%v", expired, ok, err)
	}

	alreadyExpired := testHandoffOffer(t, strings.Repeat("f", 32), now, time.Minute, "already expired")
	if _, _, err := inbox.Put(alreadyExpired, testSource(), testTargetKey, now.Add(2*time.Minute)); err == nil {
		t.Fatal("Put must reject an already-expired offer")
	}
}

func TestHandoffInboxNotesAreBoundedAndControlSafe(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	inbox, err := newHandoffInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("1", 32), now, time.Hour, "continue")
	if _, _, err := inbox.Put(offer, testSource(), testTargetKey, now); err != nil {
		t.Fatal(err)
	}
	for _, note := range []string{strings.Repeat("n", maxHandoffNote+1), "terminal\x1b[31minjection"} {
		if _, err := inbox.Transition(offer.Capsule.ID, air.HandoffAccepted, now.Add(time.Minute), note); err == nil {
			t.Fatalf("unsafe note %q was accepted", note)
		}
	}
	rec, ok, err := inbox.Get(offer.Capsule.ID)
	if err != nil || !ok || rec.State != air.HandoffOffered || rec.Note != "" {
		t.Fatalf("unsafe note mutated record: %+v ok=%v err=%v", rec, ok, err)
	}
}

func TestHandoffInboxListNewestFirstStable(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	inbox, err := newHandoffInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{strings.Repeat("3", 32), strings.Repeat("1", 32), strings.Repeat("2", 32)}
	times := []time.Time{now, now.Add(time.Minute), now.Add(time.Minute)}
	for i := range ids {
		offer := testHandoffOffer(t, ids[i], now, time.Hour, "goal "+ids[i][:1])
		if _, _, err := inbox.Put(offer, testSource(), testTargetKey, times[i]); err != nil {
			t.Fatal(err)
		}
	}
	got, err := inbox.List()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{ids[1], ids[2], ids[0]} // newest first; id ascending breaks ties
	if len(got) != len(want) {
		t.Fatalf("list len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Offer.Capsule.ID != want[i] {
			t.Fatalf("list[%d] = %s, want %s", i, got[i].Offer.Capsule.ID, want[i])
		}
	}
}

func TestHandoffInboxCountBoundAndIdempotentReplayAtCapacity(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	inbox, err := newHandoffInbox(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	offers := []air.HandoffOffer{
		testHandoffOffer(t, strings.Repeat("4", 32), now, time.Hour, "one"),
		testHandoffOffer(t, strings.Repeat("5", 32), now, time.Hour, "two"),
		testHandoffOffer(t, strings.Repeat("6", 32), now, time.Hour, "three"),
	}
	for _, offer := range offers[:2] {
		if _, _, err := inbox.Put(offer, testSource(), testTargetKey, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, created, err := inbox.Put(offers[0], testSource(), testTargetKey, now); err != nil || created {
		t.Fatalf("idempotent replay at capacity: created=%v err=%v", created, err)
	}
	if _, _, err := inbox.Put(offers[2], testSource(), testTargetKey, now); !errors.Is(err, errHandoffInboxFull) {
		t.Fatalf("third distinct offer error = %v, want errHandoffInboxFull", err)
	}
}

func TestHandoffInboxRejectsInvalidIDsAndTraversal(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	inbox, err := newHandoffInbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "short", "../outside", strings.Repeat("g", 32), strings.Repeat("A", 32), strings.Repeat("a", 31) + "/"} {
		if _, _, err := inbox.Get(id); err == nil {
			t.Fatalf("Get accepted invalid id %q", id)
		}
		if _, err := inbox.Transition(id, air.HandoffAccepted, now, ""); err == nil {
			t.Fatalf("Transition accepted invalid id %q", id)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "outside.json")); !os.IsNotExist(err) {
		t.Fatalf("path traversal created an outside file: %v", err)
	}

	valid := testHandoffOffer(t, strings.Repeat("7", 32), now, time.Hour, "valid then mutated")
	valid.Capsule.ID = "../../outside"
	if _, _, err := inbox.Put(valid, testSource(), testTargetKey, now); err == nil {
		t.Fatal("Put accepted a traversal id")
	}
}

func TestHandoffInboxConcurrentPutHasOneCreator(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	offer := testHandoffOffer(t, strings.Repeat("8", 32), now, time.Hour, "concurrent")
	const workers = 24
	var created atomic.Int32
	errC := make(chan error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inbox, err := newHandoffInbox(dir)
			if err != nil {
				errC <- err
				return
			}
			<-start
			_, wasCreated, err := inbox.Put(offer, testSource(), testTargetKey, now)
			if wasCreated {
				created.Add(1)
			}
			if err != nil {
				errC <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errC)
	for err := range errC {
		t.Errorf("concurrent put: %v", err)
	}
	if got := created.Load(); got != 1 {
		t.Fatalf("creators = %d, want exactly one", got)
	}
	inbox, err := newHandoffInbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	list, err := inbox.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("list after concurrent puts: len=%d err=%v", len(list), err)
	}
}

func TestHandoffInboxAdvisoryLockBoundsWaitAndReleases(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	holder, err := newHandoffInbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	contender, err := newHandoffInbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	contender.lockTimeout = 80 * time.Millisecond
	held, err := holder.acquireDiskLock()
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("9", 32), now, time.Hour, "locked")
	started := time.Now()
	if _, _, err := contender.Put(offer, testSource(), testTargetKey, now); err == nil {
		held.release()
		t.Fatal("held advisory lock must bound and fail acquisition")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		held.release()
		t.Fatalf("lock acquisition was not bounded: %v", elapsed)
	}
	held.release()
	if _, _, err := contender.Put(offer, testSource(), testTargetKey, now); err != nil {
		t.Fatalf("released advisory lock was not reacquired: %v", err)
	}
}

const handoffLockHelperEnv = "MESHMCP_TEST_HANDOFF_LOCK_DIR"

func TestHandoffInboxAdvisoryLockIsCrossProcessAndCrashSafe(t *testing.T) {
	if dir := os.Getenv(handoffLockHelperEnv); dir != "" {
		inbox, err := newHandoffInbox(dir)
		if err != nil {
			t.Fatal(err)
		}
		lock, err := inbox.acquireDiskLock()
		if err != nil {
			t.Fatal(err)
		}
		defer lock.release()
		if _, err := fmt.Fprintln(os.Stdout, "locked"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Second)
		return
	}

	dir := t.TempDir()
	contender, err := newHandoffInbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	contender.lockTimeout = 100 * time.Millisecond

	cmd := exec.Command(os.Args[0], "-test.run=^TestHandoffInboxAdvisoryLockIsCrossProcessAndCrashSafe$")
	cmd.Env = append(os.Environ(), handoffLockHelperEnv+"="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	lineC := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			lineC <- scanner.Text()
			return
		}
		lineC <- ""
	}()
	select {
	case line := <-lineC:
		if line != "locked" {
			t.Fatalf("lock helper readiness = %q, want locked", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for lock helper")
	}

	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	offer := testHandoffOffer(t, strings.Repeat("a", 32), now, time.Hour, "cross-process")
	if _, _, err := contender.Put(offer, testSource(), testTargetKey, now); err == nil {
		t.Fatal("another process's advisory lock did not block Put")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("lock helper unexpectedly exited cleanly after kill")
	}
	if _, _, err := contender.Put(offer, testSource(), testTargetKey, now); err != nil {
		t.Fatalf("kernel did not release advisory lock after process death: %v", err)
	}
}

func TestHandoffInboxRecordJSONContainsNoUnrelatedProcessSecrets(t *testing.T) {
	now := time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	inbox, err := newHandoffInbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("0", 32), now, time.Hour, "continue")
	if _, _, err := inbox.Put(offer, testSource(), testTargetKey, now); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, offer.Capsule.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded air.HandoffRecord
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("record is not a HandoffRecord JSON document: %v", err)
	}
	if decoded.SourceKey != testSource().PeerKey || decoded.Offer.ContentHash != offer.ContentHash {
		t.Fatalf("decoded record differs: %+v", decoded)
	}
	// The store serializes exactly the offer + transport attribution + state;
	// it never captures the process environment or unrelated credential data.
	if strings.Contains(string(raw), "NB_SETUP_KEY") || strings.Contains(string(raw), "MESHMCP_PEER_KEY") {
		t.Fatalf("record contains unrelated process secret names: %s", raw)
	}
}

func TestHandoffInboxArchivesTerminalReceiptsWithoutForgettingReplay(t *testing.T) {
	now := time.Now().UTC()
	inbox, err := newHandoffInbox(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("4", 32), now, time.Hour, "archive me")
	if _, _, err := inbox.Put(offer, testSource(), testTargetKey, now); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Transition(offer.Capsule.ID, air.HandoffDeclined, now.Add(time.Second), "declined"); err != nil {
		t.Fatal(err)
	}
	ids, err := inbox.Archive(now.Add(2*time.Second), 0)
	if err != nil || len(ids) != 1 || ids[0] != offer.Capsule.ID {
		t.Fatalf("archive ids=%v err=%v", ids, err)
	}
	if _, found, err := inbox.Get(offer.Capsule.ID); err != nil || found {
		t.Fatalf("archived receipt remained active: found=%v err=%v", found, err)
	}
	if runtime.GOOS != "windows" {
		archivedPath := filepath.Join(inbox.archiveDir(), offer.Capsule.ID+".json")
		assertPerm(t, archivedPath, 0o600)
		if err := os.Chmod(archivedPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := newHandoffInbox(inbox.dir, 1); err != nil {
			t.Fatalf("reopen inbox with archive: %v", err)
		}
		assertPerm(t, archivedPath, 0o600)
	}
	if rec, created, err := inbox.Put(offer, testSource(), testTargetKey, now.Add(3*time.Second)); err != nil || created || rec.State != air.HandoffDeclined {
		t.Fatalf("archived replay: record=%+v created=%v err=%v", rec, created, err)
	}

	fresh := testHandoffOffer(t, strings.Repeat("5", 32), now.Add(3*time.Second), time.Hour, "quota freed")
	if _, created, err := inbox.Put(fresh, testSource(), testTargetKey, now.Add(3*time.Second)); err != nil || !created {
		t.Fatalf("archive did not free active quota: created=%v err=%v", created, err)
	}
}

func TestHandoffInboxArchiveAgesImplicitExpiryFromExpiryTime(t *testing.T) {
	created := time.Now().UTC().Add(-24 * time.Hour)
	inbox, err := newHandoffInbox(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("6", 32), created, 24*time.Hour, "recently expired")
	if _, _, err := inbox.Put(offer, testSource(), testTargetKey, created); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Transition(offer.Capsule.ID, air.HandoffAccepted, created.Add(time.Minute), "accepted long ago"); err != nil {
		t.Fatal(err)
	}
	ids, err := inbox.Archive(created.Add(24*time.Hour+time.Minute), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("newly expired record archived using stale accept time: %v", ids)
	}
}

func TestHandoffInboxArchivesExpiredUnknownDispatchWithoutErasingUncertainty(t *testing.T) {
	created := time.Now().UTC()
	dir := t.TempDir()
	inbox, err := newHandoffInbox(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	offer := testHandoffOffer(t, strings.Repeat("7", 32), created, time.Minute, "unknown delivery")
	if _, _, err := inbox.Put(offer, testSource(), testTargetKey, created); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Transition(offer.Capsule.ID, air.HandoffAccepted, created.Add(time.Second), "accepted"); err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.ClaimDelivery(offer.Capsule.ID, "100.64.0.31:9120", "agent-key", "resume", created.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	archivedAt := offer.Capsule.ExpiresAt.Add(time.Second)
	ids, err := inbox.Archive(archivedAt, 0)
	if err != nil || len(ids) != 1 || ids[0] != offer.Capsule.ID {
		t.Fatalf("archive expired unknown dispatch: ids=%v err=%v", ids, err)
	}
	raw, err := os.ReadFile(filepath.Join(inbox.archiveDir(), offer.Capsule.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var archived air.HandoffRecord
	if err := json.Unmarshal(raw, &archived); err != nil {
		t.Fatal(err)
	}
	if archived.State != air.HandoffDispatching || len(archived.DeliveryAttempts) != 1 || archived.DeliveryAttempts[0].AcknowledgedAt != nil {
		t.Fatalf("archive erased unknown delivery evidence: %+v", archived)
	}

	fresh := testHandoffOffer(t, strings.Repeat("8", 32), archivedAt, time.Hour, "quota recovered")
	if _, created, err := inbox.Put(fresh, testSource(), testTargetKey, archivedAt); err != nil || !created {
		t.Fatalf("expired unknown dispatch still exhausted active quota: created=%v err=%v", created, err)
	}
	collision := testHandoffOffer(t, offer.Capsule.ID, archivedAt, time.Hour, "changed replay content")
	if _, _, err := inbox.Put(collision, testSource(), testTargetKey, archivedAt); !errors.Is(err, errHandoffIDCollision) {
		t.Fatalf("archived unknown dispatch forgot replay tombstone: %v", err)
	}
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s permissions = %04o, want %04o", path, got, want)
	}
}
