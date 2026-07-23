package session

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFileLockMutualExclusion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	a := fileLock{path: p, timeout: time.Second, staleness: 10 * time.Second}
	if err := a.acquire(); err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// A second acquire while held must time out.
	b := fileLock{path: p, timeout: 150 * time.Millisecond, staleness: 10 * time.Second}
	if err := b.acquire(); err == nil {
		t.Fatal("second acquire should have timed out while lock is held")
	}

	// After release it is acquirable.
	a.release()
	if err := b.acquire(); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	b.release()
}

func TestFileLockStealsStale(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	// Leave a lock behind (simulating a crashed holder), then make it stale.
	held := fileLock{path: p, timeout: time.Second, staleness: time.Hour}
	if err := held.acquire(); err != nil {
		t.Fatal(err)
	}
	// A short staleness window means the next acquirer steals it.
	stealer := fileLock{path: p, timeout: time.Second, staleness: 10 * time.Millisecond}
	time.Sleep(30 * time.Millisecond)
	if err := stealer.acquire(); err != nil {
		t.Fatalf("should have stolen the stale lock: %v", err)
	}
	stealer.release()
}

// TestFileLockOwnerRoundTrip: acquire writes an owner token into the lock
// file; the owner's release removes it; a re-acquire mints a fresh token.
func TestFileLockOwnerRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	l := fileLock{path: p, timeout: time.Second, staleness: 10 * time.Second}
	if err := l.acquire(); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	first, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read lock file: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("lock file should carry the owner token")
	}
	l.release()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("owner release should remove the lock file, stat err=%v", err)
	}
	if err := l.acquire(); err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	second, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read lock file after re-acquire: %v", err)
	}
	if string(second) == string(first) {
		t.Fatal("re-acquire should mint a fresh owner token")
	}
	l.release()
}

// TestFileLockStaleReleaseKeepsNewOwner: a holder whose stale lock was stolen
// must not delete the thief's lock on its (late) release; the thief still
// owns and can release the lock.
func TestFileLockStaleReleaseKeepsNewOwner(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	a := fileLock{path: p, timeout: time.Second, staleness: time.Hour}
	if err := a.acquire(); err != nil {
		t.Fatalf("holder acquire: %v", err)
	}
	// B judges A's lock stale after a short window and steals it.
	b := fileLock{path: p, timeout: time.Second, staleness: 10 * time.Millisecond}
	time.Sleep(30 * time.Millisecond)
	if err := b.acquire(); err != nil {
		t.Fatalf("steal: %v", err)
	}

	// The stalled original holder returns: its release sees a foreign token
	// and must leave B's lock intact.
	a.release()
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("stale holder's release deleted the new owner's lock: %v", err)
	}

	// B is still the owner and can release its own lock.
	b.release()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("new owner's release should remove the lock, stat err=%v", err)
	}
}

// TestFileLockTimeoutErrorIdentity: an ordinary contention timeout must stay
// identifiable as errLockTimeout via errors.Is (callers and any wrapped
// diagnostic variant rely on that identity).
func TestFileLockTimeoutErrorIdentity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	a := fileLock{path: p, timeout: time.Second, staleness: 10 * time.Second}
	if err := a.acquire(); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer a.release()
	b := fileLock{path: p, timeout: 100 * time.Millisecond, staleness: 10 * time.Second}
	err := b.acquire()
	if !errors.Is(err, errLockTimeout) {
		t.Fatalf("contention timeout should be errLockTimeout, got %v", err)
	}
}

// TestFileLockReleaseMissingFileReturnsFast: release's transient-read retry
// loop must not delay the common no-op cases — a missing lock file (already
// stolen and released) returns immediately, without burning the retry window.
func TestFileLockReleaseMissingFileReturnsFast(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	l := fileLock{path: p, timeout: time.Second, staleness: 10 * time.Second}
	if err := l.acquire(); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatalf("remove lock out from under holder: %v", err)
	}
	start := time.Now()
	l.release()
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("release on missing file should return immediately, took %v", d)
	}
}

// TestFileLockConcurrentAcquireSingleHolder: under goroutine contention the
// lock admits exactly one holder at a time (run with a high -count since
// -race is unavailable in this environment).
func TestFileLockConcurrentAcquireSingleHolder(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.lock")
	const (
		workers = 8
		rounds  = 5
	)
	var (
		inside int32
		wg     sync.WaitGroup
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := fileLock{path: p, timeout: 10 * time.Second, staleness: time.Hour}
			for j := 0; j < rounds; j++ {
				if err := l.acquire(); err != nil {
					t.Errorf("acquire: %v", err)
					return
				}
				if n := atomic.AddInt32(&inside, 1); n != 1 {
					t.Errorf("mutual exclusion violated: %d concurrent holders", n)
				}
				time.Sleep(time.Millisecond)
				atomic.AddInt32(&inside, -1)
				l.release()
			}
		}()
	}
	wg.Wait()
}
