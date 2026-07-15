package session

import (
	"path/filepath"
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
