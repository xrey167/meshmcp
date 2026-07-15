package session

import (
	"errors"
	"os"
	"time"
)

// errLockTimeout is returned when a file lock cannot be acquired in time.
var errLockTimeout = errors.New("session: lock acquire timed out")

// fileLock is a portable cross-process advisory lock backed by an exclusive
// lock file (O_CREATE|O_EXCL). It serializes access to a shared FileStore
// across gateway processes so the ownership lease is honored atomically. A
// lock left behind by a crashed holder is stolen once it is older than the
// staleness window (locks here are held only for a brief store operation).
type fileLock struct {
	path      string
	timeout   time.Duration
	staleness time.Duration
}

func (l fileLock) acquire() error {
	deadline := time.Now().Add(l.timeout)
	for {
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			f.Close()
			return nil
		}
		if !os.IsExist(err) {
			return err
		}
		// Held by someone else — steal it if it is stale (holder crashed).
		if fi, e := os.Stat(l.path); e == nil && time.Since(fi.ModTime()) > l.staleness {
			_ = os.Remove(l.path)
			continue
		}
		if time.Now().After(deadline) {
			return errLockTimeout
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (l fileLock) release() { _ = os.Remove(l.path) }
