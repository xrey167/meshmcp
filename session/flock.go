package session

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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
// The lock file carries the holder's random owner token: release removes the
// file only while it still holds this token, so a stalled holder returning
// after its stale lock was stolen cannot delete the new owner's lock.
type fileLock struct {
	path      string
	timeout   time.Duration
	staleness time.Duration
	token     string // owner token written into the lock file by acquire
}

// newLockToken mints a random owner identity for one acquisition.
func newLockToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (l *fileLock) acquire() error {
	token, err := newLockToken()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(l.timeout)
	var lastPermErr error // last create attempt that failed with EACCES, if any
	for {
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			_, werr := f.WriteString(token)
			cerr := f.Close()
			if werr != nil || cerr != nil {
				// A token-less lock could never be released by its owner and
				// would stall everyone until stolen stale; give it back.
				_ = os.Remove(l.path)
				if werr != nil {
					return werr
				}
				return cerr
			}
			l.token = token
			return nil
		}
		// On Windows a lock file mid-deletion by a racing releaser can surface
		// to the creator as a permission error rather than "exists"; both mean
		// contention, so keep polling. Any other error is fatal.
		if !os.IsExist(err) && !os.IsPermission(err) {
			return err
		}
		// Remember a permission failure so a genuine persistent EACCES (bad
		// directory ACL, pinned file) is surfaced on timeout instead of being
		// masked as ordinary contention; a later "exists" proves it transient.
		if os.IsPermission(err) {
			lastPermErr = err
		} else {
			lastPermErr = nil
		}
		// Held by someone else — steal it if it is stale (holder crashed).
		if fi, e := os.Stat(l.path); e == nil && time.Since(fi.ModTime()) > l.staleness {
			_ = os.Remove(l.path)
			continue
		}
		if time.Now().After(deadline) {
			if lastPermErr != nil {
				return fmt.Errorf("%w (last create error: %v)", errLockTimeout, lastPermErr)
			}
			return errLockTimeout
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// release removes the lock only when the lock file still carries this
// holder's token (read-verify-delete). A holder whose stale lock was stolen
// observes the new owner's token — or no file at all — and silently no-ops,
// leaving the new owner's lock intact. A transient read failure (e.g. an AV
// scanner briefly holding the file open without share flags on Windows) is
// retried for a short bounded window so the rightful owner's lock is not
// stranded until the stale-steal; a persistent failure still no-ops, failing
// safe toward never deleting a lock we cannot prove is ours.
func (l *fileLock) release() {
	if l.token == "" {
		return
	}
	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		got, err := os.ReadFile(l.path)
		if err == nil {
			if bytes.Equal(got, []byte(l.token)) {
				_ = os.Remove(l.path)
			}
			return
		}
		if os.IsNotExist(err) || time.Now().After(deadline) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}
