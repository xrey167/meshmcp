package edge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// This file holds the on-disk discipline shared by the edge's client, token,
// and authz stores. It deliberately mirrors federation/dcr.go's conventions
// (0700 dir, 0600 files, tmp+fsync+rename, per-key locking, bcrypt(sha256) for
// the one bearer secret) rather than importing them, matching the repo's own
// convention of duplicating small store helpers across packages instead of
// exporting them.

// keyedLocks serializes critical sections by an arbitrary string key, so a
// filesystem operation that must be atomic across goroutines (a read-modify-
// write of one record, a quota check-then-commit) cannot interleave. The zero
// value is ready to use.
type keyedLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func (k *keyedLocks) lock(key string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*sync.Mutex{}
	}
	m := k.locks[key]
	if m == nil {
		m = &sync.Mutex{}
		k.locks[key] = m
	}
	k.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// randHex returns n cryptographically-random bytes as a hex string.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("edge: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// randToken returns a 256-bit high-entropy opaque secret (hex). Access tokens,
// refresh tokens, authorization codes, and registration access tokens are all
// minted this way; only their SHA-256 (codes/tokens) or bcrypt(SHA-256)
// (registration token) is persisted, never the raw value.
func randToken() string { return randHex(32) }

// sha256Hex is the storage key for an opaque secret: records are named by the
// hash of the secret, so the raw secret never touches disk.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sha256Bytes is the raw-digest form used as the bcrypt pre-hash for the
// registration access token (bcrypt truncates inputs beyond 72 bytes).
func sha256Bytes(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// secureDir creates dir (0700) and repairs the mode of a pre-existing path, so
// an operator-provisioned mount created with a permissive umask is tightened to
// the private boundary the store's secrets require.
func secureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("edge: create store dir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("edge: secure store dir %s: %w", dir, err)
	}
	return nil
}

// writeAtomicJSON marshals rec and writes it to dst via tmp+fsync+rename, so a
// reader never observes a partially-written record and a crash cannot corrupt
// an existing one.
func writeAtomicJSON(dst string, rec any) error {
	if err := secureDir(filepath.Dir(dst)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("edge: marshal record: %w", err)
	}
	tmp := dst + ".tmp-" + randHex(8)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("edge: open tmp file: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("edge: write tmp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("edge: sync tmp file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("edge: close tmp file: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("edge: rename into place: %w", err)
	}
	return nil
}

// readJSON reads and unmarshals a record. os.IsNotExist(err) distinguishes a
// missing record from a corrupt one.
func readJSON(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("edge: parse record %s: %w", path, err)
	}
	return nil
}

// claimByRename atomically consumes a single-use record (an authorization code
// or a rotated refresh token): the first caller to rename it wins, and every
// later caller observes os.IsNotExist. This works across processes (the CLI and
// the daemon share the directory), which per-process locks cannot guarantee.
// It returns the claimed record decoded into out.
func claimByRename(path string, out any) error {
	if err := readJSON(path, out); err != nil {
		return err
	}
	claimed := path + ".claimed-" + randHex(8)
	if err := os.Rename(path, claimed); err != nil {
		return err // another caller already claimed it (os.IsNotExist), or a real error
	}
	_ = os.Remove(claimed)
	return nil
}
