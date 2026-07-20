package policy

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FileRevocation is a directory-backed capability revocation store: each
// revoked capability id (the token's unique "cap_…" id) is a small marker file.
// It plugs into CapabilityVerifier.WithRevocation, giving short-lived grants a
// real kill-switch: a revoked token fails closed at the enforcement point even
// before it expires. The directory can be the shared store already used for
// co-sign / session migration, so no extra infrastructure is needed.
type FileRevocation struct{ Dir string }

// NewFileRevocation returns a revocation store, creating its directory so the
// store is present from startup. This lets IsRevoked distinguish an empty store
// ("nothing revoked yet") from a store that has since become unavailable ("we
// can no longer confirm revocation state") — the latter fails closed.
func NewFileRevocation(dir string) (FileRevocation, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return FileRevocation{}, err
	}
	return FileRevocation{Dir: dir}, nil
}

// safeID rejects a capability id that could escape the directory. Capability
// ids are "cap_" + hex, so anything with a path separator or "." is refused.
func safeID(id string) bool {
	return id != "" && !strings.ContainsAny(id, "/\\") && id != "." && id != ".."
}

// Revoke marks a capability id as revoked. Idempotent.
func (r FileRevocation) Revoke(id string) error {
	if !safeID(id) {
		return os.ErrInvalid
	}
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(r.Dir, id+".revoked"), os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

// IsRevoked reports whether a capability id has been revoked. It is the
// predicate passed to CapabilityVerifier.WithRevocation and FAILS CLOSED: a
// malformed id, an unreachable store, or a lookup error is treated as revoked,
// so a capability can never widen a default deny while its revocation state is
// unknown. Only a reachable store with no marker for the id returns "not
// revoked".
func (r FileRevocation) IsRevoked(id string) bool {
	if !safeID(id) {
		return true
	}
	// The configured store must be reachable. If the revocation directory is
	// missing, unreadable, or not a directory, we cannot confirm this id was not
	// revoked — fail closed. (NewFileRevocation creates the dir at startup, so a
	// missing dir here means the store was lost, not "never used".)
	if fi, err := os.Stat(r.Dir); err != nil || !fi.IsDir() {
		return true
	}
	_, err := os.Stat(filepath.Join(r.Dir, id+".revoked"))
	if err == nil {
		return true // marker present → revoked
	}
	if os.IsNotExist(err) {
		return false // store reachable, no marker → not revoked
	}
	return true // lookup failed (permission / I/O) → fail closed
}

// List returns the revoked capability ids, sorted.
func (r FileRevocation) List() ([]string, error) {
	entries, err := os.ReadDir(r.Dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if name := e.Name(); strings.HasSuffix(name, ".revoked") {
			ids = append(ids, strings.TrimSuffix(name, ".revoked"))
		}
	}
	sort.Strings(ids)
	return ids, nil
}
