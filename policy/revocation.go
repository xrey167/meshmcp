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
// predicate passed to CapabilityVerifier.WithRevocation, and fails safe: a
// malformed id is treated as revoked.
func (r FileRevocation) IsRevoked(id string) bool {
	if !safeID(id) {
		return true
	}
	_, err := os.Stat(filepath.Join(r.Dir, id+".revoked"))
	return err == nil
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
