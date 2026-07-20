package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"meshmcp/policy"
)

// The plugin marketplace (F14) is a governed exchange for signed bundle
// manifests. Publishing mints an Ed25519-signed manifest (policy.ManifestClaims)
// bound to the bundle's content hash; discovery lists manifests; installing
// verifies a manifest against a pinned authority key AND the bundle bytes, then
// records an audited, metered grant. The plugin CODE is never loaded at runtime
// — it stays compiled in and is listed by `meshmcp plugins`; the marketplace
// governs distribution and attribution, honoring the no-dynamic-loading bar.

// manifestStore is a file-backed catalog of published manifests — one file per
// bundle name, tolerant reads — mirroring registry.FileRegistry so a directory
// can be shared (dropped or synced over the mesh) between publishers.
type manifestStore struct{ dir string }

func newManifestStore(dir string) (*manifestStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &manifestStore{dir: dir}, nil
}

// sanitizeName maps a bundle name to a safe filename stem.
func sanitizeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" {
		s = "bundle"
	}
	return s
}

func (s *manifestStore) path(name string) string {
	return filepath.Join(s.dir, sanitizeName(name)+".manifest")
}

// Publish writes a signed manifest token under its bundle name (latest wins).
func (s *manifestStore) Publish(name, token string) error {
	return os.WriteFile(s.path(name), []byte(token+"\n"), 0o644)
}

// List returns every published manifest token (order unspecified). Files that
// vanished or are empty are skipped, so a concurrent publish never turns
// enumeration into an error.
func (s *manifestStore) List() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".manifest") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		if tok := strings.TrimSpace(string(b)); tok != "" {
			out = append(out, tok)
		}
	}
	return out, nil
}

// recordInstall appends an audited, metered grant for a verified install. Every
// install is attributable (the installer identity + the bundle's content hash
// land in the tamper-evident ledger) and metered (Cost rolls up under
// `meshmcp budget`). Mirrors federation.Boundary's audited crossing.
func recordInstall(audit *policy.AuditLog, installer, peerKey string, c policy.ManifestClaims) error {
	return audit.Append(policy.AuditRecord{
		Backend:    "marketplace",
		Peer:       installer,
		PeerKey:    peerKey,
		Method:     "market/install",
		Tool:       c.Name,
		Decision:   "allow",
		Reason:     fmt.Sprintf("install %s %q v%s from %s (%s)", c.Kind, c.Name, c.BundleVersion, c.Issuer, c.ID),
		Rule:       -1,
		Cost:       c.Cost,
		Provenance: []string{c.ContentHash},
	})
}
