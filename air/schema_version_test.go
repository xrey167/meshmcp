package air

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPairedStoreStampsAndRejectsNewer proves the paired store writes the
// current schema_version and refuses (fail closed) a store written by a newer
// build, rather than silently forgetting every recognized peer.
func TestPairedStoreStampsAndRejectsNewer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired.json")

	s, err := OpenPairedStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	id := VerifiedIdentity{PublicKey: "peerkey", FQDN: "peer.netbird.cloud"}
	if _, _, err := s.Request(id, "laptop", time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatalf("request: %v", err)
	}

	// The written file self-describes its version.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.SchemaVersion != pairedSchemaVersion {
		t.Errorf("stamped version = %d, want %d", onDisk.SchemaVersion, pairedSchemaVersion)
	}

	// Bump the on-disk version beyond what this build supports; load must refuse.
	bumped := strings.Replace(string(b),
		`"schema_version": 1`, `"schema_version": 2`, 1)
	if bumped == string(b) {
		t.Fatalf("test setup: did not find the version to bump in %s", b)
	}
	if err := os.WriteFile(path, []byte(bumped), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPairedStore(path); err == nil {
		t.Fatalf("expected reject-newer error, got nil (store must fail closed)")
	} else if !strings.Contains(err.Error(), "newer than this build supports") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestPairedStoreLegacyFileLoads proves a store written before versioning (no
// schema_version key → 0) still loads, preserving its peers across the upgrade.
func TestPairedStoreLegacyFileLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired.json")
	legacy := `{"pending":[],"paired":[{"public_key":"k","approved_at":"2020-01-01T00:00:00Z","approver":"op"}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenPairedStore(path)
	if err != nil {
		t.Fatalf("legacy load failed: %v", err)
	}
	if !s.Recognized("k", "") {
		t.Errorf("legacy paired peer was dropped on load")
	}
}

// TestGrantStoreStampsAndRejectsNewer proves the grant store writes the current
// schema_version and refuses a store from a newer build (fail closed), rather
// than silently forgetting written grants.
func TestGrantStoreStampsAndRejectsNewer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grants.json")

	s, err := OpenGrantStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := s.Add("peerkey", "kg", "corpus/*", false, "op", time.Unix(1_700_000_000, 0)); err != nil {
		t.Fatalf("add: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(b, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.SchemaVersion != grantSchemaVersion {
		t.Errorf("stamped version = %d, want %d", onDisk.SchemaVersion, grantSchemaVersion)
	}

	bumped := strings.Replace(string(b),
		`"schema_version": 1`, `"schema_version": 2`, 1)
	if bumped == string(b) {
		t.Fatalf("test setup: did not find the version to bump")
	}
	if err := os.WriteFile(path, []byte(bumped), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenGrantStore(path); err == nil {
		t.Fatalf("expected reject-newer error, got nil (store must fail closed)")
	} else if !strings.Contains(err.Error(), "newer than this build supports") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestGrantStoreLegacyFileLoads proves a pre-versioning grant store still loads.
func TestGrantStoreLegacyFileLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grants.json")
	legacy := `{"grants":[{"identity":"k","verb":"kg","scope":"c/*","once":false,"granted_by":"op","granted_at":"2020-01-01T00:00:00Z"}],"pending":[]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenGrantStore(path)
	if err != nil {
		t.Fatalf("legacy load failed: %v", err)
	}
	if !s.Check("k", "kg", "c/*") {
		t.Errorf("legacy grant was dropped on load")
	}
}
