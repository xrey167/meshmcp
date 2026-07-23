package edge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEdgeStoreStampsAndRejectsNewer proves every edge record self-describes its
// format (schema_version is stamped centrally on write) and that a record from a
// newer build is refused on read — fail closed — so an older reader never
// misinterprets a future token/client format.
func TestEdgeStoreStampsAndRejectsNewer(t *testing.T) {
	dir := t.TempDir()
	s, err := NewClientStore(dir, func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	rec, _, err := s.Create("app", []string{"https://example.com/cb"}, RegistrationToken)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	path := filepath.Join(dir, "client-"+rec.ClientID+".json")

	// The record on disk carries the current schema_version even though
	// ClientRecord itself declares no such field (stamped centrally).
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
	if onDisk.SchemaVersion != edgeSchemaVersion {
		t.Errorf("stamped version = %d, want %d", onDisk.SchemaVersion, edgeSchemaVersion)
	}

	// A current-version record reads back fine.
	if _, err := s.Get(rec.ClientID); err != nil {
		t.Fatalf("get current-version record: %v", err)
	}

	// Bump the version beyond what this build supports; the read must refuse.
	bumped := strings.Replace(string(b),
		`"schema_version": 1`, `"schema_version": 2`, 1)
	if bumped == string(b) {
		t.Fatalf("test setup: did not find the version to bump in %s", b)
	}
	if err := os.WriteFile(path, []byte(bumped), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(rec.ClientID); err == nil {
		t.Fatalf("expected reject-newer error from Get, got nil (must fail closed)")
	} else if !strings.Contains(err.Error(), "newer than this build supports") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestEdgeStoreLegacyRecordReads proves a record written before versioning (no
// schema_version key) still reads, so an in-place upgrade does not orphan
// existing clients/tokens.
func TestEdgeStoreLegacyRecordReads(t *testing.T) {
	dir := t.TempDir()
	s, err := NewClientStore(dir, func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	// Hand-write a legacy record with no schema_version key.
	legacy := `{
  "client_id": "edge-legacy",
  "client_name": "old",
  "redirect_uris": ["https://example.com/cb"],
  "token_endpoint_auth_method": "none",
  "registration_mode": "token",
  "status": "approved"
}`
	if err := os.WriteFile(filepath.Join(dir, "client-edge-legacy.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("edge-legacy")
	if err != nil {
		t.Fatalf("legacy record read failed: %v", err)
	}
	if got.ClientID != "edge-legacy" || got.Status != ClientApproved {
		t.Errorf("legacy record decoded wrong: %+v", got)
	}
}
