package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegistryStampsAndSkipsNewer proves a registration self-describes its
// format and that a newer-format entry is skipped on lookup (discovery state is
// tolerant, like an unreadable file) rather than failing the whole lookup.
func TestRegistryStampsAndSkipsNewer(t *testing.T) {
	dir := t.TempDir()
	r, err := NewFileRegistry(dir)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := r.Register("kg", "10.0.0.1:9101"); err != nil {
		t.Fatalf("register: %v", err)
	}

	// The written file carries the current version.
	files, _ := os.ReadDir(dir)
	var path string
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".json") {
			path = filepath.Join(dir, f.Name())
		}
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
	if onDisk.SchemaVersion != registrySchemaVersion {
		t.Errorf("stamped version = %d, want %d", onDisk.SchemaVersion, registrySchemaVersion)
	}

	// A second, newer-format registration is skipped on lookup while the current
	// one is still discovered — the lookup does not fail whole.
	newer := `{"schema_version": 2, "name": "kg", "addr": "10.0.0.2:9101"}`
	if err := os.WriteFile(filepath.Join(dir, "kg_newer.json"), []byte(newer), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := r.Lookup()
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	addrs := got["kg"]
	if len(addrs) != 1 || addrs[0] != "10.0.0.1:9101" {
		t.Errorf("lookup = %v, want only the current-version addr (newer skipped)", addrs)
	}
}

// TestRegistryLegacyEntryLoads proves a pre-versioning registration (no
// schema_version key) is still discovered.
func TestRegistryLegacyEntryLoads(t *testing.T) {
	dir := t.TempDir()
	r, err := NewFileRegistry(dir)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	legacy := `{"name": "web", "addr": "10.0.0.9:3001"}`
	if err := os.WriteFile(filepath.Join(dir, "web_legacy.json"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := r.Lookup()
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(got["web"]) != 1 || got["web"][0] != "10.0.0.9:3001" {
		t.Errorf("legacy entry not discovered: %v", got)
	}
}
