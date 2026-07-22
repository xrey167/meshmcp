package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/air"
)

func TestLoadCatalogSnapshotRejectsHostileAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	data := []byte(`{"service":"meshmcp","version":"1","endpoints":[{"name":"fs","address":"host\u001b[2J:9101","transport":"stdio"}]}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCatalogSnapshot(path); err == nil || !strings.Contains(err.Error(), "not a valid catalog") {
		t.Fatalf("terminal-hostile snapshot accepted or wrong error: %v", err)
	}
}

func TestSaveCatalogSnapshotIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	cat := air.Catalog{
		Service: "meshmcp",
		Version: "1",
		Endpoints: []air.CatalogEntry{{
			Name: "fs", Address: "host:9101", Transport: air.TransportStdio,
		}},
	}
	if err := saveCatalogSnapshot(path, cat); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
		t.Fatalf("snapshot mode = %04o, want 0600", got)
	}
}
