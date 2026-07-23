package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestUninstallDryRunLeavesFiles proves the default (no --yes) is a dry run: it
// enumerates state but deletes nothing.
func TestUninstallDryRunLeavesFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MESHMCP_HOME", t.TempDir())
	nb := filepath.Join(dir, "meshmcp-nb.json")
	audit := filepath.Join(dir, "audit.jsonl")
	for _, p := range []string{nb, audit} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := writeConfig(t, `
mesh:
  device_name: gw
  config_path: `+nb+`
audit_log: `+audit+`
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
`)
	if err := cmdUninstall([]string{"--config", cfg}); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	// Nothing was deleted.
	for _, p := range []string{nb, audit, cfg} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("dry run deleted %s: %v", p, err)
		}
	}
}

// TestUninstallYesRemovesState proves --yes removes the declared state, including
// the mesh identity and the config file itself.
func TestUninstallYesRemovesState(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MESHMCP_HOME", t.TempDir())
	nb := filepath.Join(dir, "meshmcp-nb.json")
	audit := filepath.Join(dir, "audit.jsonl")
	cosign := filepath.Join(dir, "cosign")
	for _, p := range []string{nb, audit} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(cosign, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, `
mesh:
  device_name: gw
  config_path: `+nb+`
audit_log: `+audit+`
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
    cosign_store: `+cosign+`
    policy:
      default_allow: false
`)
	if err := cmdUninstall([]string{"--config", cfg, "--yes"}); err != nil {
		t.Fatalf("uninstall --yes: %v", err)
	}
	for _, p := range []string{nb, audit, cosign, cfg} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s to be removed, stat err=%v", p, err)
		}
	}
}

// TestUninstallKeepConfig proves --keep-config removes state but leaves the
// config file.
func TestUninstallKeepConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MESHMCP_HOME", t.TempDir())
	nb := filepath.Join(dir, "meshmcp-nb.json")
	if err := os.WriteFile(nb, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, `
mesh:
  device_name: gw
  config_path: `+nb+`
backends:
  - name: kb
    port: 9101
    stdio: ["echo"]
`)
	if err := cmdUninstall([]string{"--config", cfg, "--yes", "--keep-config"}); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if _, err := os.Stat(nb); !os.IsNotExist(err) {
		t.Errorf("identity should be removed")
	}
	if _, err := os.Stat(cfg); err != nil {
		t.Errorf("--keep-config should leave the config in place: %v", err)
	}
}
