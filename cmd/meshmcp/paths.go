package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// This file gives meshmcp a single canonical per-user data directory, so state
// that must be stable across runs — above all the WireGuard identity — no longer
// lives at a CWD-relative path. Previously `air up` from a different directory
// scaffolded a fresh ./meshmcp-nb.json and silently forked a second mesh
// identity (and a second, empty audit ledger). Rooting the scaffold's identity,
// audit, and pairing files at dataDir() makes the identity location-independent.

// dataDirPath resolves meshmcp's per-user data directory WITHOUT creating it:
// $MESHMCP_HOME when set, else <os.UserConfigDir>/meshmcp (e.g. ~/.config/meshmcp
// on Linux, ~/Library/Application Support/meshmcp on macOS, %AppData%\meshmcp on
// Windows). It errors only when neither is resolvable (e.g. no HOME).
func dataDirPath() (string, error) {
	base := os.Getenv("MESHMCP_HOME")
	if base == "" {
		cfg, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("resolve user config dir: %w", err)
		}
		base = filepath.Join(cfg, "meshmcp")
	}
	return base, nil
}

// dataDir resolves the per-user data directory and creates it 0700. Use it only
// when about to write there (scaffolding); use dataDirPath for read-only
// discovery so merely resolving a default path has no filesystem side effect.
func dataDir() (string, error) {
	base, err := dataDirPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", fmt.Errorf("create data dir %s: %w", base, err)
	}
	return base, nil
}

// scaffoldBaseDir returns the directory a fresh scaffold should root its
// identity/audit/pairing files in — the canonical data dir when resolvable, or
// "" to fall back to the historical CWD-relative defaults.
func scaffoldBaseDir() string {
	dir, err := dataDir()
	if err != nil {
		return ""
	}
	return dir
}

// defaultConfigName is the config file basename used both in the CWD (for
// back-compat) and inside the data dir.
const defaultConfigName = "meshmcp.yaml"

// defaultConfigPath resolves the config path a command uses when none is given.
// It prefers an existing ./meshmcp.yaml in the current directory (preserving
// every existing workflow that runs meshmcp beside its config), then a config
// in the canonical data dir, and otherwise defaults to the data-dir path (so a
// first run scaffolds into a stable, location-independent home).
func defaultConfigPath() string {
	if _, err := os.Stat(defaultConfigName); err == nil {
		return defaultConfigName
	}
	dir, err := dataDir()
	if err != nil {
		return defaultConfigName
	}
	return filepath.Join(dir, defaultConfigName)
}
