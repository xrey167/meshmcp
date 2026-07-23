package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveControlPrecedence proves explicit > $MESHMCP_CONTROL > profile, and
// that an empty result is returned when nothing is set (so a caller can emit its
// own usage error).
func TestResolveControlPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MESHMCP_HOME", home)
	t.Setenv("MESHMCP_CONTROL", "")

	// Nothing set → empty.
	if got := resolveControl(""); got != "" {
		t.Errorf("with nothing set, resolveControl = %q, want empty", got)
	}

	// Profile only.
	if err := saveProfile(profile{Control: "10.0.0.1:9600"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := resolveControl(""); got != "10.0.0.1:9600" {
		t.Errorf("profile fallback = %q, want 10.0.0.1:9600", got)
	}

	// Env overrides profile.
	t.Setenv("MESHMCP_CONTROL", "10.0.0.2:9600")
	if got := resolveControl(""); got != "10.0.0.2:9600" {
		t.Errorf("env override = %q, want 10.0.0.2:9600", got)
	}

	// Explicit overrides both.
	if got := resolveControl("10.0.0.3:9600"); got != "10.0.0.3:9600" {
		t.Errorf("explicit override = %q, want 10.0.0.3:9600", got)
	}
}

// TestResolveControlPositional proves the positional resolver: an explicit
// positional is returned as-is; a missing one falls back to the profile; and
// with neither a default nor a positional it errors with the usage line.
func TestResolveControlPositional(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MESHMCP_HOME", home)
	t.Setenv("MESHMCP_CONTROL", "")

	// Explicit positional wins even with no default.
	if got, err := resolveControlPositional(1, "explicit:1", "usage: x"); err != nil || got != "explicit:1" {
		t.Errorf("explicit positional: got %q err %v", got, err)
	}

	// No positional, no default → error carrying the usage line.
	if _, err := resolveControlPositional(0, "", "usage: meshmcp air sessions <control>"); err == nil {
		t.Errorf("expected error when no positional and no default")
	} else if got := err.Error(); !strings.Contains(got, "usage: meshmcp air sessions") {
		t.Errorf("error missing usage line: %q", got)
	}

	// No positional, but a saved default → the default.
	if err := saveProfile(profile{Control: "saved:9600"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got, err := resolveControlPositional(0, "", "usage: x"); err != nil || got != "saved:9600" {
		t.Errorf("default fallback: got %q err %v", got, err)
	}

	// Too many positionals → error.
	if _, err := resolveControlPositional(2, "a", "usage: x"); err == nil {
		t.Errorf("expected error with 2 positionals")
	}
}

// TestProfileSetShowClearRoundTrip proves the CLI writer persists and merges,
// show reads it back, and clear removes it.
func TestProfileSetShowClearRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MESHMCP_HOME", home)

	if err := cmdProfile([]string{"set", "--control", "10.0.0.9:9600"}); err != nil {
		t.Fatalf("profile set: %v", err)
	}
	p, err := loadProfile()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if p.Control != "10.0.0.9:9600" {
		t.Errorf("control not saved: %+v", p)
	}
	if p.SchemaVersion != profileSchemaVersion {
		t.Errorf("schema version = %d, want %d", p.SchemaVersion, profileSchemaVersion)
	}

	// Setting device merges without clobbering control.
	if err := cmdProfile([]string{"set", "--device", "gw-1"}); err != nil {
		t.Fatalf("profile set device: %v", err)
	}
	p, _ = loadProfile()
	if p.Control != "10.0.0.9:9600" || p.DeviceName != "gw-1" {
		t.Errorf("merge lost a field: %+v", p)
	}

	// Clear removes it.
	if err := cmdProfile([]string{"clear"}); err != nil {
		t.Fatalf("profile clear: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, profileFileName)); !os.IsNotExist(statErr) {
		t.Errorf("profile file still present after clear: %v", statErr)
	}
}

// TestProfileRejectsNewerVersion proves a profile from a newer build is refused
// on load, consistent with the durable stores' reject-newer discipline.
func TestProfileRejectsNewerVersion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MESHMCP_HOME", home)
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	newer := "schema_version: 2\ncontrol: 10.0.0.1:9600\n"
	if err := os.WriteFile(filepath.Join(home, profileFileName), []byte(newer), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile(); err == nil {
		t.Fatalf("expected reject-newer error, got nil")
	} else if !strings.Contains(err.Error(), "newer than this build supports") {
		t.Errorf("unexpected error: %v", err)
	}
}
