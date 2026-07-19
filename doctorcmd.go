package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// cmdDoctor runs local pre-flight checks on a config without joining the mesh
// (S47): it validates the config, confirms each stdio backend's command is
// resolvable, and checks that audit / cosign / session-store directories are
// writable and secrets files are owner-only. It reports every problem it finds
// and exits non-zero if any are fatal — a CI-safe readiness gate.
func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	cfgPath := fs.String("config", "meshmcp.yaml", "config file to check")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("config invalid: %w", err)
	}
	problems := 0
	warn := func(format string, a ...any) { problems++; fmt.Printf("  ✗ "+format+"\n", a...) }
	ok := func(format string, a ...any) { fmt.Printf("  ✓ "+format+"\n", a...) }

	fmt.Printf("meshmcp doctor: %s (%d backends)\n", *cfgPath, len(cfg.Backends))
	for _, b := range cfg.Backends {
		fmt.Printf("backend %q:\n", b.Name)
		if len(b.Stdio) > 0 {
			cmd := b.Stdio[0]
			if _, err := exec.LookPath(cmd); err != nil {
				if _, statErr := os.Stat(cmd); statErr != nil {
					warn("stdio command %q not found (%v)", cmd, statErr)
				} else {
					ok("stdio command %q present", cmd)
				}
			} else {
				ok("stdio command %q resolvable", cmd)
			}
		}
		for label, path := range map[string]string{
			"audit_log": b.AuditLog, "audit_checkpoints": b.AuditCheckpoints,
			"cosign_store": b.CosignStore, "session_store": b.SessionStore,
		} {
			if path == "" {
				continue
			}
			if err := checkWritable(path); err != nil {
				warn("%s %q not writable: %v", label, path, err)
			} else {
				ok("%s %q writable", label, path)
			}
		}
		if b.Secrets != nil && b.Secrets.File != "" {
			if fi, err := os.Stat(b.Secrets.File); err == nil && fi.Mode().Perm()&0o077 != 0 {
				warn("secrets file %q is mode %#o (must be 0600)", b.Secrets.File, fi.Mode().Perm())
			} else if err == nil {
				ok("secrets file %q is owner-only", b.Secrets.File)
			}
		}
	}
	fmt.Println()
	if problems > 0 {
		return fmt.Errorf("%d problem(s) found", problems)
	}
	fmt.Println("all checks passed")
	return nil
}

// checkWritable confirms a file path's directory exists and is writable by
// creating (and removing) a probe file.
func checkWritable(path string) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if fi, err := os.Stat(dir); err != nil {
		return err
	} else if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	probe := filepath.Join(dir, ".meshmcp-doctor-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	return os.Remove(probe)
}
