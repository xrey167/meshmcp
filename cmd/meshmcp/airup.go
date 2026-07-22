package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/xrey167/meshmcp/air"
)

// air up brings the gateway online with one command: it ensures a config
// exists (scaffolding a safe default if not), verifies the one irreducible
// secret is available, prints a calm status header, then hands off to the
// existing serve path. A missing setup key is a friendly one-step nudge, never
// a raw stack trace.

// errSetupKeyMissing signals that the mesh setup key is absent. cmdAirUp
// returns it after printing guidance so the caller sees a clean, actionable
// message rather than a panic.
var errSetupKeyMissing = errors.New("mesh setup key not set")

// cmdAirUp implements `air up [config]`.
func cmdAirUp(args []string) error {
	fs := flag.NewFlagSet("air up", flag.ExitOnError)
	name := fs.String("name", "", "device name when scaffolding a missing config")
	asJSON := fs.Bool("json", false, "print the status as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfgPath := "meshmcp.yaml"
	if fs.NArg() >= 1 {
		cfgPath = fs.Arg(0)
	}

	// Ensure a config exists: scaffold a safe default in place if missing.
	if _, statErr := os.Stat(cfgPath); errors.Is(statErr, os.ErrNotExist) {
		if !*asJSON {
			fmt.Println(dim("no config at " + cfgPath + " — scaffolding a safe default"))
		}
		cfg, summary, err := buildScaffoldConfig(scaffoldOptions{OutPath: cfgPath, DeviceName: *name})
		if err != nil {
			return fmt.Errorf("air up: %w", err)
		}
		data, err := renderScaffoldYAML(cfg)
		if err != nil {
			return fmt.Errorf("air up: %w", err)
		}
		if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
			return fmt.Errorf("air up: write %s: %w", cfgPath, err)
		}
		summary.Created = true
		if !*asJSON {
			printScaffoldSummary(summary, true)
			fmt.Println()
		}
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("air up: %w", err)
	}

	summary := statusFromConfig(cfgPath, cfg)

	// The one irreducible secret: without a mesh setup key we cannot join. Fail
	// with the single next step, not a raw error from deep in startMesh.
	if !summary.SetupKeyFound {
		if *asJSON {
			_ = printJSONValue(summary)
		} else {
			printSetupKeyGuidance(summary)
		}
		return errSetupKeyMissing
	}

	if *asJSON {
		if err := printJSONValue(summary); err != nil {
			return err
		}
	} else {
		printUpStatus(summary)
	}

	// Hand off to the existing gateway entrypoint. This joins the mesh and
	// blocks serving until interrupted.
	return cmdServe([]string{"--config", cfgPath})
}

// statusFromConfig derives an air up status summary from a loaded config,
// reusing the same shape as `air init` so human and JSON output are consistent.
func statusFromConfig(cfgPath string, cfg *Config) air.ScaffoldSummary {
	infos := make([]air.BackendInfo, 0, len(cfg.Backends))
	for _, b := range cfg.Backends {
		transport := "stdio"
		switch {
		case b.HTTP != "":
			transport = "http"
		case b.Remote != nil:
			transport = "remote"
		}
		infos = append(infos, air.BackendInfo{Name: b.Name, Port: b.Port, Transport: transport})
	}
	denyByDefault := true
	for _, b := range cfg.Backends {
		if b.Policy == nil || b.Policy.DefaultAllow {
			denyByDefault = false
			break
		}
	}
	controlPort := 0
	if cfg.Control != nil {
		controlPort = cfg.Control.Port
	}
	s := air.ScaffoldSummary{
		ConfigPath:    cfgPath,
		DeviceName:    cfg.Mesh.DeviceName,
		Backends:      infos,
		AuditLog:      cfg.AuditLog,
		DenyByDefault: denyByDefault,
		ControlPort:   controlPort,
		PairAddress:   air.PairAddress(cfg.Mesh.DeviceName, controlPort),
		SetupKeyEnv:   setupKeyEnvName(cfg.Mesh),
		SetupKeyFound: cfg.Mesh.options().SetupKey != "",
	}
	s.NextStep = scaffoldNextStep(s.SetupKeyFound)
	return s
}

// setupKeyEnvName is the env var a config reads its setup key from.
func setupKeyEnvName(m MeshConfig) string {
	if m.SetupKeyEnv != "" {
		return m.SetupKeyEnv
	}
	return scaffoldSetupKeyEnv
}

// printUpStatus prints the calm "your mesh is coming up" header before serve
// takes over the terminal.
func printUpStatus(s air.ScaffoldSummary) {
	fmt.Println(okLine("bringing up %s", bold(s.DeviceName)))
	audit := "off"
	if s.AuditLog != "" {
		audit = "on (" + s.AuditLog + ")"
	}
	deny := "on"
	if !s.DenyByDefault {
		deny = "off"
	}
	fmt.Printf("  %d backend(s) · audit %s · deny-by-default %s\n", len(s.Backends), audit, deny)
	if s.PairAddress != "" {
		fmt.Println("  pair at  " + cyan(s.PairAddress) + dim("  — peers can request access with `air join` (coming)"))
	}
	fmt.Println(dim("  joining the mesh…"))
}

// printSetupKeyGuidance prints the single next step when the setup key is
// absent — friendly, done-for-you tone, not a stack trace.
func printSetupKeyGuidance(s air.ScaffoldSummary) {
	fmt.Fprintln(os.Stderr, amber("!")+" one step left — your mesh setup key isn't set.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  Get a key from your NetBird dashboard, then:")
	fmt.Fprintln(os.Stderr, "      "+bold("export "+s.SetupKeyEnv+"=<key>"))
	fmt.Fprintln(os.Stderr, "      "+bold("air up"))
}
