package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/policy"
)

// air init scaffolds a MINIMAL, SAFE, VALID gateway config: deny-by-default
// policy, a gateway-wide hash-chained audit ledger, a mesh identity derived
// from the hostname, and an Air control endpoint so peers can pair. The one
// irreducible secret — the NetBird setup key — is never written to disk; it is
// read from $NB_SETUP_KEY at run time, and its absence is a friendly one-step
// nudge, not a failure.

const (
	// scaffoldFirstPort is the mesh port of the first generated backend;
	// subsequent backends increment from here.
	scaffoldFirstPort = 9101
	// scaffoldControlPort is the Air control endpoint port a peer pairs to.
	scaffoldControlPort = 9600
	// scaffoldAuditLog is the default gateway-wide audit ledger path.
	scaffoldAuditLog = "./audit.jsonl"
	// scaffoldPairStore is the default paired-peer store path. Its presence
	// turns pairing on, so `air join` / `air pair` work out of the box: peers
	// request access and the operator approves, without hand-editing the allow
	// list. Recognition is identity-only — never an auto-granted tool/control ACL.
	scaffoldPairStore = "./paired.json"
	// scaffoldSetupKeyEnv is the env var the generated config reads the mesh
	// setup key from — the one secret, kept out of the file.
	scaffoldSetupKeyEnv = "NB_SETUP_KEY"
)

// scaffoldOptions are the inputs to building a default config.
type scaffoldOptions struct {
	OutPath    string
	DeviceName string            // explicit override; empty derives from hostname
	Backends   []air.BackendSpec // explicit backends; empty means one example
	// BaseDir, when set, roots the generated identity/audit/pairing files at an
	// absolute location (the canonical data dir) so the mesh identity is stable
	// regardless of the working directory. Empty keeps the historical
	// CWD-relative defaults (and preserves buildScaffoldConfig's purity for
	// tests that pass no BaseDir).
	BaseDir string
}

// buildScaffoldConfig assembles a safe-by-default *Config and a matching
// summary. It is pure: no filesystem, no mesh, no env beyond detecting the
// setup key for the summary. The config it returns round-trips through
// loadConfig and is deny-by-default with audit on.
func buildScaffoldConfig(opts scaffoldOptions) (*Config, air.ScaffoldSummary, error) {
	device := opts.DeviceName
	if device == "" {
		host, _ := os.Hostname()
		device = air.DeviceNameFromHost(host)
	}

	specs := opts.Backends
	if len(specs) == 0 {
		// The default single example backend: a stdio placeholder the user
		// replaces with their real MCP server command. Deny-by-default means it
		// exposes nothing until a rule is added, so a placeholder command is safe.
		specs = []air.BackendSpec{{
			Name:  "example",
			Stdio: []string{"your-mcp-server", "--stdio"},
		}}
	}

	backends := make([]*Backend, 0, len(specs))
	infos := make([]air.BackendInfo, 0, len(specs))
	port := scaffoldFirstPort
	for _, s := range specs {
		b := &Backend{
			Name: s.Name,
			Port: port,
			// Deny-by-default policy with no rules: nothing is callable until the
			// operator opens a hole. This is the firewall's stance and the whole
			// point of a safe scaffold.
			Policy: &policy.Policy{DefaultAllow: false},
		}
		transport := "stdio"
		switch {
		case s.HTTP != "":
			b.HTTP = s.HTTP
			transport = "http"
		default:
			b.Stdio = s.Stdio
		}
		backends = append(backends, b)
		infos = append(infos, air.BackendInfo{Name: s.Name, Port: port, Transport: transport})
		port++
	}

	// Root the identity/audit/pairing files at the canonical data dir when one is
	// given, so the mesh identity is the same no matter which directory a command
	// runs from; otherwise keep the CWD-relative defaults.
	nbConfigPath := "./meshmcp-nb.json"
	auditPath := scaffoldAuditLog
	pairStorePath := scaffoldPairStore
	if opts.BaseDir != "" {
		nbConfigPath = filepath.Join(opts.BaseDir, "meshmcp-nb.json")
		auditPath = filepath.Join(opts.BaseDir, "audit.jsonl")
		pairStorePath = filepath.Join(opts.BaseDir, "paired.json")
	}

	cfg := &Config{
		Mesh: MeshConfig{
			DeviceName:  device,
			SetupKeyEnv: scaffoldSetupKeyEnv,
			ConfigPath:  nbConfigPath, // persist identity: stable mesh IP across restarts
			LogLevel:    "warn",
		},
		// Gateway-wide, tamper-evident audit ledger (one hash chain).
		AuditLog: auditPath,
		// Air control endpoint, present so pairing / air home works. Default-deny:
		// only this device's own identity is granted until the user pairs peers
		// (air join — coming). This keeps the privileged list/steer surface closed
		// to every other peer by default rather than open by omission.
		Control: &ControlConfig{
			Port:  scaffoldControlPort,
			Allow: []string{air.DeviceFQDN(device)}, // only this device until you pair peers
			// Pairing on by default: peers request with `air join`, this device's
			// operator approves with `air pair approve`. Approval recognizes an
			// identity; it never widens Allow above or grants a tool ACL.
			PairStore: pairStorePath,
		},
		Backends: backends,
	}

	summary := air.ScaffoldSummary{
		ConfigPath:    opts.OutPath,
		DeviceName:    device,
		Backends:      infos,
		AuditLog:      auditPath,
		DenyByDefault: true,
		ControlPort:   scaffoldControlPort,
		PairAddress:   air.PairAddress(device, scaffoldControlPort),
		SetupKeyEnv:   scaffoldSetupKeyEnv,
		SetupKeyFound: os.Getenv(scaffoldSetupKeyEnv) != "",
	}
	summary.NextStep = scaffoldNextStep(summary.SetupKeyFound)
	return cfg, summary, nil
}

// scaffoldNextStep is the single next command to print, depending on whether
// the irreducible setup key is already available.
func scaffoldNextStep(keyFound bool) string {
	if keyFound {
		return "air up"
	}
	return "export " + scaffoldSetupKeyEnv + "=<key from your NetBird dashboard>, then air up"
}

// renderScaffoldYAML marshals the REAL Config struct and hands it to the air
// renderer, so the written file can never drift from the schema.
func renderScaffoldYAML(cfg *Config) ([]byte, error) {
	marshaled, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return air.RenderConfigYAML(marshaled)
}

// cmdAirInit implements `air init`.
func cmdAirInit(args []string) error {
	fs := flag.NewFlagSet("air init", flag.ExitOnError)
	out := fs.String("out", defaultConfigPath(), "path to write the generated config")
	force := fs.Bool("force", false, "overwrite an existing config file")
	name := fs.String("name", "", "device name in the mesh (default: meshmcp-<hostname>)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	var backendSpecs stringList
	fs.Var(&backendSpecs, "backend", "backend as name=stdio-cmd or name=http-addr (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	specs, err := parseBackendSpecs(backendSpecs)
	if err != nil {
		return fmt.Errorf("air init: %w", err)
	}

	if _, statErr := os.Stat(*out); statErr == nil && !*force {
		return fmt.Errorf("air init: %s already exists (use --force to overwrite)", *out)
	}

	cfg, summary, err := buildScaffoldConfig(scaffoldOptions{
		OutPath:    *out,
		DeviceName: *name,
		Backends:   specs,
		BaseDir:    scaffoldBaseDir(),
	})
	if err != nil {
		return fmt.Errorf("air init: %w", err)
	}

	data, err := renderScaffoldYAML(cfg)
	if err != nil {
		return fmt.Errorf("air init: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		return fmt.Errorf("air init: create config dir: %w", err)
	}
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		return fmt.Errorf("air init: write %s: %w", *out, err)
	}
	summary.Created = true

	if *asJSON {
		return printJSONValue(summary)
	}
	printScaffoldSummary(summary, true)
	return nil
}

// parseBackendSpecs parses repeated --backend values in order, rejecting
// duplicate names so port assignment and the written config stay deterministic.
func parseBackendSpecs(raw stringList) ([]air.BackendSpec, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	specs := make([]air.BackendSpec, 0, len(raw))
	for _, r := range raw {
		spec, err := air.ParseBackendSpec(r)
		if err != nil {
			return nil, err
		}
		if seen[spec.Name] {
			return nil, fmt.Errorf("backend %q: name is used more than once", spec.Name)
		}
		seen[spec.Name] = true
		specs = append(specs, spec)
	}
	return specs, nil
}

// printJSONValue writes an indented JSON value to stdout.
func printJSONValue(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// printScaffoldSummary renders the calm, done-for-you human summary. When
// created is false it is the `air up` status header for an existing config.
func printScaffoldSummary(s air.ScaffoldSummary, created bool) {
	if created {
		fmt.Println(okLine("wrote %s", bold(s.ConfigPath)))
	} else {
		fmt.Println(okLine("using %s", bold(s.ConfigPath)))
	}
	fmt.Println()
	fmt.Println(bold("  Safe by default"))
	fmt.Println("    " + green("●") + " deny-by-default — no tool is reachable until you grant it")
	fmt.Println("    " + green("●") + " audit on — " + dim(s.AuditLog))
	fmt.Println()
	fmt.Println(bold("  Identity"))
	fmt.Println("    device   " + cyan(s.DeviceName))
	for _, b := range s.Backends {
		fmt.Printf("    backend  %s %s\n", b.Name, dim(fmt.Sprintf("(%s, port %d)", b.Transport, b.Port)))
	}
	fmt.Println("    pair at  " + cyan(s.PairAddress) + dim("  — peers request access with `air join`; you approve with `air pair approve`"))
	fmt.Println()
	if s.SetupKeyFound {
		fmt.Println("  " + green("✓") + " mesh key detected " + dim("($"+s.SetupKeyEnv+")"))
		fmt.Println()
		fmt.Println("  Next:  " + bold("air up"))
	} else {
		fmt.Println("  " + amber("!") + " one step left — set your mesh setup key:")
		fmt.Println("      " + bold("export "+s.SetupKeyEnv+"=<key from your NetBird dashboard>"))
		fmt.Println("      " + bold("air up"))
	}
}
