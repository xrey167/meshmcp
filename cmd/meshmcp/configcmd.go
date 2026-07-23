package main

import (
	"flag"
	"fmt"
)

// cmdConfig implements "meshmcp config <validate|lint>".
func cmdConfig(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshmcp config <validate|lint> --config <file>")
	}
	switch args[0] {
	case "validate":
		return configValidate(args[1:])
	case "lint":
		return configLint(args[1:])
	default:
		return fmt.Errorf("meshmcp config: unknown subcommand %q (want: validate or lint)", args[0])
	}
}

// configValidate loads a config through the full loadConfig path — which now
// compiles every policy glob, parses every window/duration, validates enums,
// secret-grant scope, and DLP rules — and reports the result without joining
// the mesh. Safe to run in CI as a gate.
func configValidate(args []string) error {
	fs := flag.NewFlagSet("config validate", flag.ContinueOnError)
	cfgPath := fs.String("config", "meshmcp.yaml", "config file to validate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("invalid: %w", err)
	}
	nPolicy, nDLP, nSecrets, nCaps := 0, 0, 0, 0
	for _, b := range cfg.Backends {
		if b.Policy != nil {
			nPolicy++
		}
		if len(b.DLP) > 0 {
			nDLP++
		}
		if b.Secrets != nil {
			nSecrets++
		}
		if b.Capabilities != nil {
			nCaps++
		}
	}
	fmt.Printf("OK  %s: %d backend(s) — %d with policy, %d with DLP, %d with secrets, %d with capabilities\n",
		*cfgPath, len(cfg.Backends), nPolicy, nDLP, nSecrets, nCaps)
	return nil
}
