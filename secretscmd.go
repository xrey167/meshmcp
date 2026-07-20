package main

import (
	"flag"
	"fmt"
	"sort"

	"github.com/xrey167/meshmcp/secrets"
)

// cmdSecrets implements "meshmcp secrets <subcommand>".
func cmdSecrets(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshmcp secrets check --config <file>")
	}
	switch args[0] {
	case "check":
		return secretsCheck(args[1:])
	default:
		return fmt.Errorf("meshmcp secrets: unknown subcommand %q (want: check)", args[0])
	}
}

// secretsCheck validates the secrets configuration of every backend and reports
// which secret names are available — NEVER any values. It is safe to run in CI
// and in front of anyone; a secret value is never printed or logged.
func secretsCheck(args []string) error {
	fs := flag.NewFlagSet("secrets check", flag.ContinueOnError)
	cfgPath := fs.String("config", "meshmcp.yaml", "meshmcp config to check")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}

	found := 0
	for _, b := range cfg.Backends {
		if b.Secrets == nil {
			continue
		}
		found++
		store, err := secretStore(b.Secrets)
		if err != nil {
			return fmt.Errorf("backend %q: %w", b.Name, err)
		}
		fmt.Printf("backend %q: %d grant(s)\n", b.Name, len(b.Secrets.Grants))
		if b.Secrets.File != "" {
			// Only a file store can enumerate names (env can't be listed safely).
			fsStore, ferr := secrets.NewFileStore(b.Secrets.File)
			if ferr != nil {
				return fmt.Errorf("backend %q: %w", b.Name, ferr)
			}
			names := fsStore.Names()
			sort.Strings(names)
			fmt.Printf("  file %s: %d secret name(s) available: %v\n", b.Secrets.File, len(names), names)
		}
		if b.Secrets.EnvPrefix != "" {
			fmt.Printf("  env: secrets read from %s* (values never listed)\n", b.Secrets.EnvPrefix)
		}
		_ = store
	}
	if found == 0 {
		fmt.Println("no backends configure secrets")
	}
	return nil
}
