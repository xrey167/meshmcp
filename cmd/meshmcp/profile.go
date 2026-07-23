package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// A profile is the CLI's small pocket of remembered defaults, so an operator
// who always talks to the same gateway does not have to repeat its
// control-ip:port on every command. It lives at <dataDir>/profile.yaml (Phase B's
// canonical data dir), is the CLI's second config mutator after `air init`, and
// holds nothing secret — only a default control address and, optionally, a
// device name. Resolution precedence is explicit flag/positional → $MESHMCP_CONTROL
// → profile, so a one-off override never has to fight a saved default.

// profileSchemaVersion is the on-disk format version of profile.yaml. A profile
// from a newer build is refused rather than misread (consistent with the durable
// stores' reject-newer discipline).
const profileSchemaVersion = 1

// profileFileName is the profile basename inside the data dir.
const profileFileName = "profile.yaml"

// profile is the remembered-defaults document.
type profile struct {
	SchemaVersion int    `yaml:"schema_version,omitempty"`
	Control       string `yaml:"control,omitempty"`
	DeviceName    string `yaml:"device_name,omitempty"`
}

// profilePath resolves <dataDir>/profile.yaml WITHOUT creating the data dir, so
// merely reading a default has no filesystem side effect. It returns "" when the
// data dir cannot be resolved (e.g. no HOME), which callers treat as "no
// profile".
func profilePath() string {
	dir, err := dataDirPath()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, profileFileName)
}

// loadProfile reads the saved profile, returning an empty profile when none
// exists. A present-but-unparseable or newer-version profile is a hard error, so
// a corrupt or too-new file is surfaced rather than silently ignored.
func loadProfile() (profile, error) {
	path := profilePath()
	if path == "" {
		return profile{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return profile{}, nil
		}
		return profile{}, fmt.Errorf("profile: read %s: %w", path, err)
	}
	var p profile
	if err := yaml.Unmarshal(b, &p); err != nil {
		return profile{}, fmt.Errorf("profile: parse %s: %w", path, err)
	}
	if p.SchemaVersion > profileSchemaVersion {
		return profile{}, fmt.Errorf("profile: %s has schema version %d, newer than this build supports (%d) — upgrade meshmcp", path, p.SchemaVersion, profileSchemaVersion)
	}
	return p, nil
}

// saveProfile writes the profile to <dataDir>/profile.yaml (0600), creating the
// data dir if needed. It stamps the current schema version.
func saveProfile(p profile) error {
	dir, err := dataDir()
	if err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	p.SchemaVersion = profileSchemaVersion
	b, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("profile: marshal: %w", err)
	}
	path := filepath.Join(dir, profileFileName)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("profile: write %s: %w", path, err)
	}
	return nil
}

// resolveControl returns the control address to use, in precedence order:
// an explicit value (a flag or positional) wins; then $MESHMCP_CONTROL; then the
// saved profile's default. It returns "" when none is set, so a caller can emit
// a command-appropriate usage error. A profile that fails to load is treated as
// absent (best-effort) — resolution never fails a command on a malformed
// profile; that surfaces via `profile show`.
func resolveControl(explicit string) string {
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		return explicit
	}
	if env := strings.TrimSpace(os.Getenv("MESHMCP_CONTROL")); env != "" {
		return env
	}
	if p, err := loadProfile(); err == nil {
		return strings.TrimSpace(p.Control)
	}
	return ""
}

// noControlHint is appended to a command's usage when neither a positional nor a
// remembered default is available, pointing at the one-time fix.
const noControlHint = "\n  no control address given and none saved — pass <control-ip:port>, set $MESHMCP_CONTROL, or run `meshmcp profile set --control <addr>`"

// resolveControlPositional resolves the control address for a command whose
// control endpoint is a single optional trailing positional. It accepts an
// explicit fs.Arg(0), else falls back to $MESHMCP_CONTROL then the saved profile,
// so a configured operator can omit it. usage is the command's own usage line,
// used verbatim on the error paths.
func resolveControlPositional(narg int, arg0 string, usage string) (string, error) {
	switch narg {
	case 0:
		if addr := resolveControl(""); addr != "" {
			return addr, nil
		}
		return "", errors.New(usage + noControlHint)
	case 1:
		return arg0, nil
	default:
		return "", errors.New(usage)
	}
}

// cmdProfile implements `meshmcp profile <set|show|clear>` — the CLI's writer for
// remembered defaults.
func cmdProfile(args []string) error {
	if len(args) == 0 {
		return cmdProfileShow(nil)
	}
	switch args[0] {
	case "set":
		return cmdProfileSet(args[1:])
	case "show":
		return cmdProfileShow(args[1:])
	case "clear":
		return cmdProfileClear(args[1:])
	case "-h", "--help", "help":
		fmt.Println("usage: meshmcp profile <set|show|clear>")
		fmt.Println("  set    --control <ip:port> [--device <name>]   save default(s)")
		fmt.Println("  show                                           print the saved profile")
		fmt.Println("  clear                                          remove the saved profile")
		return nil
	default:
		return fmt.Errorf("profile: unknown subcommand %q (want set|show|clear)", args[0])
	}
}

// cmdProfileSet writes (or updates) the saved defaults. It merges onto the
// existing profile so setting one field leaves the others intact.
func cmdProfileSet(args []string) error {
	fs := flag.NewFlagSet("profile set", flag.ExitOnError)
	control := fs.String("control", "", "default control-ip:port for commands that omit it")
	device := fs.String("device", "", "default device name")
	asJSON := fs.Bool("json", false, "print the saved profile as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *control == "" && *device == "" {
		return errors.New("profile set: nothing to set — pass --control and/or --device")
	}

	p, err := loadProfile()
	if err != nil {
		return err
	}
	if *control != "" {
		p.Control = strings.TrimSpace(*control)
	}
	if *device != "" {
		p.DeviceName = strings.TrimSpace(*device)
	}
	if err := saveProfile(p); err != nil {
		return err
	}
	if *asJSON {
		return printJSONValue(p)
	}
	fmt.Println(okLine("saved %s", bold(profilePath())))
	printProfile(p)
	return nil
}

// cmdProfileShow prints the saved profile (or a friendly note when none exists).
func cmdProfileShow(args []string) error {
	fs := flag.NewFlagSet("profile show", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the profile as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := loadProfile()
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSONValue(p)
	}
	path := profilePath()
	if p == (profile{}) {
		if path == "" {
			fmt.Println(dim("no profile (data dir unresolved)"))
		} else {
			fmt.Println(dim("no saved profile at " + path))
			fmt.Println(dim("  set one with `meshmcp profile set --control <ip:port>`"))
		}
		return nil
	}
	fmt.Println(okLine("profile %s", bold(path)))
	printProfile(p)
	return nil
}

// cmdProfileClear removes the saved profile.
func cmdProfileClear(args []string) error {
	fs := flag.NewFlagSet("profile clear", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := profilePath()
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			fmt.Println(dim("no saved profile to clear"))
			return nil
		}
		return fmt.Errorf("profile clear: %w", err)
	}
	fmt.Println(okLine("cleared %s", bold(path)))
	return nil
}

// printProfile renders the profile's fields, showing which are set.
func printProfile(p profile) {
	control := p.Control
	if control == "" {
		control = dim("(unset)")
	} else {
		control = cyan(control)
	}
	fmt.Println("  control  " + control)
	if p.DeviceName != "" {
		fmt.Println("  device   " + cyan(p.DeviceName))
	}
}
