package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// cmdApprove records a human co-sign for a require_cosign tool call. A human
// identity on the mesh runs this to authorize a privileged call the gateway is
// holding; the approval lands in the shared cosign_store directory the gateway
// watches. This is the human-in-the-loop half of the agent firewall.
func cmdApprove(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	store := fs.String("store", "", "cosign store directory (must match the backend's cosign_store)")
	approver := fs.String("approver", "", "the approving operator identity (pubkey or fqdn)")
	configPath := fs.String("config", "", "gateway config, to validate --approver against its operators")
	revoke := fs.Bool("revoke", false, "revoke an existing approval instead of granting one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *store == "" {
		return fmt.Errorf("meshmcp approve: --store <dir> is required")
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: meshmcp approve --store <dir> [--config <cfg>] [--approver <id>] [--revoke] <peer-fqdn> <tool>")
	}
	peer, tool := fs.Arg(0), fs.Arg(1)

	if *revoke {
		if err := policy.Revoke(*store, peer, tool); err != nil {
			return err
		}
		fmt.Printf("revoked co-sign: %s may no longer call %q\n", peer, tool)
		return nil
	}

	who, err := resolveApprover(*approver, *configPath)
	if err != nil {
		return err
	}
	if err := policy.Grant(*store, peer, tool, who, time.Now()); err != nil {
		return err
	}
	fmt.Printf("co-signed: %s may call %q (approver: %s)\n", peer, tool, who)
	return nil
}

// resolveApprover determines the approver identity recorded on a co-sign, being
// honest about how much it can vouch for it:
//
//   - When a config with an operators list is given, --approver is REQUIRED and
//     must match a configured operator (pubkey or fqdn) — so the recorded
//     approver is a real, enrolled operator identity, not a self-asserted string.
//   - Otherwise (no operators to bind against), it falls back to an explicitly
//     UNVERIFIED local-OS-user label ("os:<user>"), so the audit record never
//     misrepresents a machine-local username as a mesh identity.
func resolveApprover(approver, configPath string) (string, error) {
	approver = strings.TrimSpace(approver)
	if configPath != "" {
		cfg, err := loadConfig(configPath)
		if err != nil {
			return "", fmt.Errorf("approve: %w", err)
		}
		if len(cfg.Operators) > 0 {
			if approver == "" {
				return "", fmt.Errorf("approve: --approver is required and must be one of the configured operators (see `air operator list`)")
			}
			if !newACL(operatorPatterns(cfg.Operators)).allows(approver, approver) {
				return "", fmt.Errorf("approve: %q is not a configured operator (add it with `air operator add`)", approver)
			}
			return approver, nil
		}
	}
	if approver != "" {
		return approver, nil
	}
	return osUserLabel(), nil
}

// osUserLabel returns an explicitly-unverified label for the local OS user, so a
// co-sign made without an operator binding is not dressed up as a mesh identity.
func osUserLabel() string {
	if env := strings.TrimSpace(os.Getenv("USER")); env != "" {
		return "os:" + env
	}
	if env := strings.TrimSpace(os.Getenv("USERNAME")); env != "" {
		return "os:" + env
	}
	return "os:unknown"
}
