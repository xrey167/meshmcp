package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"meshmcp/policy"
)

// cmdApprove records a human co-sign for a require_cosign tool call. A human
// identity on the mesh runs this to authorize a privileged call the gateway is
// holding; the approval lands in the shared cosign_store directory the gateway
// watches. This is the human-in-the-loop half of the agent firewall.
func cmdApprove(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	store := fs.String("store", "", "cosign store directory (must match the backend's cosign_store)")
	approver := fs.String("approver", "", "the approving identity (defaults to the OS user)")
	revoke := fs.Bool("revoke", false, "revoke an existing approval instead of granting one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *store == "" {
		return fmt.Errorf("meshmcp approve: --store <dir> is required")
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: meshmcp approve --store <dir> [--revoke] <peer-fqdn> <tool>")
	}
	peer, tool := fs.Arg(0), fs.Arg(1)

	if *revoke {
		if err := policy.Revoke(*store, peer, tool); err != nil {
			return err
		}
		fmt.Printf("revoked co-sign: %s may no longer call %q\n", peer, tool)
		return nil
	}

	who := *approver
	if who == "" {
		if u, err := os.UserHomeDir(); err == nil {
			who = u
		}
		if env := os.Getenv("USER"); env != "" {
			who = env
		} else if env := os.Getenv("USERNAME"); env != "" {
			who = env
		}
	}
	if err := policy.Grant(*store, peer, tool, who, time.Now()); err != nil {
		return err
	}
	fmt.Printf("co-signed: %s may call %q (approver: %s)\n", peer, tool, who)
	return nil
}
