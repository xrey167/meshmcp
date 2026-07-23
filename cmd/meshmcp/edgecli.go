package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/xrey167/meshmcp/edge"
)

// cmdEdgeClients is the operator surface for reviewing and deciding hosted-client
// registrations: `meshmcp edge clients <list|approve|deny|revoke> --state <dir>`.
// It operates directly on the edge state directory (the daemon reads the same
// files on its next request), the same file-coordination pattern the Air pairing
// and co-sign approver CLIs use.
func cmdEdgeClients(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshmcp edge clients <list|approve|deny|revoke> --state <dir> [client_id]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("edge clients "+sub, flag.ExitOnError)
	stateDir := fs.String("state", "", "edge state_dir (as in edge.yaml)")
	by := fs.String("by", defaultApprover(), "operator identity recorded on the decision")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *stateDir == "" {
		return fmt.Errorf("edge clients: --state <dir> is required")
	}
	store, err := edge.NewClientStore(filepath.Join(*stateDir, "clients"), time.Now)
	if err != nil {
		return err
	}

	switch sub {
	case "list":
		recs, err := store.List()
		if err != nil {
			return err
		}
		printClientTable(recs)
		return nil
	case "approve", "deny":
		id := fs.Arg(0)
		if id == "" {
			return fmt.Errorf("edge clients %s: a client_id argument is required", sub)
		}
		var rec edge.ClientRecord
		if sub == "approve" {
			rec, err = store.Approve(id, *by)
		} else {
			rec, err = store.Deny(id, *by)
		}
		if err != nil {
			return fmt.Errorf("edge clients %s: %w", sub, err)
		}
		fmt.Printf("client %s is now %s\n", rec.ClientID, rec.Status)
		return nil
	case "revoke":
		id := fs.Arg(0)
		if id == "" {
			return fmt.Errorf("edge clients revoke: a client_id argument is required")
		}
		// Full cascade: mark revoked, delete tokens, revoke their capabilities.
		n, err := edge.RevokeClientState(*stateDir, id, *by)
		if err != nil {
			return fmt.Errorf("edge clients revoke: %w", err)
		}
		fmt.Printf("client %s revoked; %d token(s) invalidated and their capabilities revoked\n", id, n)
		return nil
	default:
		return fmt.Errorf("edge clients: unknown subcommand %q (want list | approve | deny | revoke)", sub)
	}
}

func printClientTable(recs []edge.ClientRecord) {
	if len(recs) == 0 {
		fmt.Println("no registered clients")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT_ID\tSTATUS\tNAME\tREGISTERED\tMODE")
	for _, r := range recs {
		name := r.ClientName
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ClientID, r.Status, name, r.CreatedAt.Format(time.RFC3339), r.RegistrationMode)
	}
	_ = tw.Flush()
}

// cmdEdgeAuthz is the operator surface for deciding in-flight authorization
// requests: `meshmcp edge authz <list|approve|deny> --state <dir> [request_id]`.
func cmdEdgeAuthz(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshmcp edge authz <list|approve|deny> --state <dir> [request_id]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("edge authz "+sub, flag.ExitOnError)
	stateDir := fs.String("state", "", "edge state_dir (as in edge.yaml)")
	by := fs.String("by", defaultApprover(), "operator identity recorded on the decision")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *stateDir == "" {
		return fmt.Errorf("edge authz: --state <dir> is required")
	}
	store, err := edge.NewAuthzStore(filepath.Join(*stateDir, "authz"), time.Now)
	if err != nil {
		return err
	}

	switch sub {
	case "list":
		pend, err := store.ListPending()
		if err != nil {
			return err
		}
		if len(pend) == 0 {
			fmt.Println("no pending authorization requests")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "REQUEST_ID\tCLIENT_ID\tNAME\tREQUESTED")
		for _, p := range pend {
			name := p.ClientName
			if name == "" {
				name = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.RequestID, p.ClientID, name, p.CreatedAt.Format(time.RFC3339))
		}
		return tw.Flush()
	case "approve", "deny":
		id := fs.Arg(0)
		if id == "" {
			return fmt.Errorf("edge authz %s: a request_id argument is required", sub)
		}
		if sub == "approve" {
			err = store.Approve(id, *by)
		} else {
			err = store.Deny(id, *by)
		}
		if err != nil {
			return fmt.Errorf("edge authz %s: %w", sub, err)
		}
		fmt.Printf("authorization request %s is now %sd\n", id, sub)
		return nil
	default:
		return fmt.Errorf("edge authz: unknown subcommand %q (want list | approve | deny)", sub)
	}
}

// cmdEdgeTokens is the operator surface for reviewing and revoking issued
// tokens: `meshmcp edge tokens <list|revoke> --state <dir> [--family id | --client id]`.
func cmdEdgeTokens(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshmcp edge tokens <list|revoke> --state <dir> [--family id | --client id]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("edge tokens "+sub, flag.ExitOnError)
	stateDir := fs.String("state", "", "edge state_dir (as in edge.yaml)")
	family := fs.String("family", "", "token family id to revoke")
	client := fs.String("client", "", "client id whose tokens to revoke")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *stateDir == "" {
		return fmt.Errorf("edge tokens: --state <dir> is required")
	}

	switch sub {
	case "list":
		toks, err := edge.ListTokens(*stateDir)
		if err != nil {
			return err
		}
		if len(toks) == 0 {
			fmt.Println("no live access tokens")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "CLIENT_ID\tFAMILY\tCAP_ID\tEXPIRES")
		for _, tk := range toks {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", tk.ClientID, tk.FamilyID, tk.CapID, tk.ExpiresAt.Format(time.RFC3339))
		}
		return tw.Flush()
	case "revoke":
		switch {
		case *family != "":
			n, err := edge.RevokeFamilyState(*stateDir, *family)
			if err != nil {
				return err
			}
			fmt.Printf("token family %s revoked; %d token(s) invalidated\n", *family, n)
			return nil
		case *client != "":
			n, err := edge.RevokeClientState(*stateDir, *client, defaultApprover())
			if err != nil {
				return err
			}
			fmt.Printf("client %s tokens revoked; %d token(s) invalidated\n", *client, n)
			return nil
		default:
			return fmt.Errorf("edge tokens revoke: pass --family <id> or --client <id>")
		}
	default:
		return fmt.Errorf("edge tokens: unknown subcommand %q (want list | revoke)", sub)
	}
}

// defaultApprover derives a best-effort operator identity for decision records.
func defaultApprover() string {
	if u := os.Getenv("USER"); u != "" {
		return "cli:" + u
	}
	return "cli:operator"
}
