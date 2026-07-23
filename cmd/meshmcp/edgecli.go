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
	case "approve", "deny", "revoke":
		id := fs.Arg(0)
		if id == "" {
			return fmt.Errorf("edge clients %s: a client_id argument is required", sub)
		}
		var rec edge.ClientRecord
		switch sub {
		case "approve":
			rec, err = store.Approve(id, *by)
		case "deny":
			rec, err = store.Deny(id, *by)
		case "revoke":
			rec, err = store.Revoke(id, *by)
		}
		if err != nil {
			return fmt.Errorf("edge clients %s: %w", sub, err)
		}
		fmt.Printf("client %s is now %s\n", rec.ClientID, rec.Status)
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

// defaultApprover derives a best-effort operator identity for decision records.
func defaultApprover() string {
	if u := os.Getenv("USER"); u != "" {
		return "cli:" + u
	}
	return "cli:operator"
}
