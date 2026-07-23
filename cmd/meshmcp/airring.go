package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/netbirdio/netbird/client/embed"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/session"
)

// Air · Ring — ring a peer (AirDrop's ping / a doorbell / paging).
//
// A ring is a governed, identity-attributed attention request for a HUMAN — not
// an agent instruction (that is `air agent-steer`). It rides the same resumable,
// ACL'd mesh channel as a drop, framed as one newline-JSON notice, and lands on
// the peer's `air listen` terminal (and, later, their served Air page). The
// receiver gates senders deny-by-default, rate-limits per identity, and audits
// every ring into the hash-chained ledger. `air listen` is the receiving end.
//
//	meshmcp air ring --message "build is red, need eyes" [--control <gateway>] <target>
func cmdAirRing(args []string) error {
	fs := flag.NewFlagSet("air ring", flag.ExitOnError)
	o := meshFlags(fs)
	control := fs.String("control", "", "Air control gateway used to resolve a Nearby name, FQDN, or full public key")
	message := fs.String("message", "", "the human-readable message to ring with (required)")
	priority := fs.String("priority", "normal", "priority: normal | urgent")
	approval := fs.String("approval", "", "optional approvals server (mesh-ip:port) for a ring-for-approval link-out")
	from := fs.String("from", "", "optional sender label shown to the recipient (identity is verified separately)")
	id := fs.String("id", "", "optional caller correlation id (audited)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air ring --message <text> [--control <gateway>] [mesh-flags] <target>")
	}
	peerRef := fs.Arg(0)

	n := air.Notice{
		Kind: air.NoticeRing, Message: *message, Priority: *priority,
		Approval: *approval, From: *from, ID: *id,
	}
	if err := n.Validate(); err != nil {
		return fmt.Errorf("air ring: %w", err)
	}

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)
	peer, err := resolveAirTargetOverMesh(context.Background(), client, peerRef, *control, air.ServiceRing)
	if err != nil {
		return fmt.Errorf("air ring: %w", err)
	}

	if err := sendNotice(context.Background(), client, peer, n); err != nil {
		return fmt.Errorf("air ring: %w", err)
	}
	label := "ring"
	if n.Urgent() {
		label = "urgent ring"
	}
	fmt.Println(okLine("%s → %s", label, peer))
	return nil
}

// sendNotice delivers one notice to a peer's listen inbox over an existing mesh
// membership — the same resumable, line-framed channel as a push.
func sendNotice(ctx context.Context, client *embed.Client, addr string, n air.Notice) error {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(air.WriteNotice(pw, n)) }()
	dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", addr) }
	return session.NewClient(dial, log.Printf).Run(ctx, sendStream{r: pr})
}
