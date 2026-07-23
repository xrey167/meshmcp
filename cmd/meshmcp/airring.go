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
	"strings"
	"time"

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
// With a `group:<name>` target the ring fans out to every present member of an
// operator-defined group: the roster is resolved server-side (GET /v1/groups),
// then the EXISTING single-notice delivery runs once per member, so each ring
// still lands on that member's own deny-by-default `air listen` gate with its
// own local audit record. A group is name resolution, never authorization.
//
//	meshmcp air ring --message "build is red, need eyes" [--control <gateway>] <target>
//	meshmcp air ring --control <gateway> --message "eyes please" group:oncall [--json]
func cmdAirRing(args []string) error {
	fs := flag.NewFlagSet("air ring", flag.ExitOnError)
	o := meshFlags(fs)
	control := fs.String("control", "", "Air control gateway used to resolve a Nearby name, FQDN, full public key, or group:<name>")
	message := fs.String("message", "", "the human-readable message to ring with (required)")
	priority := fs.String("priority", "normal", "priority: normal | urgent")
	approval := fs.String("approval", "", "optional approvals server (mesh-ip:port) for a ring-for-approval link-out")
	from := fs.String("from", "", "optional sender label shown to the recipient (identity is verified separately)")
	id := fs.String("id", "", "optional caller correlation id (audited)")
	asJSON := fs.Bool("json", false, "group mode only: print the air.fanout-result/v1 envelope instead of per-member lines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air ring --message <text> [--control <gateway>] [mesh-flags] <target | group:<name>>")
	}
	peerRef := fs.Arg(0)
	// Reserve the group: prefix before any presence resolution, so a card
	// named "group:x" can never shadow the fan-out grammar (fail closed).
	group, isGroup, err := parseGroupSelector(peerRef)
	if err != nil {
		return fmt.Errorf("air ring: %w", err)
	}
	if *asJSON && !isGroup {
		return errors.New("air ring: --json is only supported with a group:<name> target")
	}

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

	if isGroup {
		ctx := context.Background()
		source := func(ctx context.Context, g string) (airGroupMembers, error) {
			return fetchAirGroup(ctx, meshDialHTTP(client, strings.TrimSpace(*control)), g)
		}
		members, unmatched, err := resolveAirGroupMembers(ctx, group, *control, air.ServiceRing, source)
		if err != nil {
			return fmt.Errorf("air ring: %w", err)
		}
		res, err := ringGroupFanout(ctx, group, members, unmatched, func(ctx context.Context, addr string) error {
			// Bound each member's delivery so one unreachable inbox cannot
			// stall the rest of the loop (matches the control client timeout).
			ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			return sendNotice(ctx, client, addr, n)
		})
		if err != nil {
			return fmt.Errorf("air ring: %w", err)
		}
		return reportFanout(res, *asJSON)
	}

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

// ringGroupFanout delivers one ring per resolved member, SEQUENTIALLY in
// server resolution order, through the injected single-notice delivery — the
// unchanged path, so each ring still enters the receiver's own deny-by-default
// listen gate, which audits locally on arrival. A member's skip or failure
// never stops the loop. Honesty note: the sender usually cannot distinguish a
// receiver's deny from a network failure, so undelivered rings report `failed`
// with the transport reason and the receiver's ledger stays the authoritative
// deny record (the address is routing metadata; receiver policy is authority).
func ringGroupFanout(ctx context.Context, group string, members []groupMember, unmatched []string, deliver func(ctx context.Context, addr string) error) (air.FanoutResult, error) {
	out := make([]air.FanoutMember, 0, len(members))
	for _, m := range members {
		fm := air.FanoutMember{
			Recipient: air.FanoutRecipient{
				Name: m.Presence.Name, FQDN: m.Presence.FQDN, PublicKey: m.Presence.PublicKey,
				Service: air.ServiceRing, Address: m.Address,
			},
			Time: time.Now().UTC().Format(time.RFC3339Nano),
		}
		switch {
		case m.SkipReason != "":
			fm.Status, fm.Reason = air.FanoutSkipped, m.SkipReason
		default:
			if err := deliver(ctx, m.Address); err != nil {
				fm.Status, fm.Reason = air.FanoutFailed, singleLineReason(err.Error())
			} else {
				fm.Status = air.FanoutDelivered
			}
		}
		out = append(out, fm)
	}
	return air.NewFanoutResult(group, air.FanoutActionRing, out, unmatched)
}

// sendNotice delivers one notice to a peer's listen inbox over an existing mesh
// membership — the same resumable, line-framed channel as a push.
func sendNotice(ctx context.Context, client *embed.Client, addr string, n air.Notice) error {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(air.WriteNotice(pw, n)) }()
	dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", addr) }
	return session.NewClient(dial, log.Printf).Run(ctx, sendStream{r: pr})
}
