package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

// cmdPeers lists the mesh peers currently reachable from this node — the
// AirDrop-style "who can I drop to" view. Each row is a cryptographic identity
// (WireGuard public key + mesh FQDN), not a claim.
func cmdPeers(args []string) error {
	fs := flag.NewFlagSet("peers", flag.ExitOnError)
	o := meshFlags(fs)
	all := fs.Bool("all", false, "include peers that are not currently connected")
	if err := fs.Parse(args); err != nil {
		return err
	}

	o.BlockInbound = true // we only need to read status, not accept inbound
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	st, err := client.Status()
	if err != nil {
		return fmt.Errorf("mesh status: %w", err)
	}

	peers := st.Peers
	sort.Slice(peers, func(i, j int) bool { return peers[i].FQDN < peers[j].FQDN })

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tMESH IP\tFQDN\tPUBKEY")
	shown := 0
	for _, p := range peers {
		connected := strings.EqualFold(fmt.Sprint(p.ConnStatus), "Connected")
		if !connected && !*all {
			continue
		}
		status := "connected"
		if !connected {
			status = strings.ToLower(fmt.Sprint(p.ConnStatus))
		}
		ip := strings.SplitN(p.IP, "/", 2)[0]
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", status, ip, p.FQDN, shortKey(p.PubKey))
		shown++
	}
	tw.Flush()

	if shown == 0 {
		if len(peers) == 0 {
			fmt.Fprintln(os.Stderr, "no peers on the mesh yet")
		} else {
			fmt.Fprintln(os.Stderr, "no connected peers (use --all to include offline peers)")
		}
	}
	return nil
}
