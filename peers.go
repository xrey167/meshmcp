package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
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

	var rows [][]cell
	for _, p := range peers {
		connected := strings.EqualFold(fmt.Sprint(p.ConnStatus), "Connected")
		if !connected && !*all {
			continue
		}
		label := "connected"
		if !connected {
			label = strings.ToLower(fmt.Sprint(p.ConnStatus))
		}
		ip := strings.SplitN(p.IP, "/", 2)[0]
		rows = append(rows, []cell{
			statusDot(connected, label),
			plain(ip),
			styled(p.FQDN, bold),
			styled(shortKey(p.PubKey), dim),
		})
	}

	if len(rows) == 0 {
		if len(peers) == 0 {
			fmt.Fprintln(os.Stderr, dim("no peers on the mesh yet"))
		} else {
			fmt.Fprintln(os.Stderr, dim("no connected peers (use --all to include offline peers)"))
		}
		return nil
	}
	renderTable(os.Stdout, []string{"", "mesh ip", "fqdn", "pubkey"}, rows)
	fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("%d peer(s)", len(rows))))
	return nil
}
