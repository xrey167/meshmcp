package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// peerRow is one mesh peer as reported by `peers` — the machine-readable form
// behind both the table and --json output.
type peerRow struct {
	IP        string `json:"ip"`
	FQDN      string `json:"fqdn"`
	PubKey    string `json:"pubkey"`
	Status    string `json:"status"`
	Connected bool   `json:"connected"`
}

// filterPeerRows keeps connected peers, or all of them when all is set.
func filterPeerRows(rows []peerRow, all bool) []peerRow {
	if all {
		return rows
	}
	var out []peerRow
	for _, r := range rows {
		if r.Connected {
			out = append(out, r)
		}
	}
	return out
}

// cmdPeers lists the mesh peers currently reachable from this node — the
// AirDrop-style "who can I drop to" view. Each row is a cryptographic identity
// (WireGuard public key + mesh FQDN), not a claim.
func cmdPeers(args []string) error {
	fs := flag.NewFlagSet("peers", flag.ExitOnError)
	o := meshFlags(fs)
	all := fs.Bool("all", false, "include peers that are not currently connected")
	jsonOut := fs.Bool("json", false, "emit the peer list as JSON on stdout")
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

	var allRows []peerRow
	for _, p := range peers {
		connected := strings.EqualFold(fmt.Sprint(p.ConnStatus), "Connected")
		label := "connected"
		if !connected {
			label = strings.ToLower(fmt.Sprint(p.ConnStatus))
		}
		allRows = append(allRows, peerRow{
			IP:        strings.SplitN(p.IP, "/", 2)[0],
			FQDN:      p.FQDN,
			PubKey:    p.PubKey,
			Status:    label,
			Connected: connected,
		})
	}
	rows := filterPeerRows(allRows, *all)

	if *jsonOut {
		if rows == nil {
			rows = []peerRow{} // an empty mesh is [], not null
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}

	if len(rows) == 0 {
		if len(peers) == 0 {
			fmt.Fprintln(os.Stderr, dim("no peers on the mesh yet"))
		} else {
			fmt.Fprintln(os.Stderr, dim("no connected peers (use --all to include offline peers)"))
		}
		return nil
	}
	var cells [][]cell
	for _, r := range rows {
		cells = append(cells, []cell{
			statusDot(r.Connected, r.Status),
			plain(r.IP),
			styled(r.FQDN, bold),
			styled(shortKey(r.PubKey), dim),
		})
	}
	renderTable(os.Stdout, []string{"", "mesh ip", "fqdn", "pubkey"}, cells)
	fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("%d peer(s)", len(rows))))
	return nil
}
