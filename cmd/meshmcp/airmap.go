package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/air"
)

// cmdAirMap renders the reachable mesh as a tree: YOU (your mesh identity) → the
// gateway → the backends you may reach, with each backend's transport and
// capabilities. It is the "what does my mesh look like" view — a topology, not
// a flat list — composed from `air whoami` and the ARD catalog.
func cmdAirMap(args []string) error {
	fs := flag.NewFlagSet("air map", flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "print the map as JSON (you + catalog)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp air map [flags] <control-ip:port>")
	}
	control := fs.Arg(0)

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	st, err := client.Status()
	if err != nil {
		return fmt.Errorf("air map: mesh status: %w", err)
	}
	me := air.PeerRow{
		Status: "connected",
		IP:     strings.SplitN(st.LocalPeerState.IP, "/", 2)[0],
		FQDN:   st.LocalPeerState.FQDN,
		PubKey: st.LocalPeerState.PubKey,
	}

	hc := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return client.Dial(ctx, "tcp", control)
			},
		},
	}
	cat, _, err := air.FetchCatalog(hc, "http://air-control"+air.CatalogPath)
	if err != nil {
		return fmt.Errorf("air map: %w", err)
	}

	if *asJSON {
		b, err := json.MarshalIndent(map[string]any{"you": me, "control": control, "catalog": cat}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	renderAirMap(os.Stdout, me, control, cat)
	fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("%d reachable backend(s) on %s", len(cat.Endpoints), control)))
	return nil
}

// renderAirMap draws the you→gateway→backends tree. It is pure (no mesh), so it
// is unit-testable; colour is applied by the style helpers only when enabled.
func renderAirMap(w io.Writer, me air.PeerRow, controlAddr string, cat air.Catalog) {
	you := me.FQDN
	if you == "" {
		you = me.IP
	}
	fmt.Fprintln(w, dim("you  ")+bold(you)+dim("  ("+me.IP+")"))
	fmt.Fprintln(w, dim("│"))

	gw := cat.Gateway
	if gw == "" {
		gw = controlAddr
	}
	fmt.Fprintln(w, cyan("◆ ")+bold(gw)+dim("  ·  "+controlAddr))

	eps := cat.Sorted().Endpoints
	if len(eps) == 0 {
		fmt.Fprintln(w, dim("└── (no backends you may reach)"))
		return
	}
	width := 0
	for _, e := range eps {
		if n := runeLen(e.Name); n > width {
			width = n
		}
	}
	for i, e := range eps {
		branch := "├──"
		if i == len(eps)-1 {
			branch = "└──"
		}
		fmt.Fprintf(w, "%s %s  %s  %s\n", dim(branch), bold(padRight(e.Name, width)), dim(padRight(e.Transport, 6)), mapCaps(e))
	}
}

// mapCaps renders an entry's capabilities as small coloured labels (a leaf
// display, not a table cell, so colour here is fine).
func mapCaps(e air.CatalogEntry) string {
	var caps []string
	if e.Resumable {
		caps = append(caps, green("resumable"))
	}
	if e.Steerable {
		caps = append(caps, blue("steerable"))
	}
	if len(caps) == 0 {
		return dim("—")
	}
	return strings.Join(caps, dim(" · "))
}
