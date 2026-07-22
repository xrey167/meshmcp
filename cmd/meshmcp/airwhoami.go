package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// cmdAirWhoami prints THIS node's own mesh identity — the mesh IP, FQDN, and
// WireGuard public key a gateway's allow-list and audit records key on. `peers`
// answers "who else is here"; this answers "who does the mesh see me as",
// which is what you need to know whether an `allow:` list will admit you.
func cmdAirWhoami(args []string) error {
	fs := flag.NewFlagSet("air whoami", flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "print the identity as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o.BlockInbound = true // we only read our own status
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	st, err := client.Status()
	if err != nil {
		return fmt.Errorf("air whoami: %w", err)
	}
	ip := strings.SplitN(st.LocalPeerState.IP, "/", 2)[0]
	fqdn := st.LocalPeerState.FQDN
	pubkey := st.LocalPeerState.PubKey

	if *asJSON {
		b, err := json.MarshalIndent(map[string]string{"ip": ip, "fqdn": fqdn, "pubkey": pubkey}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	if fqdn != "" {
		fmt.Println(bold(fqdn))
	}
	fmt.Println(dim("mesh ip  ") + cyan(ip))
	if pubkey != "" {
		fmt.Println(dim("pubkey   ") + dim(shortKey(pubkey)))
	}
	fmt.Fprintln(os.Stderr, dim("this is the identity a gateway's allow-list and audit records see"))
	return nil
}
