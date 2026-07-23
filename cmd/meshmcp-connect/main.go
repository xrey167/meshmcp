// meshmcp-connect is the thin, connect-only meshmcp client (S45): it joins the
// mesh as an outbound-only peer and bridges local stdio to a remote stdio MCP
// backend — nothing else. It reuses the exact connect code path of the full
// binary (internal/connectcli), so it is a smaller build, not a fork: no
// policy engine, air surface, control plane, or receiver daemons are linked.
//
//	meshmcp-connect [flags] <peer-ip:port>
//
// flags and behavior are identical to `meshmcp connect`.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/xrey167/meshmcp/internal/connectcli"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("meshmcp-connect: ")
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	if err := connectcli.Connect(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "meshmcp-connect:", err)
		os.Exit(1)
	}
}
