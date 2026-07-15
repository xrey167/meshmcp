// meshmcp is a mesh gateway for MCP servers: it exposes local MCP servers
// as peers on a NetBird WireGuard mesh (no open ports, userspace networking,
// no admin rights) and lets MCP clients on other mesh peers reach them.
//
//	meshmcp serve   --config meshmcp.yaml     expose local MCP servers on the mesh
//	meshmcp connect <peer-ip:port>            stdio bridge to a remote stdio backend
//	meshmcp forward <local> <peer-ip:port>    local TCP forward to a remote HTTP backend
package main

import (
	"fmt"
	"log"
	"os"
)

const version = "0.1.0"

func usage() {
	fmt.Fprintf(os.Stderr, `meshmcp %s — MCP servers over a private WireGuard mesh

Usage:
  meshmcp serve --config <file>                 join mesh, expose configured backends
  meshmcp router --config <file>                join mesh, aggregate upstreams as one endpoint
  meshmcp orchestrate --config <file>           join mesh, serve a tool that calls another server
  meshmcp control [flags]                        run the managed control plane (enroll, registry, policy)
  meshmcp connect [flags] <peer-ip:port>        bridge stdio <-> remote stdio backend
  meshmcp forward [flags] <local> <peer:port>   forward a local TCP port to a mesh peer
  meshmcp probe [flags] <peer-ip:port>          run an MCP handshake against a backend
  meshmcp ls [flags] <peer-ip:port>             list a backend's tools/resources/prompts
  meshmcp call [flags] <peer:port> <tool>       call a tool (--arg k=v, --json, --task)
  meshmcp read [flags] <peer:port> <uri>        read a resource
  meshmcp prompt [flags] <peer:port> <name>     render a prompt (--arg k=v)
  meshmcp audit verify <file>                   verify a tamper-evident audit log's hash chain
  meshmcp approve [flags] <peer-fqdn> <tool>    co-sign a require_cosign tool call for a peer
  meshmcp dash [flags]                          serve the mesh control dashboard over audit/trace logs
  meshmcp replay [flags] <trace> <peer:port>    replay a traced session against a backend and diff
  meshmcp version

Mesh credentials come from flags, config, or $NB_SETUP_KEY / $NB_MANAGEMENT_URL.
Run "meshmcp <command> -h" for command flags.
`, version)
}

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("meshmcp: ")
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "connect":
		err = cmdConnect(os.Args[2:])
	case "forward":
		err = cmdForward(os.Args[2:])
	case "probe":
		err = cmdProbe(os.Args[2:])
	case "ls":
		err = cmdLs(os.Args[2:])
	case "call":
		err = cmdCall(os.Args[2:])
	case "read":
		err = cmdRead(os.Args[2:])
	case "prompt":
		err = cmdPrompt(os.Args[2:])
	case "router":
		err = cmdRouter(os.Args[2:])
	case "orchestrate":
		err = cmdOrchestrate(os.Args[2:])
	case "control":
		err = cmdControl(os.Args[2:])
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "approve":
		err = cmdApprove(os.Args[2:])
	case "dash":
		err = cmdDash(os.Args[2:])
	case "replay":
		err = cmdReplay(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "meshmcp: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}
