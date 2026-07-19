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
  meshmcp graphrag --config <file>              serve graph_search: vector retrieval + knowledge-graph expansion (S3)
  meshmcp control [flags]                        run the managed control plane (enroll, registry, policy)
  meshmcp federate --config <file>               run a cross-org federation boundary (granted tools only, audited)
  meshmcp agent --role <r> [flags] <peer:port>  run a demo agent app (reader/fetcher/billing/analyst) with its own identity
  meshmcp air <sessions|steer|launch> [flags]   drive live work: list/steer a gateway's sessions, launch an agent
  meshmcp connect [flags] <peer-ip:port>        bridge stdio <-> remote stdio backend
  meshmcp forward [flags] <local> <peer:port>   forward a local TCP port to a mesh peer
  meshmcp drop [flags] <peer:port> <path...>    AirDrop files or directories to a mesh peer (resumable, audited); --config runs a receiver
  meshmcp peers [flags]                          list mesh peers you can reach (identities you can drop to)
  meshmcp fetch [flags] <peer:port> <sha256>    fetch a blob by content hash from a peer's store (F11)
  meshmcp push [flags] <peer:port>              push a stdin payload to a peer's inbox (universal clipboard)
  meshmcp pubsub --config <file>                run an identity-gated, audited event bus on the mesh (durable + resumable)
  meshmcp pubsub verify <event-log>             verify a persisted event stream's hash chain
  meshmcp pubsub stats [flags] <peer:port>      query a running broker (subscribers, sequence, drops)
  meshmcp publish [flags] <peer:port> <topic>   publish an event to a broker topic (stdin or --data; --stream: one per line)
  meshmcp subscribe [flags] <peer:port> <topic...>  stream events from a broker (--since replays, Ctrl-C to stop)
  meshmcp probe [flags] <peer-ip:port>          run an MCP handshake against a backend
  meshmcp ls [flags] <peer-ip:port>             list a backend's tools/resources/prompts
  meshmcp call [flags] <peer:port> <tool>       call a tool (--arg k=v, --json, --task, --capability @file)
  meshmcp read [flags] <peer:port> <uri>        read a resource
  meshmcp prompt [flags] <peer:port> <name>     render a prompt (--arg k=v)
  meshmcp audit verify <file> [--checkpoints f] verify an audit log (hash chain; +signatures with --checkpoints)
  meshmcp audit keygen [--out f]                generate a gateway signing key for audit checkpoints
  meshmcp audit export --in <file>              export an audit ledger to CSV on stdout (for BI/spreadsheets)
  meshmcp audit receipt --in <file> [--peer]    emit a verifiable provenance receipt (what a session's tools produced)
  meshmcp audit attest --audit <f> [--checkpoints --pubkey --policy]  build a verifiable compliance/attestation bundle
  meshmcp capability keygen [--out f]           generate an Ed25519 authority key backends pin as a trust root
  meshmcp capability issue [flags]              sign a short-lived, subject-bound tool grant (--subject/--audience/--tool)
  meshmcp capability revoke --store <d> <id>    revoke a capability id (fails closed at every gateway sharing the store)
  meshmcp capability list --store <d>           list revoked capability ids
  meshmcp approve [flags] <peer-fqdn> <tool>    co-sign a require_cosign tool call for a peer
  meshmcp approvals --store <dir> [--approver <id>]  serve the co-sign approver over the mesh (--approver restricts who may approve)
  meshmcp secrets check --config <file>         validate the credential broker config (never prints values)
  meshmcp dash [flags]                          serve the mesh control dashboard over audit/trace logs
  meshmcp room --audit <file>                   serve the live Control Room (server tiles, apps, decision feed)
  meshmcp mcp [flags]                            run meshmcp AS an MCP server (add it to Claude Code / Codex to operate the mesh)
  meshmcp insight <profile|recommend|simulate|detect>  turn the audit stream into policy (the firewall's read side)
  meshmcp replay [flags] <trace> <peer:port>    replay a traced session against a backend and diff
  meshmcp config validate --config <file>       validate a config (policy globs, windows, enums, DLP) without joining the mesh
  meshmcp status --audit <file> [--json]        roll up an audit ledger: per-peer/tool/backend calls + chain verdict
  meshmcp budget --audit <file> [--by-tool]     sum cost/quota units consumed per identity (FinOps for the fleet)
  meshmcp doctor --config <file>                pre-flight checks: config valid, commands present, dirs writable, secret perms
  meshmcp hook --client <c> --config <file>     PreToolUse hook adapter: govern EVERY tool call in Claude Code/Cursor/Codex by policy+audit
  meshmcp hook install --client <c>             print the hook config to add to a client's settings
  meshmcp plugins                                list extensions compiled into this build
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
	case "drop":
		err = cmdDrop(os.Args[2:])
	case "peers":
		err = cmdPeers(os.Args[2:])
	case "fetch":
		err = cmdFetch(os.Args[2:])
	case "push":
		err = cmdPush(os.Args[2:])
	case "pubsub":
		err = cmdPubsub(os.Args[2:])
	case "publish":
		err = cmdPublish(os.Args[2:])
	case "subscribe":
		err = cmdSubscribe(os.Args[2:])
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
	case "functions":
		err = cmdFunctions(os.Args[2:])
	case "function-call":
		err = cmdFunctionCall(os.Args[2:])
	case "router":
		err = cmdRouter(os.Args[2:])
	case "orchestrate":
		err = cmdOrchestrate(os.Args[2:])
	case "graphrag":
		err = cmdGraphRAG(os.Args[2:])
	case "control":
		err = cmdControl(os.Args[2:])
	case "federate":
		err = cmdFederate(os.Args[2:])
	case "audit":
		err = cmdAudit(os.Args[2:])
	case "capability":
		err = cmdCapability(os.Args[2:])
	case "approve":
		err = cmdApprove(os.Args[2:])
	case "approvals":
		err = cmdApprovals(os.Args[2:])
	case "agent":
		err = cmdAgent(os.Args[2:])
	case "air":
		err = cmdAir(os.Args[2:])
	case "secrets":
		err = cmdSecrets(os.Args[2:])
	case "dash":
		err = cmdDash(os.Args[2:])
	case "room":
		err = cmdRoom(os.Args[2:])
	case "mcp":
		err = cmdMCP(os.Args[2:])
	case "insight":
		err = cmdInsight(os.Args[2:])
	case "replay":
		err = cmdReplay(os.Args[2:])
	case "config":
		err = cmdConfig(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "budget":
		err = cmdBudget(os.Args[2:])
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "hook":
		err = cmdHook(os.Args[2:])
	case "plugins":
		err = cmdPlugins(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		usage()
	default:
		// Fall through to the plugin subcommand registry before giving up, so a
		// compiled-in extension can add a verb without editing this switch.
		if handled, perr := dispatchPlugin(os.Args[1], os.Args[2:]); handled {
			err = perr
		} else {
			fmt.Fprintf(os.Stderr, "meshmcp: unknown command %q\n\n", os.Args[1])
			usage()
			os.Exit(2)
		}
	}
	if err != nil {
		log.Fatal(err)
	}
}
