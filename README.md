<div align="center">

# meshmcp

**A private, identity-native mesh for MCP servers.**

Expose any [Model Context Protocol](https://modelcontextprotocol.io) server as a *dark service* —
reachable only over a WireGuard mesh, with **zero open ports**, cryptographic per-caller
identity, sessions that survive roaming *and* gateway failover, per-tool policy + audit,
and a self-healing router that unions many servers into one endpoint.

`Go` · embedded [NetBird](https://netbird.io) WireGuard · stdio + Streamable-HTTP · `go test -race` green across 6 packages

</div>

---

## Why

An MCP server is usually a local stdio process or an open HTTP port. Sharing one securely across
machines means a VPN, a reverse proxy, auth, and hoping the connection holds. meshmcp collapses
that into one idea: **connectivity, identity, and policy as a library**, wrapped around any MCP
server you already have.

```
                         ┌──────────── NetBird mesh — one flat, encrypted overlay ────────────┐
                         │                                                                    │
   CLI / agent / IDE     │   meshmcp router :9100  ── unions ──▶  fs :9101   (stdio)          │
   meshmcp call ─────────┼──▶  (LB · failover ·             ├──▶  fetch :9102 (stdio)          │
   meshmcp connect       │      discovery · bidi MCP)        └──▶  demo :9104 ──┐              │
        (over mesh)      │                                                       │ server→server│
                         │   every call: authorized by WireGuard identity,       ▼ (orchestrator│
                         │   audited + traced, session survives failover     calls fetch + fs)  │
                         └────────────────────────────────────────────────────────────────────┘
             No public ports anywhere · nmap from the internet finds nothing
```

## What you get

| | |
|---|---|
| **Zero exposure** | Backends listen only on the mesh interface (userspace WireGuard, no TUN, no admin). |
| **Cryptographic identity** | Every request resolves to the caller's WireGuard public key + mesh FQDN — the basis for policy and audit. |
| **Resumable + migratable sessions** | Exactly-once, in-order delivery with a bounded, flow-controlled buffer; survives client roaming *and* a gateway crash (shared durable store + ownership lease). |
| **Per-tool / per-method policy** | Allow/deny individual `tools/call`s and JSON-RPC methods by identity; denied inline with a JSON-RPC error. |
| **Audit + full trace** | Structured per-call audit of decisions, plus an optional both-directions trace of every message. |
| **Aggregating tool mesh** | One namespaced endpoint over N servers, with replica load-balancing, health-based failover, a discovery registry, and full bidirectional MCP (sampling/elicitation relay). |
| **stdio + HTTP backends** | Wrap any stdio MCP server, or reverse-proxy a Streamable-HTTP one. |
| **A real CLI** | `ls / call / read / prompt` drive tools, resources, and prompts from a terminal. |

## Install

```bash
go build -o meshmcp .
go build -o cmd/mcpserver/mcpserver ./cmd/mcpserver   # a full demo MCP server
```

## Quick start

Create a setup key at [app.netbird.io](https://app.netbird.io) → Setup Keys (or use your own
self-hosted NetBird server), then:

```bash
export NB_SETUP_KEY=<your-setup-key>

# Serve a demo MCP server on the mesh (prints its mesh IP, e.g. 100.x.y.z)
meshmcp serve --config examples/demo-backends.yaml

# From any other machine on the mesh:
meshmcp ls   100.x.y.z:9101                       # list tools / resources / prompts
meshmcp call 100.x.y.z:9101 add --arg a=2 --arg b=40
```

To use a mesh MCP server from Claude Code or any MCP client, add a stdio bridge:

```jsonc
{ "mcpServers": {
    "home-tools": {
      "command": "meshmcp",
      "args": ["connect", "--resumable", "100.x.y.z:9101"],
      "env": { "NB_SETUP_KEY": "<setup-key>" }
} } }
```

## Commands

| Command | Purpose |
|---|---|
| `meshmcp serve --config <f>` | Join the mesh; expose configured backends on mesh ports. |
| `meshmcp router --config <f>` | Aggregate upstreams into one namespaced endpoint (LB, failover, discovery). |
| `meshmcp orchestrate --config <f>` | Serve a tool that calls another server's tools over the mesh. |
| `meshmcp connect [flags] <peer:port>` | Stdio ⇄ remote stdio bridge (for MCP client configs); `--resumable`. |
| `meshmcp forward [flags] <local> <peer:port>` | Forward a local TCP port to a mesh peer (for HTTP backends). |
| `meshmcp ls / call / read / prompt <peer:port> …` | Drive tools / resources / prompts from the CLI. |
| `meshmcp probe [--full\|--task] <peer:port>` | In-process MCP handshake diagnostic. |

Shared mesh flags: `--setup-key` (`$NB_SETUP_KEY`), `--management-url`, `--device-name`,
`--nb-config` (persist identity), `--wg-port`.

## Layout

```
session/    resumable + migratable session layer (Mars-STN-style reliability, store, lease, flock)
policy/     MCP-aware policy enforcement, audit, and full-traffic trace
mcp/        dependency-free MCP server framework (tools, resources, prompts, tasks, HTTP)
mcpclient/  MCP client over any transport (used by the router, orchestrator, CLI)
registry/   file-based discovery registry
cmd/        mcpserver (demo), mcpecho, mcphttp (HTTP demo)
*.go        the meshmcp binary: serve / router / orchestrate / connect / forward / probe / CLI
examples/   ready-to-adapt configs (see examples/README.md)
docs/       reference, HA / tool-mesh design, vision, and network plan
```

## Docs & examples

- **[examples/](examples/)** — annotated configs for every scenario.
- **[docs/reference.md](docs/reference.md)** — the complete feature reference.
- **[docs/HA-TOOLMESH.md](docs/HA-TOOLMESH.md)** — session migration, lease, failover, bidirectional MCP.
- **[docs/VISION.md](docs/VISION.md)** — the layered architecture and where it's headed.
- **[docs/NETWORK-PLAN.md](docs/NETWORK-PLAN.md)** — the full-network build plan.

## Develop

```bash
go build ./... && go vet ./... && go test ./... -race
```

## Design invariants

1. **No open ports, ever** — backends listen only on the mesh interface.
2. **Identity is cryptographic, never claimed** — authz keys off the WireGuard key the transport proves, not headers the caller sends.
3. **Deny is the safe default** — policies are allowlists; an unopenable audit sink is a hard error.
4. **Pure transport where possible** — the gateway parses MCP only to authorize; any MCP server works unmodified.

---

<div align="center"><sub>Built on the reliability idea behind Tencent Mars STN, the embedding pattern from caddy-netbird, and NetBird's userspace WireGuard.</sub></div>
