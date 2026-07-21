# meshmcp — MCP servers over a private WireGuard mesh

`meshmcp` exposes your MCP servers as **dark services** on a [NetBird](https://netbird.io)
mesh: no open ports, no reverse proxy, no API keys in transit. The gateway embeds
the NetBird client **in-process** (userspace WireGuard via netstack — no TUN device,
no admin rights) and every caller is identified by its WireGuard public key.

```
[Claude Code / any MCP client]                 [your GPU box / homelab / VM]
  meshmcp connect <peer>:9101   ── mesh ──▶     meshmcp serve
  (stdio bridge, outbound-only)                   ├─ stdio backend :9101 (per-conn subprocess)
                                                  └─ http  backend :9102 (reverse proxy + identity headers)
```

- **Zero exposure** — backends listen only on the mesh interface. `nmap` from the internet finds nothing.
- **NAT-proof** — works behind CGNAT, hotel Wi-Fi, LTE; NetBird handles ICE/STUN/TURN.
- **Cryptographic caller identity** — every request resolves to the peer's WireGuard
  public key and mesh FQDN (`IdentityForIP`), enforced by per-backend ACLs and stamped
  onto HTTP requests as `X-Meshmcp-Peer` / `X-Meshmcp-Peer-Key`.
- **Resumable sessions** — a `resumable` stdio backend keeps its subprocess alive across
  client reconnects and replays missed messages, so an MCP session survives the mesh
  connection dropping (Wi-Fi↔LTE roam, laptop sleep/wake, TURN relay switch) with
  exactly-once, in-order delivery and a bounded, flow-controlled buffer. See `session/`.
- **Gateway HA / session migration** — with `session_store`, session state is checkpointed
  to a shared, durable store (atomic + fsync + cross-process lock) so a **logical MCP
  session survives a gateway crash**: another gateway rehydrates it (handshake / full /
  backend-EventStore modes) under an ownership lease. See [docs/HA-TOOLMESH.md](docs/HA-TOOLMESH.md).
- **Aggregating tool mesh** — `meshmcp router` unions many servers into one namespaced
  endpoint with replica load-balancing, health-based failover, a self-registering
  discovery registry, and full bidirectional MCP (sampling/elicitation relay).
- **Self-hostable end-to-end** — point `management_url` at your own NetBird server.

## Build

```powershell
go build -o meshmcp.exe .
go build -o cmd/mcpserver/mcpserver.exe ./cmd/mcpserver/prompt_mcp   # the demo MCP server
```

## A real MCP server to serve

`cmd/mcpserver` is a full MCP server built on the framework in `mcp/`, implementing the
complete standard capability set:

- **Tools** (executable): `echo`, `add`, `read_file`, `write_file`, `list_dir`,
  `slow_count` — filesystem tools are sandboxed to `--root` and reject path traversal.
- **Resources**: `time://now`, `info://server`, and `meshmcp://peer` — the last returns
  the caller's mesh identity (FQDN + WireGuard key) that the gateway injected.
- **Prompts**: `summarize`, `code_review` — parameterized prompt templates.
- **Notifications**: handlers emit `notifications/progress` and `notifications/message`;
  the server sends `notifications/tasks/status` and accepts `notifications/cancelled`.
- **Tasks**: any tool run with `"task": true` executes asynchronously, returning a
  working handle; poll `tasks/list` / `tasks/get`, fetch `tasks/result`, cancel with
  `tasks/cancel`. `slow_count` demonstrates streamed progress and cooperative cancel.

Drive a task over the mesh: `meshmcp probe --task <peer-ip:port>`.

The `mcp` package is a small, dependency-free way to build your own servers:

```go
s := mcp.New("my-server", "1.0")
s.AddTool(mcp.Tool{Name: "greet", Handler: func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
    return mcp.ToolResult{Content: []mcp.Content{mcp.Text("hi")}}, nil
}})
s.Serve(context.Background(), os.Stdin, os.Stdout)
```

Tour it over the mesh: `meshmcp probe --full <peer-ip:port>` drives initialize, tools,
resources, and prompts against a live backend.

## Quick start

1. Create a **setup key** in the NetBird dashboard (app.netbird.io → Setup Keys),
   ideally one key for the gateway and one (ephemeral, auto-groups) for clients.

2. **On the machine with your MCP servers** — copy `meshmcp.example.yaml` to
   `meshmcp.yaml`, edit backends, then:

   ```powershell
   $env:NB_SETUP_KEY = "<gateway setup key>"
   .\meshmcp.exe serve --config meshmcp.yaml
   # meshmcp: mesh peer up: 100.92.1.5 (meshmcp-gw.netbird.cloud)
   ```

3. **In Claude Code (or any MCP client) anywhere else** — add a stdio server that
   bridges over the mesh:

   ```json
   {
     "mcpServers": {
       "home-gpu-tools": {
         "command": "C:\\path\\to\\meshmcp.exe",
         "args": ["connect", "--nb-config", "C:\\path\\to\\client-identity.json", "100.92.1.5:9101"],
         "env": { "NB_SETUP_KEY": "<client setup key>" }
       }
     }
   }
   ```

   For **Streamable HTTP** backends, run a local forward instead and point the
   client at localhost:

   ```powershell
   .\meshmcp.exe forward 127.0.0.1:8090 100.92.1.5:9102
   # MCP client URL: http://127.0.0.1:8090/mcp
   ```

## Commands

| Command | Purpose |
|---|---|
| `meshmcp serve --config <file>` | Join mesh, expose configured backends on mesh ports |
| `meshmcp router --config <file>` | Join mesh, aggregate upstreams as one namespaced endpoint |
| `meshmcp orchestrate --config <file>` | Join mesh, serve a tool that calls another server (server-to-server) |
| `meshmcp connect [flags] <peer:port>` | Bridge stdio ⇄ remote stdio backend (for MCP client configs) |
| `meshmcp forward [flags] <local> <peer:port>` | Forward a local TCP port to a mesh peer (for HTTP backends) |
| `meshmcp probe [flags] <peer:port>` | In-process MCP handshake diagnostic (`--full`, `--task`) |
| `meshmcp ls [flags] <peer:port>` | List a backend's tools, resources, and prompts |
| `meshmcp call [flags] <peer:port> <tool>` | Call a tool: `--arg k=v` (JSON-coerced), `--json '{...}'`, `--task` |
| `meshmcp read [flags] <peer:port> <uri>` | Read a resource |
| `meshmcp prompt [flags] <peer:port> <name>` | Render a prompt: `--arg k=v` |
| `meshmcp drop [flags] <peer:port> <file...>` | AirDrop files to a peer (`--config` runs a receiver) |
| `meshmcp push [flags] <peer:port>` | Push a stdin payload to a peer's inbox |
| `meshmcp peers [flags]` | List reachable mesh identities |
| `meshmcp fetch [flags] <peer:port> <sha256>` | Fetch a blob by content hash from a peer's store |
| `meshmcp air <sessions\|steer\|handoff\|launch\|agent-steer\|workflow\|serve>` | **Air · Steer** — list/steer live sessions, hand a session to another identity (F30), steer/launch agents, run a workflow, or serve the live web page (see [AIR.md](AIR.md)) |
| `meshmcp pubsub --config <f>` · `publish` · `subscribe <peer:port> <topic>` | Identity-gated, audited **event bus** on the mesh — durable + resumable (see [PUBSUB.md](PUBSUB.md)) |
| `meshmcp mcp [flags]` | Run meshmcp **as an MCP server** for Claude Code / Codex (see [MCP-APP.md](MCP-APP.md)) |
| `meshmcp approvals --store <dir>` | Serve the co-sign approver (`--devices <dir>` enables push-wake; `--notify-webhook <url>` delivers pendings to a relay) |
| `meshmcp audit <verify\|keygen\|export\|receipt\|attest>` | Verify/sign the ledger; export CSV; emit a provenance receipt; build a compliance attestation bundle (F32) |
| `meshmcp capability <keygen\|issue\|revoke\|list>` | Mint an authority key, sign a short-lived tool grant, revoke/list capability ids (F21) |
| `meshmcp status --audit <f> [--json]` | Roll up a ledger: per-peer/tool/backend calls + chain verdict (F15) |
| `meshmcp budget --audit <f> [--by-tool]` | Total cost/quota units consumed per identity — FinOps for the fleet (F29) |
| `meshmcp config validate --config <f>` · `doctor --config <f>` | Validate a config (globs/windows/enums/DLP); run pre-flight readiness checks |
| `meshmcp hook --client <c> --config <f>` | Client-hook firewall: govern every local tool call in Claude Code / Cursor / Codex (F33) |
| `meshmcp plugins` | List the extensions compiled into this build (F13) |
| `meshmcp spotlight [flags] <query>` | Federated semantic search across the mesh backends you can reach — merged, ranked, provenance-tagged (F19) |
| `meshmcp market <keygen\|publish\|list\|verify\|install>` | Governed plugin marketplace: signed bundle manifests, pinned-key + content-hash verify, metered + audited installs (F14) |

Shared mesh flags for `connect`/`forward`/`probe`/`ls`/`call`/`read`/`prompt`/`drop`/`push`/`peers`/`fetch`/`air`: `--setup-key` (or `$NB_SETUP_KEY`),
`--management-url` (or `$NB_MANAGEMENT_URL`), `--device-name`, `--nb-config`
(persist identity — reuse the same peer/IP across runs; without it every run
registers a fresh peer), `--log-level`, `--start-timeout`.

## Configuration (`serve`)

See `meshmcp.example.yaml`. Each backend is either:

- `stdio: [cmd, args...]` — one subprocess per inbound connection, connection piped
  to stdin/stdout. The subprocess gets `MESHMCP_PEER` / `MESHMCP_PEER_ADDR` env vars
  identifying the caller. Works with every stdio MCP server unchanged.
- `http: http://127.0.0.1:PORT` — reverse proxy with immediate flushing (SSE-safe)
  and identity headers. Works with Streamable HTTP MCP servers.

Per-backend `allow` lists accept FQDN globs (`laptop-*.netbird.cloud`) and
`pubkey:<wireguard-key>` entries; empty means any mesh peer. NetBird's own
dashboard ACLs remain the outer boundary — `allow` adds per-backend, per-agent
granularity inside the mesh.

Policy rules govern **tools** (`tools:`) or **methods** (`methods:`). A method rule
authorizes non-tool JSON-RPC methods and client notifications by glob — e.g. deny
`tasks/cancel`, or drop `notifications/roots/*` — so the task and notification
utilities are governed and audited alongside tool calls:

```yaml
policy:
  default_allow: false
  rules:
    - peers: ["*"]
      tools: ["slow_count", "read_*"]
      allow: true
    - peers: ["*"]
      methods: ["tasks/cancel"]   # only the owner should cancel; deny others
      allow: false
```

Method governance is opt-in: a method is only restricted when a `methods` rule matches
it, so `initialize`, `tools/list`, and ungoverned `tasks/*` always pass. Denied requests
get a JSON-RPC error; denied notifications are dropped (no id to answer).

An optional top-level `control:` block enables the [Air](AIR.md) session-control endpoint —
`GET /v1/sessions` and `POST /v1/steer` on a mesh port, identity-gated + audited — so live
resumable sessions can be listed and steered:

```yaml
control:
  port: 9600
  allow: ["laptop-*.netbird.cloud"]   # empty = any mesh peer
```

## Security notes

- `connect`/`forward` peers set `BlockInbound` — they can dial out but accept nothing.
- Identity headers are stripped from inbound requests before being re-stamped, so
  callers can't spoof them.
- A setup key is a credential: prefer ephemeral, group-scoped keys per client, and
  revoke them from the dashboard.

## Resumable sessions

Set `resumable: true` on a stdio backend and connect with `--resumable`:

```powershell
# client side, in the MCP client config args:
["connect", "--resumable", "--nb-config", "client.json", "100.92.1.5:9103"]
```

The gateway keeps the backend subprocess alive for `session_ttl_seconds` after a
transport drop and replays anything the client missed on reattach; the client
buffers local input while reconnecting with jittered backoff. Delivery is
sequence-numbered and acknowledged in both directions, so the MCP client and
server never observe the interruption. Verified by `session` package tests that
sever the live connection mid-stream (once, and repeatedly) and assert
exactly-once, no-loss delivery under the race detector.

The design mirrors the reliability core of Tencent's Mars STN: number what you
send, buffer until acked, replay what the peer never saw.

## Tool-level policy & audit

The gateway is an MCP-aware policy enforcement point: for a stdio backend with a
`policy` block it parses the JSON-RPC stream and authorizes each `tools/call` by the
caller's cryptographic mesh identity. Denied calls get a JSON-RPC error (`-32001`) and
never reach the backend; every call is written to a structured audit log.

```yaml
- name: kg-memory-guarded
  port: 9105
  stdio: ["python", "-m", "my_mcp_server"]
  resumable: true
  audit_log: ./audit.jsonl        # omit -> stderr; unopenable file -> hard error
  policy:
    default_allow: false          # allowlist: no rule => deny
    rules:
      - peers: ["laptop-*.netbird.cloud"]
        tools: ["read_*", "search_*"]
        allow: true
```

Audit records are one JSON object per line:

```json
{"time":"2026-07-15T08:59:20Z","backend":"kg-memory-guarded","peer":"probe.netbird.cloud",
 "peer_key":"FvBIVDhf0+4...","method":"tools/call","tool":"echo","decision":"deny","rule":-1}
```

This is a control NetBird's network ACLs can't express: network ACLs decide who may reach
a backend; policy decides which *tools* each identity may call once connected. Verified by
`policy` package tests (allowed tool reaches backend, denied tool blocked + audited, under
`-race`) and a live mesh deny. Applies to stdio backends; HTTP backends get network ACL +
identity headers.

Diagnose a backend end-to-end with the built-in probe (joins the mesh, runs a real MCP
handshake): `meshmcp probe --resumable <peer-ip:port>`.

## Full-traffic trace log

Add a top-level `trace:` block to `serve` config and every MCP message across every
stdio backend — both directions — is written to one newline-delimited JSON file,
attributed to the caller's mesh identity:

```json
{"time":"...","backend":"demo","peer":"orch.netbird.cloud","peer_key":"lYvuPR...",
 "dir":"c2s","kind":"request","method":"tools/call","tool":"add","rpc_id":"2",
 "payload":{"arguments":{"a":2,"b":40},"name":"add"}}
```

`dir` is `c2s`/`s2c`; `kind` is request/response/notification; `payload` (when
`payloads: true`) is capped at `max_bytes`. Unlike the policy audit log (client→server
decisions only), the trace records both directions of every message. Verified by
`policy` tests and a live run where an orchestrator's server-to-server calls appeared in
the gateway's trace.

## Aggregating router & server-to-server

- `meshmcp router --config router.yaml` joins the mesh and presents the **namespaced
  union** of its `upstreams` (`demo.add`, `echo.echo`, ...) as one endpoint. It forwards
  upstream notifications (progress, tasks/status) to the client and stamps the end
  client's identity into each upstream request's `_meta` (`meshmcpOriginPeer/Key`) — an
  on-behalf-of hint carried through the hop (the transport identity is still the router).
  An upstream may list **multiple replica addresses**, across which the router
  **load-balances (round-robin) and fails over** — a call routes around a dead replica
  (verified by test), re-dialing it after a cooldown.
- `meshmcp orchestrate --config orchestrate.yaml` is a **server-to-server** node: it
  serves a `research` tool whose handler calls another server's tools (`add`, `echo`)
  over the mesh and combines the results.

## Roadmap

See [docs/VISION.md](docs/VISION.md) for the full picture and
[docs/HA-TOOLMESH.md](docs/HA-TOOLMESH.md) for the HA / tool-mesh internals.

**Done:** resumable + migratable sessions (bounded/flow-controlled buffer, cross-gateway
migration with lease); per-tool + per-method policy with audit and a full both-directions
trace; aggregating router with replica LB, health-based failover, dynamic discovery
registry, and bidirectional MCP; stdio + HTTP backends; a CLI (`ls/call/read/prompt`).

**Shipped since (Wave 2 — see [ROADMAP-HARDENING.md](ROADMAP-HARDENING.md)):**
- **Capability tokens** — short-lived signed grants, plus a **revocation store** (`capability revoke/list`, F21).
- **Rate & cost governance** — per-identity quotas and cost accounting; `meshmcp budget` totals spend (F29).
- **`meshmcp status`** — per-peer/tool/backend call rollup + chain verdict (F15); `budget`, `doctor`, `config validate`, `audit export/receipt/attest`.
- **Federation** — cross-org boundary with policy at the trust seam (already built; F31 SSO mapping is open).
- **HTTP-backend policy parity** (F16), a **plugin platform** (F13), **fail-closed audit** (F22), **identity-bound sessions** (F23),
  a **client-hook firewall** for Claude Code / Cursor / Codex (F33), and new dark backends **vault/scheduler/bus** (F26–F28).

**Still open:**
- **Replicated store backend:** Redis/etcd behind the `SessionStore` interface for multi-datacenter HA.
- Flagships F14 (plugin marketplace), F19 (Mesh Spotlight), F25 (multi-tenant), F30 (live handoff), F31 (federated SSO mapping).
