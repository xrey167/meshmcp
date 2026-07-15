# meshmcp — full network plan (tools, prompts, CLI, server-to-server, client)

## Context

meshmcp today is a per-backend gateway: each MCP server is exposed on its own mesh port,
reached 1:1 by a client. The pieces for a *full network* mostly exist — tools, resources,
prompts, notifications, tasks, policy, audit, resumable sessions — but four things are
missing to make it feel like one fabric:

1. **Trace/observability** — `policy/trace.go` is written but **orphaned** (not wired into
   the filter, config, or serve). No unified per-call log yet.
2. **Aggregation** — no component presents several servers as one endpoint; a client holds
   N separate connections.
3. **Server-to-server** — no MCP server can call another server's tools over the mesh.
4. **A real CLI client** — `probe` is a fixed diagnostic, not a general `call/ls/read` tool.

Goal: a working mesh where multiple MCP servers (tools/functions, prompts, resources),
a command-line client, and server-to-server calls all operate over one WireGuard fabric,
with every call authorized and traced. Note: "tool call" and "function call" are the same
MCP `tools/call` mechanism (MCP tools are the function-calling interface).

## Target topology

```
                         ┌────────── NetBird mesh (one flat overlay) ──────────┐
                         │                                                      │
  [CLI client]           │   [gateway peer: meshmcp serve]                      │
  meshmcp call/ls/read ──┼──▶  router :9100  ──┬─▶ filesystem :9101 (stdio)     │
  meshmcp connect        │                     ├─▶ fetch      :9102 (stdio)     │
       (agent/IDE)       │                     ├─▶ time       :9103 (stdio)     │
                         │                     ├─▶ demo       :9104 (mcpserver) │
                         │                     └─▶ orchestrator :9105 ──────────┼─┐ server→server
                         │                                                      │ │ dials fetch:9102
                         │   trace.jsonl  ◀── every call, both directions ──────┘ │ + filesystem:9101
                         └──────────────────────────────────────────────────────┘ over the mesh
```

- **router :9100** — one MCP endpoint; its `tools/list` is the namespaced union of all
  upstreams; it routes `tools/call`/`resources/read`/`prompts/get` to the right upstream
  over the mesh. This is what makes the client see "the mesh," not N servers.
- **orchestrator :9105** — a demo MCP server whose tools call *other* servers' tools over
  the mesh (server-to-server).
- **trace** — a single gateway-wide NDJSON log of every message.

## What exists vs. what to build

| Piece | State | Files |
|---|---|---|
| Tools / resources / prompts framework | Built | `mcp/server.go`, `cmd/mcpserver/main.go` |
| Notifications / tasks | Built | `mcp/session.go`, `mcp/tasks.go` |
| Policy (per-tool + per-method) + audit | Built | `policy/policy.go`, `policy/filter.go`, `policy/audit.go`, `serve.go` |
| Resumable sessions | Built | `session/*.go` |
| CLI: serve/connect/forward/probe | Built | `main.go`, `serve.go`, `bridge.go`, `probe.go` |
| Trace logging | Built (both directions, payloads) | `policy/trace.go`, `serve.go` |
| Aggregating router (LB, failover, discovery, bidirectional) | Built | `router.go`, `registry/` |
| Server-to-server orchestrator | Built | `orchestrate.go` |
| General CLI client (`ls/call/read/prompt`) | Built | `cli.go`, `mcpclient/` |
| HTTP backend + `mcp` HTTP transport | Built | `serve.go` (`serveHTTP`), `mcp/http.go`, `cmd/mcphttp` |
| Gateway HA / session migration + lease | Built | `session/store.go`, `session/flock.go`, `session/server.go` |

**Everything in the original plan below is now implemented and tested (`-race`).** See
[HA-TOOLMESH.md](HA-TOOLMESH.md) for the HA / tool-mesh details. Remaining open work is
the control-plane/governance roadmap in [VISION.md](VISION.md).

## Build — phased

### Phase 1 — Wire the trace log (finish the orphaned feature)
Deliver the "audit + trace of every tool call, read, write" you asked for.
- `config.go`: add a top-level `trace:` block (`log`, `payloads`, `max_bytes`) on `Config`.
- `serve.go` `cmdServe`: construct one shared `*policy.Tracer` (open the file once) and pass
  it to `backendFactory`; wrap a backend with `Filter` when `policy != nil` **or** `tracer != nil`.
- `policy/filter.go`: add a `tracer` field + `NewFilter(..., tracer)`; call `tracer.record`
  in `handleLine` (c2s, with the policy decision) and in `pumpInner` (s2c). Reuse the
  existing `Caller` on the Filter — integration surface is small.
- Tests: `policy/trace_test.go` — both directions recorded; `tools/call` captures tool name;
  payload cap produces the truncation marker; decision recorded on governed calls.
- Result: one NDJSON line per message — `{time, backend, peer, peer_key, dir, kind, method,
  tool, rpc_id, decision, bytes, payload?}` — a mesh-wide, identity-attributed trace.

### Phase 2 — Aggregating router (one endpoint = all servers)
A new backend kind that fans out to upstream mesh peers.
- New package `router/` (or `cmd/mcprouter`): an `mcp.Server` whose handlers are dynamic.
  On `initialize` it dials each configured upstream (`peer-ip:port`) over the mesh using a
  session client (reuse `session.Client` / `client.Dial`), runs each upstream's
  `initialize` + `tools/list` + `resources/list` + `prompts/list`, and builds a routing
  table. Names are namespaced (`filesystem.read_file`) to avoid collisions.
- Routing: `tools/call filesystem.read_file` → strip prefix → forward to the filesystem
  upstream session → return its result. Same for `resources/read` (by URI owner) and
  `prompts/get`. Notifications/`list_changed` from any upstream re-trigger discovery and are
  forwarded to the client.
- Config: a `router` backend type listing `upstreams: [name -> peer:port]`. Policy still
  applies at each real backend; the router itself can also carry a coarse policy.
- Result: the client runs one `connect …:9100` and sees every server's capabilities as one.

### Phase 3 — Server-to-server orchestrator (demo of server→server)
- `cmd/orchestrator/main.go`: an `mcp.Server` exposing e.g. `research(topic)` whose handler,
  over the mesh, calls `fetch` on the fetch peer and `write_file` on the filesystem peer,
  then returns a summary. Built on `mcp` + a small mesh MCP client helper (extract the
  handshake/call logic from `probe.go` into a reusable `mcpclient` used by both the router
  and the orchestrator).
- This proves an agent-tool calling other agent-tools over the mesh, fully traced/audited at
  each hop (each hop is an ordinary policed mesh session).

### Phase 4 — Command-line MCP client
- Add `meshmcp` subcommands that make the mesh usable from a terminal (generalize `probe`):
  - `meshmcp ls <peer>` — list tools/resources/prompts.
  - `meshmcp call <peer> <tool> --arg k=v …` — invoke a tool/function, print result; `--task` for async.
  - `meshmcp read <peer> <uri>` — read a resource.
  - `meshmcp prompt <peer> <name> --arg k=v` — render a prompt.
- Optional: a guarded `run_command` tool in a demo server (allow-listed commands, sandboxed),
  so "command line" is also reachable *as a tool* — governed by policy like any other tool.

### Phase 5 — Reference deployment + live demo
- `deploy/` configs: `gateway.yaml` (filesystem, fetch, time, demo, orchestrator, router,
  one `trace:` block); env-based setup keys.
- A `run-demo` script (documented, not committed with secrets) that starts the gateway and
  drives, from the CLI client over the mesh: a function/tool call, a prompt, a resource
  read/write, a server-to-server `research`, and shows the growing `trace.jsonl`.

## Files to add / modify

- Modify: `config.go` (+trace block, +router/upstreams backend type), `serve.go` (construct
  Tracer, wire router listener), `policy/filter.go` (+tracer), `probe.go` (extract reusable
  client, add CLI subcommands), `main.go` (register new subcommands).
- Add: `policy/trace_test.go`, `mcpclient/` (reusable mesh MCP client), `cmd/mcprouter/` (or
  `router/`), `cmd/orchestrator/`, `deploy/*.yaml`, docs updates (`README.md`, `VISION.md`).
- Reuse: `session.Client`/`embed.Client.Dial` for upstream dials; `mcp.Server` for router +
  orchestrator; `policy.Filter`/`Tracer` unchanged at each real backend.

## Verification (end-to-end, over the live mesh)

Each phase is provable without net-new infra (a reusable NB setup key already works):
1. Phase 1: `serve` with a `trace:` block; run `probe --full`; assert `trace.jsonl` has c2s
   requests + s2c responses for tools/resources/prompts, with identity and decision. Unit:
   `go test ./policy -race`.
2. Phase 2: `connect`/`probe` the **router** port; assert `tools/list` = union with
   namespaced names; call `filesystem.read_file` and confirm it round-trips through the
   router to the real server.
3. Phase 3: call `orchestrator.research`; confirm the trace shows the orchestrator's
   outbound calls to fetch + filesystem as separate policed sessions.
4. Phase 4: `meshmcp call <router> time.get_current_time`, `meshmcp read <peer> meshmcp://peer`
   from the terminal.
5. Full: `go build ./... && go vet ./... && go test ./... -race`; then the live gateway +
   CLI-client demo across the mesh.

## Open decisions
- **Router vs. no router**: build the aggregator (unified endpoint) now, or keep N endpoints
  and just add server-to-server + CLI? The router is the biggest new piece.
- **Trace scope**: gateway-wide single file (recommended) vs. per-backend files.
- **"Command line"**: a CLI *client* (recommended) and/or a guarded `run_command` *tool*.
- **Reference servers**: use official `filesystem`/`fetch`/`time` (npx/uvx) or all-Go demos.
</content>
