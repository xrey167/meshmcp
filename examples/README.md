# Example configurations

Ready-to-adapt configs for `meshmcp serve`, `meshmcp router`, and
`meshmcp orchestrate`. Each needs a NetBird setup key — set `NB_SETUP_KEY`
in the environment (or `setup_key` in the `mesh` block). Paths inside the
files are relative to the directory you run `meshmcp` from.

| File | Command | What it shows |
|---|---|---|
| `meshmcp.example.yaml` | `serve` | The fully-annotated reference: stdio + HTTP backends, ACLs, resumable + policy + tasks, tracing, session migration, registry. Start here. |
| `demo-backends.yaml` | `serve` | Two stdio backends (`demo` + `echo`) — the upstreams a router aggregates. |
| `demo-trace.yaml` | `serve` | A backend with a full both-directions trace log (`trace.jsonl`). |
| `live-policy.yaml` | `serve` | Per-tool policy (allowlist) with an audit log; disallowed tools denied inline. |
| `live-task.yaml` | `serve` | A resumable backend exposing an async task tool (`slow_count`) with progress. |
| `http-backend.yaml` | `serve` | An HTTP (Streamable-HTTP) backend reverse-proxied onto the mesh. |
| `router.yaml` | `router` | Aggregate upstreams into one namespaced endpoint; one upstream is a replica set (load-balanced + failover). |
| `router-failover.yaml` | `router` | An upstream with a dead replica first — the router discovers + routes via failover. |
| `orchestrate.yaml` | `orchestrate` | A server-to-server node whose `research` tool calls another server's tools over the mesh. |

## Quick start

```bash
export NB_SETUP_KEY=<your-netbird-setup-key>

# 1. Serve two demo MCP servers on the mesh
meshmcp serve --config examples/demo-backends.yaml
# -> note the mesh IP it prints (e.g. 100.x.y.z)

# 2. From anywhere on the mesh, list and call tools
meshmcp ls   100.x.y.z:9101
meshmcp call 100.x.y.z:9101 add --arg a=2 --arg b=40
```

See the top-level `README.md` for the full command reference and
`docs/` for architecture, the HA / tool-mesh design, and the roadmap.
