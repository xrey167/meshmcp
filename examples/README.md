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
| `agent-firewall.yaml` | `serve` | The full policy engine: rate limits, time windows, taint tracking, and human co-sign — plus a tamper-evident audit log. |
| `federate.yaml` | `federate` | A cross-org federation boundary: bridge granted tools between two meshes, identity-mapped and audited. |
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

## The agent firewall + control plane

```bash
# Enforce rate limits / windows / taint / co-sign and a tamper-evident audit
meshmcp serve --config examples/agent-firewall.yaml

# A human co-signs a held privileged call
meshmcp approve --store ./cosign <peer-fqdn> transfer_funds

# Prove the audit log was not edited, then watch it live
meshmcp audit verify ./agent-firewall-audit.jsonl
meshmcp dash        --audit ./agent-firewall-audit.jsonl   # http://127.0.0.1:9800

# Non-repudiable: sign checkpoints, then verify with the public key alone
meshmcp audit keygen --out ./audit-signing-key.json
#   (set audit_checkpoints + audit_signing_key in the backend config)
meshmcp audit verify ./agent-firewall-audit.jsonl \
  --checkpoints ./agent-firewall-cps.jsonl --pubkey <public-key>

# Replay a recorded session against a backend and diff every response
meshmcp replay ./trace.jsonl 100.x.y.z:9110 --fork 5

# Run the managed control plane (enrollment, registry, policy distribution)
meshmcp control --registry ./registry --policies ./policies --enroll-key <key>
```

See the top-level `README.md` for the full command reference,
`docs/AGENT-FIREWALL.md` for the policy engine and audit design, and
`docs/` for architecture, the HA / tool-mesh design, and the roadmap.
