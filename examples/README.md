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
| `secrets.yaml` | `serve` | The credential broker: agents reference secrets by name (`{{secret:...}}`) and never hold the value; injection is identity-gated, audited, and refused into a tainted session. |
| `live-task.yaml` | `serve` | A resumable backend exposing an async task tool (`slow_count`) with progress. |
| `http-backend.yaml` | `serve` | An HTTP (Streamable-HTTP) backend reverse-proxied onto the mesh. |
| `router.yaml` | `router` | Aggregate upstreams into one namespaced endpoint; one upstream is a replica set (load-balanced + failover). |
| `router-failover.yaml` | `router` | An upstream with a dead replica first — the router discovers + routes via failover. |
| `orchestrate.yaml` | `orchestrate` | A server-to-server node whose `research` tool calls another server's tools over the mesh. |
| `air-workflow.yaml` | `air workflow` | An [Air](../docs/AIR.md) declarative workflow: launch agents, steer a session, call a tool — run in order, governed + audited. |
| `demo-mesh.yaml` | `serve` | The live showcase gateway: one process fronts four differently-governed backends writing one shared ledger for the Control Room. |
| `capabilities.yaml` | `serve` | Signed capabilities: a short-lived signed grant upgrades a policy-default deny to allow, subject/audience/tool-bound. |
| `continuity.yaml` | `serve` | Session handoff (F5): a shared durable store lets a second gateway rehydrate a live session on failover. |
| `knowledge.yaml` | `serve` | Knowledge graph (F2) + RAG/vector store (F3) backends over the mesh, one shared hash-chained ledger. |
| `graphrag.yaml` | `graphrag` | GraphRAG bridge (S3): `graph_search` combining vectors (F3) + knowledge graph (F2) over the mesh. |
| `vectors-shards.yaml` | `router` | Vector-shard compute mesh (S7): several `vectors` backends behind a router for round-robin LB + failover. |
| `rag-firewall.yaml` | `serve` | Taint-contained RAG (F7): retrieval marks a taint source so egress/write is blocked at the gateway after a search. |
| `dlp-firewall.yaml` | `serve` | Content-aware DLP hook (F18): scans call arguments; denies or tags the session with a data-flow label a later rule enforces. |
| `cost-governance.yaml` | `serve` | Cost/budget governance (F29): per-tool cost weights + cost-weighted rate limits; over-budget calls denied inline. |
| `group-policy.yaml` | `serve` | Group/role-based policy (F17): rules reference `group:<name>` instead of individual keys. |
| `vault.yaml` | `serve` | Mesh secrets vault (F26): a zero-exposure secrets manager (no `get` tool) plus a backend that references secrets by name. |
| `scheduler.yaml` | `serve` | Governed scheduler/cron (F27): identity-attributed scheduled tool calls; a worker drains `due` and calls over the mesh. |
| `bus.yaml` | `serve` | Governed event bus (F28): zero-exposure pub/sub backend; the firewall gates publish vs. poll per topic. |
| `pubsub.yaml` | `pubsub` | Identity-native pub/sub broker: per-topic authorization, publisher-stamped, hash-chained, audited. |
| `hooks.yaml` | `serve` | Gateway hooks: emit firewall decisions to the event bus and/or a webhook; observability only, never blocks. |
| `hook-policy.yaml` | `hook` | Client-hook firewall (F33): governs an LLM client's local tools (Bash/Edit/MCP) with policy + DLP + taint + audit, no mesh join. |
| `drop.yaml` | `drop` | AirDrop receiver across mesh instances: ACL-gated, content-hash-verified, one audit record per file. |

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

# Turn the audit stream into policy (the firewall's read side)
meshmcp insight profile   ./agent-firewall-audit.jsonl              # what agents actually do
meshmcp insight recommend ./agent-firewall-audit.jsonl > policy.yaml # least-privilege policy
meshmcp insight simulate  ./agent-firewall-audit.jsonl --policy policy.yaml  # CI gate (exit≠0 on regressions)
meshmcp insight detect    ./today.jsonl --baseline ./last-week.jsonl # drift → open a co-sign

# Run the managed control plane (enrollment, registry, policy distribution)
meshmcp control --registry ./registry --policies ./policies --enroll-key <key>
```

## Air · Steer — drive live work

```bash
# In the gateway config, add a `control:` block to enable the session endpoint:
#   control: { port: 9600 }
# then, from any mesh peer:
meshmcp air sessions 100.x.y.z:9600                 # list live resumable sessions
meshmcp air steer    100.x.y.z:9600 --backend fs --session <id> --param text="focus"
meshmcp air launch   --role reader 100.x.y.z:9101   # spawn a new agent identity
meshmcp air workflow --dry-run examples/air-workflow.yaml   # validate a workflow
meshmcp air serve    --port 9800 --control 100.x.y.z:9600   # the live Air web page

# Steer an agent whose inbox names this caller (meshmcp agent --steer-port 9120 --steer-allow <identity> ...)
meshmcp air agent-steer 100.x.y.z:9120 --type nudge --text "prioritize the API"
```

See the top-level `README.md` for the full command reference,
`docs/AGENT-FIREWALL.md` for the policy engine and audit design, and
`docs/` for architecture, the HA / tool-mesh design, and the roadmap.
