# meshmcp as an MCP app — operate the mesh from Claude Code / Codex

`meshmcp mcp` runs meshmcp *itself* as an MCP server. Add it to Claude Code or
Codex and the assistant can **operate your agent mesh** through tool calls: see
the live network, drive backends, run governed commands, and handle co-sign
approvals — all still routed through the gateway's policy and audit, so the
assistant is just another governed mesh client, not a backdoor.

## Add it

**Claude Code** — `~/.claude.json` (or your project's `.mcp.json`):

```jsonc
{ "mcpServers": {
    "meshmcp": {
      "command": "meshmcp",
      "args": ["mcp", "--audit", "./demo/audit.jsonl", "--cosign-store", "./demo/cosign",
               "--control", "100.64.0.2:9600"],
      "env": { "NB_SETUP_KEY": "<your-reusable-setup-key>" }
} } }
```

**Codex** — `~/.codex/config.toml`:

```toml
[mcp_servers.meshmcp]
command = "meshmcp"
args = ["mcp", "--audit", "./demo/audit.jsonl", "--cosign-store", "./demo/cosign", "--control", "100.64.0.2:9600"]
env = { NB_SETUP_KEY = "<your-reusable-setup-key>" }
```

- `--audit` / `--cosign-store` point at the gateway's ledger and co-sign dir
  (the read-only tools work with just these).
- `NB_SETUP_KEY` lets it **join the mesh** and drive backends. Without it, the
  network/pending/verify tools still work; the mesh-driving tools return a clear
  "not connected" message.
- `--control <gateway-ip:port>` points at the gateway's [Air control
  endpoint](AIR-STEER.md) so `air_sessions`/`air_steer` can list and steer live
  sessions (enable it in the gateway config with a `control:` block).
- `--allow-launch` (off by default) opts in to the `air_launch` tool, which
  spawns agent processes — like the Control Room's `--local-shell`.

## The tools it exposes

Operate the mesh:

| Tool | What the assistant can do |
|---|---|
| `network` | Show the live mesh: servers, agent identities, recent decisions, chain status. |
| `list_tools` | List a backend's tools/resources/prompts. `{target}` |
| `call_tool` | Call a tool on a backend (policy-governed + audited). `{target, tool, arguments}` |
| `run` | Run an allow-listed command via the backend's `run_command`. `{target, command, args}` |
| `pending_approvals` | List held `require_cosign` calls awaiting a decision. |
| `approve` / `deny` | Resolve a held co-sign for `{peer, tool}` (approve writes an attributed grant). |
| `audit_verify` | Verify the tamper-evident chain (`{checkpoints, pubkey}` for signed verification). |
| `show_retrievals` | Show provenance receipts from the audit log — "what did the agent read?". |

Air — move payloads and drive live work ([AIR.md](AIR.md), [AIR-STEER.md](AIR-STEER.md)):

| Tool | What the assistant can do |
|---|---|
| `air_peers` | List reachable mesh identities. |
| `air_send` | Resolve a verified Nearby node and deliver text plus an optional file/directory in one bounded session. `{to, text?, path?, name?}` |
| `air_push` | Push text to either a verified Nearby node or legacy address. `{to\|target, text, name?}` |
| `air_fetch` | Fetch a blob by sha256 from a peer's store. `{target, hash}` |
| `drop_file` | Drop a local file to either a verified Nearby node or legacy address. `{to\|target, path}` |
| `air_sessions` | List the gateway's live sessions (needs `--control`). |
| `air_steer` | Steer a live session. `{backend, id, method, params}` (needs `--control`). |
| `air_tasks` | List a backend's running/finished tasks. `{target}` |
| `air_task_steer` | Augment a running task in-flight. `{target, task_id, payload}` |
| `air_launch` | Spawn a new agent (opt-in `--allow-launch`). `{role, gateway}` |
| `pubsub_publish` | Publish an event to a broker topic. `{target, topic, data, json?, retain?}` |
| `pubsub_stats` | Query a running broker's snapshot (subscribers, sequence, drops). `{target}` |

Resolved `air_send`, `air_push`, and `drop_file` calls return the shared
`air.action-result/v1` metadata envelope. It contains bounded per-payload
receipts, never payload bodies or local source paths. Legacy raw-target calls
retain their existing text responses for compatibility.

For example, a confirmed two-payload result is:

```json
{
  "schema": "air.action-result/v1",
  "status": "delivered",
  "recipient": {
    "name": "Analyst",
    "fqdn": "analyst.mesh.example",
    "public_key": "full-transport-public-key",
    "service": "inbox",
    "address": "100.64.0.23:9110"
  },
  "payloads": 2,
  "bytes": 17,
  "receipts": [
    {
      "schema": "air.action-receipt/v1",
      "action": "push",
      "status": "delivered",
      "recipient": {
        "name": "Analyst",
        "fqdn": "analyst.mesh.example",
        "public_key": "full-transport-public-key",
        "service": "inbox",
        "address": "100.64.0.23:9110"
      },
      "payload_name": "note.txt",
      "bytes": 5,
      "time": "2026-07-23T10:15:30Z"
    },
    {
      "schema": "air.action-receipt/v1",
      "action": "drop",
      "status": "delivered",
      "recipient": {
        "name": "Analyst",
        "fqdn": "analyst.mesh.example",
        "public_key": "full-transport-public-key",
        "service": "inbox",
        "address": "100.64.0.23:9110"
      },
      "payload_name": "report.pdf",
      "bytes": 12,
      "time": "2026-07-23T10:15:30Z"
    }
  ]
}
```

`delivered` means the selected inbox advertised `drop.complete.v1` and returned
a nonce-bound `meshmcp.drop-completion/v1` `installed` status with exact payload
and byte totals. Rejection, mismatch, malformed/missing completion, or timeout
returns an error instead of this object. If installation may have happened
before confirmation was lost, the error warns against a blind retry. An inbox
can advertise support with `--service inbox=9110,drop.complete.v1`; the receiver
ACL/policy remains authoritative. A resolved client refuses older Presence
cards without that capability, while explicit `target: "host:port"` calls keep
the legacy response contract.

## What it feels like

Once added, you can just ask:

- *"Show me the mesh network"* → `network` → the servers, who's active, chain intact.
- *"What tools does 100.64.0.2:9101 have?"* → `list_tools`.
- *"Add 2 and 40 on the fs backend"* → `call_tool` (governed + audited).
- *"Anything waiting for approval?"* → `pending_approvals` → *"Approve the transfer for billing.mesh"* → `approve`.
- *"Who's on the mesh?"* → `air_peers`. *"List the live sessions."* → `air_sessions`.
- *"Steer session 9f2a on fs to re-read customer 42."* → `air_steer`.
- *"What tasks are running on the analyst?"* → `air_tasks` → *"Nudge task-17 to focus on the API."* → `air_task_steer`.
- *"Prove the audit log wasn't edited."* → `audit_verify`.

Every drive action the assistant takes appears in the same audit ledger and
Control Room feed as any other caller — because it *is* one.

## Safety

- The MCP app dials backends as its own mesh identity, so the gateway's policy
  (rate limits, taint, labels, co-sign) applies to whatever the assistant tries —
  it cannot bypass the firewall.
- There is **no local-shell tool** here (unlike the Control Room's opt-in `sh`):
  the assistant can only run **allow-listed** `run_command` on backends that
  permit it, and only over the mesh.
- `air_launch` — which spawns an agent **process** — is **off by default**; it
  only works if you started the app with `--allow-launch` (the same opt-in
  posture as the Control Room's `--local-shell`).
- `air_steer` and `air_task_steer` are governed too: session steer goes through
  the gateway's identity-gated, audited control endpoint, and task steer is a
  policy `methods:`-governed `tasks/steer` call — the assistant cannot steer past
  the firewall.
- `approve`/`deny` write to the co-sign store you point it at; scope that store
  to what you're comfortable letting the assistant resolve.
