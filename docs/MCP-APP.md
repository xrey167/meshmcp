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
      "args": ["mcp", "--audit", "./demo/audit.jsonl", "--cosign-store", "./demo/cosign"],
      "env": { "NB_SETUP_KEY": "<your-reusable-setup-key>" }
} } }
```

**Codex** — `~/.codex/config.toml`:

```toml
[mcp_servers.meshmcp]
command = "meshmcp"
args = ["mcp", "--audit", "./demo/audit.jsonl", "--cosign-store", "./demo/cosign"]
env = { NB_SETUP_KEY = "<your-reusable-setup-key>" }
```

- `--audit` / `--cosign-store` point at the gateway's ledger and co-sign dir
  (the read-only tools work with just these).
- `NB_SETUP_KEY` lets it **join the mesh** and drive backends. Without it, the
  network/pending/verify tools still work; the mesh-driving tools return a clear
  "not connected" message.

## The tools it exposes

| Tool | What the assistant can do |
|---|---|
| `network` | Show the live mesh: servers, agent identities, recent decisions, chain status. |
| `list_tools` | List a backend's tools/resources/prompts. `{target}` |
| `call_tool` | Call a tool on a backend (policy-governed + audited). `{target, tool, arguments}` |
| `run` | Run an allow-listed command via the backend's `run_command`. `{target, command, args}` |
| `pending_approvals` | List held `require_cosign` calls awaiting a decision. |
| `approve` / `deny` | Resolve a held co-sign for `{peer, tool}` (approve writes an attributed grant). |
| `audit_verify` | Verify the tamper-evident chain (`{checkpoints, pubkey}` for signed verification). |

## What it feels like

Once added, you can just ask:

- *"Show me the mesh network"* → `network` → the servers, who's active, chain intact.
- *"What tools does 100.64.0.2:9101 have?"* → `list_tools`.
- *"Add 2 and 40 on the fs backend"* → `call_tool` (governed + audited).
- *"Run `git status` on the deploy backend"* → `run` (allow-listed only).
- *"Anything waiting for approval?"* → `pending_approvals`.
- *"Approve the transfer for billing.mesh"* → `approve`.
- *"Prove the audit log wasn't edited"* → `audit_verify`.

Every drive action the assistant takes appears in the same audit ledger and
Control Room feed as any other caller — because it *is* one.

## Safety

- The MCP app dials backends as its own mesh identity, so the gateway's policy
  (rate limits, taint, labels, co-sign) applies to whatever the assistant tries —
  it cannot bypass the firewall.
- There is **no local-shell tool** here (unlike the Control Room's opt-in `sh`):
  the assistant can only run **allow-listed** `run_command` on backends that
  permit it, and only over the mesh.
- `approve`/`deny` write to the co-sign store you point it at; scope that store
  to what you're comfortable letting the assistant resolve.
