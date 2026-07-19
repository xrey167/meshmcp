# Baking meshmcp into LLM client hooks (F33)

meshmcp already governs the tools it fronts on the mesh. But an LLM client —
Claude Code, Cursor, Codex — also calls **local** tools (`Bash`, `Edit`,
`Read`, native MCP servers) that never touch the mesh. To govern *those*,
meshmcp plugs into the client's own **pre-tool hook**: the point where the
client hands a tool + arguments to an external command and takes back an
allow / deny / ask verdict.

`meshmcp hook` is that command. It reads the client's hook JSON on stdin,
evaluates the tool call against a local policy engine (+ DLP), records the
verdict in the tamper-evident audit ledger, and writes the client-specific
response on stdout. **No mesh join is required** — this is the same policy
engine, audit chain, and DLP the gateway uses, running locally.

The result: *every* tool the model calls flows through the same firewall and
audit as mesh traffic. `meshmcp status --audit <log>` shows the model's local
Bash/Edit/MCP activity next to everything else.

## The client hook surfaces

| Client | Hook | Config | Input → Output |
|---|---|---|---|
| **Claude Code** | `PreToolUse` (also `PostToolUse`, `UserPromptSubmit`) | `.claude/settings.json` `hooks` | `{tool_name, tool_input}` → `{"hookSpecificOutput":{"permissionDecision":"allow|deny|ask"}}` |
| **Cursor** (1.7+) | `beforeShellExecution`, `beforeMCPExecution` | `.cursor/hooks.json` | `{tool_name|command|url, tool_input}` → `{"permission":"allow|deny|ask","agentMessage":…}` |
| **Codex** | `PermissionRequest` | `~/.codex` hooks | `{tool_name, tool_input}` → `{"decision":"allow|deny|decline"}` |
| **Claude Desktop / Windsurf** | MCP-config only (no lifecycle hook) | `mcpServers` / `mcp_config.json` | govern via `meshmcp connect` (the transport path) |

meshmcp maps its three-valued verdict onto each dialect: **allow → allow**,
**deny → deny**, **co-sign → ask/decline** (defer to the client's own human
prompt; for full mesh co-sign, route the approval to `meshmcp approvals`).

## Wire it up

```bash
# 1. Author a policy (reuses the gateway's Policy + DLP types).
cp examples/hook-policy.yaml ./meshmcp-hook.yaml

# 2. Print the hook config for your client and add it to that client's settings.
meshmcp hook install --client claude-code --config ./meshmcp-hook.yaml
meshmcp hook install --client cursor      --config ./meshmcp-hook.yaml

# 3. From then on, every tool call is governed + audited:
meshmcp status --audit ./hook-audit.jsonl
```

## Two layers, one firewall

- **Transport layer** (`meshmcp connect`, the gateway): governs tools that are
  mesh backends — full policy incl. taint, secret injection, capabilities.
- **Hook layer** (`meshmcp hook`): governs the client's *own* local tools —
  policy, DLP, rate/window/co-sign, and audit — where they'd otherwise be
  ungoverned.

Together they close the gap: the model can't reach a tool, local or remote,
that isn't authorized and recorded.

## Three events, one adapter

`meshmcp hook` dispatches on the hook event (auto-detected from the payload's
`hook_event_name`, or forced with `--event`):

- **pre-tool** (`PreToolUse` / `beforeShellExecution` / `beforeMCPExecution` /
  `PermissionRequest`) — authorize the call: policy + DLP + rate/window/co-sign,
  carrying session taint, and return allow/deny/ask.
- **post-tool** (`PostToolUse` / `afterFileEdit` / `afterMCPExecution`) —
  observe-only: record the result with a **content hash** of the output for
  provenance (proves what a tool returned without storing the bytes).
- **prompt** (`UserPromptSubmit` / `beforeSubmitPrompt`) — DLP-scan the prompt
  and **block** on a match (e.g. a prompt-injection phrase); record it by hash.

## Prompt-injection defense inside the client (taint)

Set `session_dir` and `taint_tools` and the adapter carries F7's taint across
the client's own tool loop: a local tool that pulls untrusted content
(`WebFetch`, a browser MCP) marks the session tainted, and a later `Write`/`Edit`
with `taint_guard` is **blocked** — the same network-layer prompt-injection
containment the gateway does, now for local tools. Taint is per-session
(keyed on `session_id` / `conversation_id`).

## Human co-sign from your phone

Point `cosign_store` at the same directory `meshmcp approvals` serves. A
`require_cosign` local tool returns "ask" and records a pending request; a human
approves it from a phone on the mesh (`meshmcp approvals`), and the next call is
allowed — a local Bash/Deploy gated by a mesh identity's approval.

## Backlog

- `hook install --write` to merge the config into the client settings in place.
- `SessionStart` context injection (tell the model the policy it's under).
