<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# mcpecho

## Purpose
A minimal but real MCP stdio server used mainly as a **resumable-session test backend**. Small enough to reason about while exercising the session layer's reconnect/replay behavior.

## Key Files
| File | Description |
|------|-------------|
| `main.go` | `package main`: a hand-rolled newline-delimited JSON-RPC 2.0 loop over stdio (no `mcp/` framework), implementing `initialize`, `tools/list`, `tools/call` (a single `echo` tool), and `ping`. |

## For AI Agents

### Working In This Directory
- Keep it minimal and deterministic — its value is as a predictable backend for `session/` and `connect --resumable` tests.

## Dependencies

### External
- Standard library only (`bufio`, `encoding/json`).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
