<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# mcpecho

## Purpose
A minimal but real MCP stdio server used mainly as a **resumable-session test backend**. Small enough to reason about while exercising the session layer's reconnect/replay behavior.

## Key Files
| File | Description |
|------|-------------|
| `main.go` | `package main`: registers a trivial echo-style tool set on an `mcp.Server` over stdio. |

## For AI Agents

### Working In This Directory
- Keep it minimal and deterministic — its value is as a predictable backend for `session/` and `connect --resumable` tests.

## Dependencies

### Internal
- `mcp/`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
