<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# cmd

## Purpose
Standalone MCP servers used as **test and demo backends** behind the gateway. These are the "real MCP servers" the examples and tests put meshmcp in front of — a minimal echo server, a minimal HTTP server, and a full-featured stdio server exercising tools, prompts, resources, and tasks.

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `mcpecho/` | Minimal resumable-test stdio MCP server (see `mcpecho/AGENTS.md`). |
| `mcphttp/` | Minimal Streamable-HTTP-style MCP server (see `mcphttp/AGENTS.md`). |
| `mcpserver/` | The full demo stdio server, built to `mcpserver.exe` (see `mcpserver/AGENTS.md`). |
| `kg/` · `vectors/` · `memory/` | The payload backends: provenance knowledge graph, zero-exposure RAG, agent-memory fabric. |
| `vault/` | **F26** — mesh secrets vault: set/rotate/delete/list secrets into the broker's store; no `get` tool (see `vault/AGENTS.md`). |
| `scheduler/` | **F27** — governed scheduler/cron: identity-attributed scheduled tool calls, drained by a worker (see `scheduler/AGENTS.md`). |
| `bus/` | **F28** — governed event bus: identity-stamped pub/sub with a global cursor (see `bus/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Each subdirectory is its own `package main` building one binary. They depend on the `mcp/` framework, not on the gateway root.
- These servers are what example configs (`examples/*.yaml`) spawn as `stdio:` backends; keep their tool names stable or update the configs and policy examples together.

### Testing Requirements
- Exercised indirectly by the root integration tests (`nettest_test.go`, `replay_test.go`) and by running the demo scripts in `demo/`.

## Dependencies

### Internal
- `mcp/` (server framework).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
