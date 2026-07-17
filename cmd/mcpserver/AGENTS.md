<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# mcpserver

## Purpose
The full-featured demo MCP stdio server — the primary backend the showcase, cookbook, and example configs run behind meshmcp. It builds to `mcpserver.exe` (referenced as `./cmd/mcpserver/mcpserver.exe` in `examples/*.yaml`). The actual server source lives in the `prompt_mcp/` subpackage.

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `prompt_mcp/` | The server implementation: `main.go` plus `tools/`, `prompts/`, `resources/` subpackages (see `prompt_mcp/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- The `transports/` directory and any `mcp-server/` scaffold here are **not** part of the built package (`go list` shows only `prompt_mcp` and its subpackages). Don't document or wire stray scaffolding.
- Build with `go build -o cmd/mcpserver/mcpserver.exe ./cmd/mcpserver/prompt_mcp` so the path in the example configs resolves.

## Dependencies

### Internal
- `mcp/` framework; consumed as a backend by `examples/` and the demo scripts.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
