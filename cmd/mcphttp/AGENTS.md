<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# mcphttp

## Purpose
A minimal HTTP (Streamable-HTTP-style) MCP server, used to test the gateway's **HTTP backend** path (`http:` config key, `meshmcp forward`). The counterpart to `mcpecho` for the reverse-proxy transport instead of stdio.

## Key Files
| File | Description |
|------|-------------|
| `main.go` | `package main`: serves MCP over HTTP on a local port. |

## For AI Agents

### Working In This Directory
- Represents the "MCP server speaking Streamable HTTP" case; used to validate `http-backend.yaml` and `forward`. Keep the endpoint shape aligned with what `serve.go`'s HTTP proxy expects.

## Dependencies

### Internal
- `mcp/` (+ `mcp/http.go` header propagation).

### External
- `net/http`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
