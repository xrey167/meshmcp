<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# resources

## Purpose
The demo server's MCP resources, one file per resource. Each exposes a `registerX(s *mcp.Server)` function aggregated by `resources.go`.

## Key Files
| File | Description |
|------|-------------|
| `resources.go` | Package doc + aggregator that registers all resources. |
| `info.go` | Static server info resource. |
| `time.go` | Current-time resource. |
| `peer.go` | The connected mesh peer's identity, as injected by the gateway — demonstrates caller identity reaching the backend. |

## For AI Agents

### Working In This Directory
- `peer.go` reads the identity the gateway injects; it's the backend-side proof that meshmcp attributes every call. Keep that wiring intact.
- Add a resource as a new `registerX` file and wire it into `resources.go`.

## Dependencies

### Internal
- `mcp/`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
