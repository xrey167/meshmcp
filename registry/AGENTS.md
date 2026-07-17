<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# registry

## Purpose
A file-based service registry. MCP backends register themselves (name, mesh address, tools) into a shared directory, and the aggregating router reads it for discovery and failover. Deliberately simple and filesystem-backed so multiple gateway processes can share it without a database.

## Key Files
| File | Description |
|------|-------------|
| `registry.go` | Package doc + register / list / deregister over a directory of entries; the discovery source for `meshmcp router`. |

## For AI Agents

### Working In This Directory
- Concurrent processes read/write the same directory; keep writes atomic (temp-file + rename) and tolerate stale/partial entries on read.
- Entries are operational state — a missing or extra entry must degrade gracefully, never panic the router.

### Testing Requirements
- `CGO_ENABLED=1 go test ./registry/ -race`.

## Dependencies

### Internal
- Enabled by the `registry:` config key; consumed by root `router.go`. Backends deregister on shutdown in `serve.go`.

### External
- Standard library only.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
