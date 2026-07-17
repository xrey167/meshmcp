<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# federation

## Purpose
A cross-org federation boundary. It bridges a small set of **explicitly granted** tools between two independent meshes/orgs, mapping the remote caller to a local identity and auditing every crossing. Only granted tools are exposed; everything else is invisible across the boundary. Backs `meshmcp federate`.

## Key Files
| File | Description |
|------|-------------|
| `boundary.go` | Package doc + the boundary: relays only granted tools from a local upstream to remote-mesh callers, with identity mapping and audit. |

## For AI Agents

### Working In This Directory
- The boundary is a default-deny surface: a tool not on the grant list must not be listed or callable across the boundary. `boundary_test.go` (`TestFederationBoundaryRelaysGrantedToolOnly`) pins this — keep it.
- Remote identities are mapped to a local identity for policy/audit; preserve that mapping so audit attribution stays meaningful.

### Testing Requirements
- `CGO_ENABLED=1 go test ./federation/ -race`.

## Dependencies

### Internal
- Uses `mcpclient/` (to the upstream) and `mcp/` (to serve the remote side); audited via `policy`. Invoked from root `federate.go`.

### External
- Standard library only.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
