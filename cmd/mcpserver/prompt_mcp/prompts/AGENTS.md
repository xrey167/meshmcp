<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# prompts

## Purpose
The demo server's MCP prompts, one file per prompt. Each exposes a `registerX(s *mcp.Server)` function aggregated by `prompts.go`.

## Key Files
| File | Description |
|------|-------------|
| `prompts.go` | Package doc + aggregator that registers all prompts. |
| `codereview.go` | A code-review prompt template. |
| `summarize.go` | A summarize prompt template. |

## For AI Agents

### Working In This Directory
- Add a prompt as a new `registerX` file and wire it into `prompts.go`, mirroring the `tools/` pattern.

## Dependencies

### Internal
- `mcp/`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
