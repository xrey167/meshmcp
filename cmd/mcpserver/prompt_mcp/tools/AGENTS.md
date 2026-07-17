<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# tools

## Purpose
The demo server's tools, one file per tool. Each exposes a `registerX(s *mcp.Server)` function aggregated by `tools.go`. These are the tool names the example policies, capabilities, secrets grants, and agent role scripts reference.

## Key Files
| File | Description |
|------|-------------|
| `tools.go` | Package doc + aggregator that registers all tools. |
| `add.go` · `echo.go` | Trivial `add` and `echo` tools. |
| `fs.go` | Filesystem tools (`list_dir`, `read_file`, `write_file`), all sandboxed to a root. |
| `runcommand.go` | `run_command` — guarded shell tool; only allow-listed command names run. |
| `slowcount.go` | `slow_count` — long-running tool, best invoked as a task. |
| `demo.go` | Canned showcase tools for the mesh agents (`charge`, `fetch` (taint source), `read_customer`, `language`, `code`, `text`). |

## For AI Agents

### Working In This Directory
- Add a tool as a new `registerX` file and wire it into `tools.go`.
- Tool names are a cross-repo contract (policy/examples/agent scripts/tests). Renaming requires updating those. Keep `run_command` allow-listed and `fs` sandboxed.

## Dependencies

### Internal
- `mcp/`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
