<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# prompt_mcp

## Purpose
A real, full-featured MCP stdio server built on the `meshmcp/mcp` framework. It exposes tools, prompts, resources, and a long-running task, and is the backend most examples and showcase agents talk to through the gateway. Each capability lives in its own file under a subpackage, registered via a `registerX(s)` function.

## Key Files
| File | Description |
|------|-------------|
| `main.go` | `package main`: constructs the `mcp.Server`, registers all tools/prompts/resources, and serves over stdio. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `tools/` | One file per tool: `add`, `echo`, filesystem (`list_dir`/`read_file`/`write_file`, sandboxed to a root), `run_command` (guarded — only allow-listed command names), `slow_count` (long-running, best called as a task), and `demo` (canned showcase tools: `charge`, `fetch`, `read_customer`, …). |
| `prompts/` | One file per prompt: `codereview`, `summarize`. |
| `resources/` | One file per resource: `info`, `time`, and `peer` (the connected mesh peer's identity, as injected by the gateway). |

## For AI Agents

### Working In This Directory
- The registration pattern is one file per capability exposing `registerX(s *mcp.Server)`, aggregated in `tools.go`/`prompts.go`/`resources.go`. Follow it when adding a capability.
- Tool names here are referenced by policy/examples (e.g. `run_command`, `read_file`, `charge`, `fetch`) and by agent role scripts and taint-demo configs — **renaming a tool means updating those configs and tests** (a rename of `list`→`list_dir` previously broke an agent test).
- `run_command` is intentionally guarded (allow-listed command names only); `fetch` is used as a taint source in the data-flow demos; the `fs` tools are sandboxed to a root. Preserve these safety properties.
- `peer` resource surfaces the caller identity the gateway injects — it demonstrates identity flowing all the way to the backend.

### Testing Requirements
- Built and driven by root integration tests and the `demo/` scripts. Rebuild `mcpserver.exe` after changes so example configs pick them up.

## Dependencies

### Internal
- `mcp/` (server framework). The gateway injects caller identity that `resources/peer.go` reads.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
