<!-- Parent: ../AGENTS.md -->

# cmd/scheduler

## Purpose
A governed scheduler / cron MCP server (F27): identity-attributed scheduled tool
calls over the mesh. `schedule(tool, args, run_at|every)` registers a job stamped
with the caller's mesh identity; `due` returns jobs that are ready (advancing
recurring jobs, marking one-shots done); `list` / `cancel` manage them. The
scheduler is PURE STATE — it never calls out. A separate worker drains `due` and
makes the actual calls, where the firewall governs and audits them, so every
fired action stays attributable and policy-gated.

## Key Files
| File | Description |
|------|-------------|
| `main.go` | `scheduleStore` (JSONL snapshot, injectable clock) + the four MCP tools. |
| `main_test.go` | One-shot vs recurring `due` semantics with a fake clock + cancel/persist. |

## For AI Agents
- Built on the dependency-free `mcp/` framework, like `cmd/bus` / `cmd/memory`.
- The store takes a `now func() time.Time` so time-based logic is testable — keep
  it injectable; do not call `time.Now()` inside the store methods.
- Snapshot writes are atomic (temp+rename), `0600`. Keep tool names stable or
  update `examples/scheduler.yaml` together.

### Testing
- `CGO_ENABLED=1 go test ./cmd/scheduler/ -race`.
