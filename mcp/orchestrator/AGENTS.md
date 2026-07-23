<!-- Parent: ../AGENTS.md -->

# mcp/orchestrator

## Purpose
The dark MCP service that exposes the `harness` engine's capabilities as a tool
catalog on meshmcp's MCP transport (zero public ports). Tool names keep the
source projects' names so existing agent prompts port over unchanged. Every tool
call passes the harness `Governor` (policy.Engine + policy.AuditLog): default-deny
by the caller's role, one hash-chained audit record per call.

## Key Files
| File | Description |
|------|-------------|
| `server.go` | `Server`: builds an `mcp.Server`, installs `RecoverPanics` + the `govern` GLOBAL middleware, registers the catalog. `govern` authorizes every call via `harness.Governor.Guard` and returns an error result on deny/cosign. |
| `labels.go` | `toolLabels`: each tool → its data-flow labels (attached to the `GovernedAction` for the firewall + audit). |
| `tools_delegate.go` | task, call_agent, background_output/cancel, synthesize (+ background job registry). |
| `tools_plan.go` | plan, plan_review, interview, start_work, review_work, ultragoal_check. |
| `tools_code.go` | grep/glob/edit (real, local fs); lsp_*, ast_grep_*, look_at (governed; Phase-2 backend). |
| `tools_session.go` | session_* (governed; Phase-2 backend) + task_* (in-mem store, air-backed in prod). |
| `tools_env.go` | interactive_bash (real local exec); browser/canvas/nodes/cron (governed; Phase-2/4 driver). |
| `tools_skill.go` | skill, skill_mcp, market (governed; Phase-2 loader/bridge). |
| `schema.go` `taskstore.go` | Schema/result helpers; the task_* backing store. |

## For AI Agents

### Working In This Directory
- Governance is registered as GLOBAL middleware in `New` (`s.mcp.Use(...)`), so a
  new tool is governed automatically. Add its labels to `labels.go` so the
  firewall + audit see the right classification.
- The default caller is a run-scoped `orchestrator` identity (delegating,
  non-writing) — so `edit`/`exec.shell` tools are DENIED to it by design; drive
  writes by delegating (`task`/`call_agent`) or `SetCaller` to an executor role.
  This is a correct governance demonstration, not a bug.
- Tools whose live backend is deferred use `pendingBackend`: they are authorized
  and audited but fail closed with an explanatory note — never a silent success.

### Testing Requirements
- `CGO_ENABLED=1 go test ./mcp/orchestrator/ -race`. `server_test.go` drives the
  server through `mcpclient` over `net.Pipe` and asserts the governance boundary
  (grep allowed, edit denied for orchestrator; executor may edit) and that the
  audit chain still verifies.

## Dependencies

### Internal
- `harness` (the engine + Governor), `mcp` (server framework), `mcpclient`
  (tests), `policy` (outcomes). Served by `cmd/meshmcp harness serve`.

### External
- Standard library only.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
