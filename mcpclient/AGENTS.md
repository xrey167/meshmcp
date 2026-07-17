<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# mcpclient

## Purpose
A minimal MCP **client** over any `io.ReadWriteCloser`, plus two higher-level surfaces an agent runtime needs: provider-neutral **function calls** and a full **task** client. Used by the root CLI (`ls`, `call`, `functions`, …) and by the gateway when it acts as a client (router, orchestrate, federate, room).

## Key Files
| File | Description |
|------|-------------|
| `client.go` | `Client`: `Initialize`, `ListTools/Resources/Prompts`, `CallTool`, `ReadResource`, `GetPrompt`. `RequestMeta` is merged into every request's `params._meta` via `withMeta` (this is how `--capability` rides along). |
| `function.go` | Provider-neutral tools-as-functions: `ListFunctions`, `InvokeFunction`/`InvokeTool`, `ToolCallResult`, and `ToolExecutionError` (an `isError` result becomes a typed Go error). Arguments validated to be exactly one JSON object. |
| `tasks.go` | Task client: `StartTool`, `WaitTask` (polls; cancels via `notifications/cancelled` on ctx cancel), `GetTask`, `ListTasks`, `CancelTask`, `TaskResult`, `Task.Terminal()`. |

## For AI Agents

### Working In This Directory
- `Client.RequestMeta` is set once and attached to **every** request — including task-status polls. The gateway relies on stripping meta keys (e.g. capabilities) on every governed line, not just `tools/call`.
- `InvokeFunction` validates that arguments are exactly one JSON object (first char `{`, no trailing tokens) before sending.

### Testing Requirements
- `CGO_ENABLED=1 go test ./mcpclient/ -race`. `extensions_test.go` wires a real `mcp.Server` over pipes to exercise functions + tasks end-to-end.

## Dependencies

### Internal
- Paired with the `mcp/` server framework (both sides of the protocol). Consumed widely by root `cli.go`, `router.go`, `orchestrate.go`, `room.go`.

### External
- Standard library only.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
