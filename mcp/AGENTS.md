<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# mcp

## Purpose
A small, dependency-free MCP **server** framework speaking the 2025-06-18 protocol over newline-delimited JSON-RPC 2.0. It is used to build the test/demo backends (`cmd/`) and meshmcp's own `mcp` app. Supports tools, resources, prompts, and the async task lifecycle, plus composable middleware around tool handlers.

## Key Files
| File | Description |
|------|-------------|
| `server.go` | `Server`: registration of tools/resources/prompts, the read loop, dispatch, and `Use`/`UseTool` middleware installation. |
| `session.go` | `Session` — the per-connection handle handlers use to send notifications (`Notify`/`Progress`/`Log`); `WithSession`/`SessionFrom`. Backed by `outConn`, which serializes all writes to the client stream so concurrent handlers can't interleave. |
| `tasks.go` | The MCP task lifecycle: `start`, status values, `tasks/get`/`tasks/result`/`tasks/cancel`/`tasks/steer`. Threads the composed handler through async execution and exposes `SteerChan(ctx)` so a cooperative handler receives mid-flight guidance over a bounded, non-blocking steer buffer. |
| `middleware.go` | `ToolHandler`, `ToolMiddleware`, `ToolCallInfo`, `withToolCall`/`ToolCallFrom`, `effectiveHandler`, and built-ins `RecoverPanics`/`Timeout`/`LimitConcurrency`. |
| `idempotency.go` | `Idempotency` middleware enforcing the router's `_meta["meshmcp.io/idempotency-key"]`: atomic claim scoped per (tool, key), single-flight duplicates, cached terminal outcome (capped at `MaxCachedResultBytes`), TTL horizon, generation-guarded `Complete` (a stale winner never overwrites a successor's claim), fail-closed on store errors. `ClaimStore` + bounded `MemClaimStore`; PostgreSQL backend in `pgstore`, conformance harness in `claimtest/`. |
| `http.go` | `WithHTTPHeaders` — attach request headers to a handler context (Streamable-HTTP servers). |
| `subscriptions.go` | The draft `subscriptions/listen` stream: `handleListen`, `NotifyToolsChanged`/`NotifyPromptsChanged`/`NotifyResourcesChanged`/`NotifyResourceUpdated`, ack + terminal `complete`. Served when used; not advertised in the 2025-06-18 initialize capabilities. |

## For AI Agents

### Working In This Directory
- `mcp.Content` is a **struct** with a `.Text` field — do not type-assert to `mcp.TextContent`.
- Middleware order is outermost-first: `mws[0]` wraps `mws[1]` … wraps the handler; global middleware wraps per-tool middleware. The composed handler must run identically for sync and task calls (both go through `s.tasks.start`).
- All client writes go through `outConn`; never write to the raw stream directly from a handler.

### Testing Requirements
- `CGO_ENABLED=1 go test ./mcp/ -race`. See `middleware_test.go` (composition/order) and `tasks_test.go` (lifecycle).

## Dependencies

### Internal
- Used by `cmd/*` backends and root `mcpapp.go`. Paired with `mcpclient/` on the calling side.

### External
- Standard library only (`encoding/json`, `bufio`, `context`).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
