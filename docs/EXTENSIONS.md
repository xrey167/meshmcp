# Extensions

Three capability surfaces added on top of the core gateway. Each is additive —
nothing here changes existing behavior unless you opt in — and each was built
against meshmcp's own baseline (MCP 2025-06-18, the three-valued policy engine,
the hash-chained audit) rather than dropped in from elsewhere.

- [Signed capabilities](#signed-capabilities) — short-lived, subject-bound tool grants
- [Server middleware](#server-middleware) — compose cross-cutting behavior around tool calls
- [Typed function calls & task client](#typed-function-calls--task-client) — provider-neutral tool invocation

---

## Signed capabilities

A capability is a short-lived, cryptographically signed grant that lets a caller
reach a tool the static policy would otherwise **default-deny** — without editing
the gateway config. An authority issues it out of band; the gateway verifies it
at the enforcement point.

It is deliberately weak where it needs to be. A capability can only **upgrade a
policy-DEFAULT deny to allow**. It cannot:

- override an explicit `allow: false` rule (explicit deny always wins),
- bypass a `require_cosign` gate (a co-sign requirement still holds),
- carry its own trust root (the gateway only honors signatures from **pinned**
  authority keys), or
- outlive its 24h ceiling.

Every check **fails closed**: a missing token on a `required` surface, an
expired token, a wrong-subject/wrong-audience/wrong-tool token, a token from an
unpinned authority, or a malformed token all result in a deny, and the call
never reaches the backend.

### Binding and stripping

Each grant is bound to three things the gateway proves independently:

| Claim      | Bound to                                             |
|------------|------------------------------------------------------|
| `subject`  | the caller's **transport-proven WireGuard key**      |
| `audience` | a single backend name                                |
| `tools`    | a set of tool-name globs (e.g. `read_*`, `get_balance`) |

The token travels in `params._meta` under the key `com.meshmcp/capability`. A
caller typically sets it once for a session, so it rides along on follow-up
requests (task-status polls, `tools/list`). The gateway therefore **strips it
from every governed client→backend line** — not just `tools/call` — before the
request reaches the backend, the trace, the audit record, or secret injection.
It is only *honored* on `tools/call`; everywhere else it is simply removed, so a
backend never sees the token and it never lands in a log.

### Precedence

For a given `tools/call`, the outcome is:

1. Explicit policy **deny** (a matching `allow: false` rule) → **deny**. A
   capability cannot override this.
2. Policy **co-sign** required → **co-sign** (unchanged). A capability does not
   satisfy a human co-sign.
3. Policy **default** deny (no matching rule) + a **valid** capability → **allow**.
4. `required: true` and **no** token → **deny** (`capability required`).
5. Any **invalid** token presented → **deny** (`invalid capability: …`).

### Configure

Two shapes, both in [`examples/capabilities.yaml`](../examples/capabilities.yaml):

```yaml
backends:
  # Capability-only surface: every call must present a valid grant.
  - name: finance
    port: 9130
    stdio: ["./mcpserver"]
    capabilities:
      required: true
      trusted_public_keys: ["<authority-pubkey-hex>"]

  # Policy + capabilities: policy is the floor; a grant upgrades a default-deny.
  - name: ledger
    port: 9131
    stdio: ["./mcpserver"]
    capabilities:
      required: false            # only upgrades a policy-default call
      trusted_public_keys: ["<authority-pubkey-hex>"]
    policy:
      default_allow: false
      rules:
        - { peers: ["*"], tools: ["read_*"], allow: true }
        - { peers: ["*"], tools: ["delete_all"], allow: false }  # capability can't override
```

Validation rules (enforced at load): capabilities are stdio-only, need at least
one `trusted_public_keys` entry, and with `required: false` need a
deny-by-default policy (a capability only upgrades a policy-default call, so
there must be a policy for it to upgrade).

### Issue and present

```bash
# One-time: mint an authority key. Keep the private file 0600; pin the hex.
meshmcp capability keygen --out capability-key.json

# Issue a 15-minute grant for one agent, bound to one backend and two tools.
# The token goes to stdout (redirect to a 0600 file); the note goes to stderr.
meshmcp capability issue --key capability-key.json \
  --subject <agent-wireguard-key> --audience finance \
  --tool 'read_*' --tool get_balance --ttl 15m > read.cap

# Present it on a call.
meshmcp call <peer:port> read_invoice --capability @read.cap
```

`--capability` accepts `@file` (recommended — keeps the token out of shell
history) or a literal token. The token is opaque base64url; it is never raw JSON
the backend could mistake for an argument.

### Containment and revocation

A capability's primary containment is its **short lifetime** — keep TTLs tight
(the `issue` default is 15m, and 24h is a hard ceiling). The verifier also
supports an optional **revocation predicate** (`CapabilityVerifier.WithRevocation`,
keyed on the token's unique `cap_…` ID), but it is not yet wired to a
config-driven revocation store, so today short TTLs are the operative control.
Issue narrowly-scoped, short-lived grants rather than relying on being able to
pull one back.

---

## Server middleware

`mcp.Server` composes cross-cutting behavior around tool handlers, so a concern
(timeout, panic recovery, concurrency limiting, logging) is written once and
applied uniformly — including to calls that run **as tasks**, because the
composed handler is threaded through the task runner, not just the synchronous
path.

```go
srv.Use(mcp.RecoverPanics(), mcp.Timeout(30*time.Second))
srv.UseTool("expensive_report", mcp.LimitConcurrency(2))
```

- `Use(...)` installs global middleware (applies to every tool).
- `UseTool(name, ...)` installs per-tool middleware.
- Order is outermost-first: `mws[0]` wraps `mws[1]` wraps … wraps the handler.
- Global middleware wraps per-tool middleware wraps the handler.

A `ToolMiddleware` is `func(ToolHandler) ToolHandler`. Inside a handler,
`mcp.ToolCallFrom(ctx)` exposes the `ToolCallInfo{Tool, RequestID, Meta}` for
the in-flight call. Built-ins: `RecoverPanics()`, `Timeout(d)`,
`LimitConcurrency(n)`.

---

## Typed function calls & task client

`mcpclient` exposes a backend's tools as provider-neutral **functions** and adds
a full **task** client, so an agent runtime can invoke tools by name with a JSON
arguments object and get typed results and errors back.

```go
// Discover tools as functions and invoke one.
fns, _ := mc.ListFunctions(ctx)
res, err := mc.InvokeFunction(ctx, mcpclient.ModelFunctionCall{
    Name:      "get_balance",
    Arguments: `{"account":"ACME"}`,
})
// A tool that returns isError surfaces as *ToolExecutionError, not a silent value.
```

- `ListFunctions` / `InvokeFunction` / `InvokeTool` — provider-neutral calls.
  Arguments are validated to be exactly one JSON object.
- `ToolExecutionError{Tool, Result}` — a tool-reported failure (`isError`)
  becomes a typed Go error rather than an ambiguous success.
- Task client: `StartTool`, `WaitTask` (polls; cancels via
  `notifications/cancelled` on ctx cancel), `GetTask`, `ListTasks`,
  `CancelTask`, `TaskResult`.

CLI parallels: `meshmcp functions <peer:port>`, `meshmcp function-call …`, and
`meshmcp call … --task --wait`.

---

## What was intentionally NOT merged

A larger "fabric" extension pack (OAuth broker, a token-exchange service, a
workflow compiler, a provenance package) was reviewed and **not** integrated: it
targets a different protocol baseline (MCP 2025-11-25), is security-critical
code of external provenance, and is incomplete against this repo (missing
packages, no CLI, no configs). The capability system here was written fresh
against meshmcp's own policy engine and audit, with the invariants above proven
by tests (`policy/capability_test.go`).
