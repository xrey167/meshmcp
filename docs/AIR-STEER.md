# Air · Steer — build spec

**Status: P1 · P2 · P3 + gateway exposure + CLI shipped · P4 (workflow files) proposed.**
This is the design for the *Steer* capability of [Air](AIR.md): address and drive **live
work** — an **agent** (by name), a **session** (by id), or a **task/subagent** (by id) — and
act on it (**send** · **cancel** · **nudge** · **launch**). Implemented and tested: **P3**
task steer/augment ([§4](#4--p3--task-steer--augment)), the **P2** session core
([§3](#3--p2--session-enumeration--injection)), **P1** the agent steer inbox
([§2](#2--p1--steerable-agent-the-receive-path)), the **gateway control endpoint** + `air_*`
tools ([§6](#6--assistant-facing-mcp-tools)), and the **`meshmcp air` CLI**. Only **P4**
declarative workflow files remain. Each primitive names the exact seam it reuses.

> Air's `push` already delivers a payload *to a passive `drop` inbox* — there is no
> consumer that acts on it, and no way to reach a running session or task. Steer closes
> that gap with four small primitives, each modelled on code that already exists.

---

## 0 · What already exists (do not rebuild)

| Need | Already in the tree | Where |
|---|---|---|
| Address by identity | mesh FQDN rows; each is a WireGuard key | `peers.go` (`cmdPeers`) |
| Name → address | logical registry, control-plane `/v1/registry` | `registry/registry.go`, `control/control.go` |
| `<name>.<tool>` namespacing | router proxy tool names | `router.go:421` |
| "on behalf of" origin identity | `_meta` origin stamp on every hop | `router.go:174-176` |
| Server → client push mid-call | bidirectional MCP request/notify (line-framed) | `mcp/server.go:161,224`, `./bidir_test.go` |
| Async work + interrupt | MCP Tasks + governable `tasks/cancel` | `mcp/tasks.go`, `mcpclient/tasks.go`, `examples/live-task.yaml` |
| Resumable session + a live handle to reach it | `Server.sessions[id]` (durable id, ATTACH resume) | `session/server.go`, `session/store.go` |
| Receive-a-payload-by-identity pattern | drop receiver + framing | `drop.go:302-432`, `push.go:33-46` |
| Sender ACL · audit | firewall ACL + hash-chained ledger | `acl.go`, `policy/` |

> **`endpoint.Send` is deliberately *not* in this table.** It exists
> (`session/endpoint.go:80-125`) and is the raw ordered byte pipe, but it is the **wrong
> layer to steer at** — it carries `maxPayload`-sized chunks with no JSON-RPC line boundary,
> so an injected payload can splice into the middle of a message, and an ordinary MCP client
> would not act on unsolicited server→client bytes anyway. Steering a live session goes
> through the **line-framed** `Server.Request`/`Server.Notify` instead (see P2).

Steer is built **entirely** from these; the new code is glue, one store method, one task
channel, and one control endpoint.

---

## 1 · The steer envelope (shared wire type)

One JSON object, framed as a single drop/push record (`sendData`, `push.go:33-46`) so it
rides the same resumable, audited, ACL'd channel as a file drop:

```jsonc
{
  "type": "task" | "cancel" | "nudge" | "launch",
  "tool":   "read_file",          // type=task: the tool to run
  "args":   { "path": "README" }, // type=task: its arguments
  "text":   "focus on the API",   // type=nudge: free-form guidance
  "target": "task:9f2a" ,          // optional: task/session id when addressing sub-work
  "role":   "reader",             // type=launch: agent role or workflow name
  "id":     "str-17"              // caller-chosen correlation id (audited)
}
```

The envelope is the single vocabulary across all three target types; each primitive below
consumes the subset it understands. It is authorized **before delivery, at whichever gate
its transport crosses** — the drop-inbox sender ACL (P1), the control-plane auth (P2), or
the MCP `methods:` policy filter (P3, `tasks/steer`). See [§7](#7--governance--security-all-reused);
the gates differ by path, and only `tasks/steer` is a policy `methods:` rule. Every delivery
is audited with the caller's WireGuard identity.

---

## 2 · P1 — Steerable agent (the receive path)  ✅ *shipped*

Implemented: `steerenvelope.go` (`steerEnvelope`), `steerinbox.go`
(`newSteerFactory`/`recvEnvelopes`, reusing `dropSink`), and `agent.go` — a `--steer-port`
(with `--steer-allow`) starts the agent inbound-enabled via `runSteerableAgent`, and
`runAgentLoop` gained a `steer` channel + `applySteer` (task→`CallTool`, nudge→log,
cancel→stop). The sender is `meshmcp air agent-steer` (`air.go`). Tests:
`TestRunAgentLoopSteerTask`, `TestRecvEnvelopes`. The sketch below is what landed.

**Problem.** `agent.go` is a script-driven **pure client** (`runAgentLoop`,
`agent.go:100-118`) with no way to accept an external instruction — and it is *outbound
only*: `dialMCP` sets `o.BlockInbound = true` (`cli.go:39`), so its mesh client never
listens.

**Design.** Give the agent an inbox by **adding a listener role** modelled on the drop
receiver. This is the biggest of the four changes: the agent flips to inbound-enabled and,
alongside dialling its backend, runs a `session.NewServer` on a **steer port** with its own
`newACL` gate and audit wiring (all the `dropReceive` scaffolding, `drop.go:304-367`), whose
backend factory parses steer envelopes and pushes them onto a channel the loop selects on.
It is *feasible with existing patterns*, not a one-line diff.

```go
// new: a control backend for the agent's steer port — a parallel to newDropFactory
// (drop.go) that parses envelope JSON instead of file frames (not literal reuse).
func newSteerFactory(ch chan<- steerEnvelope, acl *ACL) session.BackendFactory { … }

// agent.go: with the listener in place, the loop gains one more select case.
func runAgentLoop(ctx, mc, steps, count, interval, steer <-chan steerEnvelope, logf) error {
    for {
        select {
        case <-ctx.Done():        return ctx.Err()
        case env := <-steer:      applySteer(ctx, mc, env, logf)  // task → CallTool; nudge → adjust; cancel → stop
        case <-time.After(interval): /* scripted step, as today */
        }
    }
}
```

- **Mirrors (not verbatim):** the `dropReceive` / `newDropFactory` listener shape
  (`drop.go:302-432`), `sendData` (`push.go:33-46`) for the sender, `acl.go` for the sender
  allow-list, and the `policy` audit for one record per delivered envelope. The steer factory
  is a new parallel that reads envelope JSON, not the file-frame parser.
- **Governance:** the steer port is ACL'd exactly like a drop receiver (`examples/drop.yaml`
  `allow:`), so only permitted identities may steer this agent.
- **`type=task`** injects a `mc.CallTool` step; **`nudge`** updates a guidance field the
  agent's next step reads; **`cancel`** breaks the loop. The agent stays a governed mesh
  client — every steered call still hits the gateway firewall.

`meshmcp agent --steer-port 9120 --role reader <gateway>` starts an agent that also
listens for steers.

---

## 3 · P2 — Session enumeration + line-safe steer  ✅ *session core shipped*

Implemented in `session/store.go` (`SessionStore.List` + `MemStore`/`FileStore`) and
`session/server.go` (`serverSession` gained `meta`/`createdAt`, a line-aware backend→peer
pump, `SessionInfo`, `Server.Sessions`, and `Server.Steer`), with `TestStoreList`,
`TestSteerLineFraming`, and `TestSteerUnknownSession`. The **gateway exposure** (a
`/v1/sessions`+`/v1/steer` control endpoint, the `air_sessions`/`air_steer` tools, the CLI)
is the remaining, still-proposed part. The sketch below is what landed.

**Problem.** Sessions have durable, resumable ids, but there was **no `List()`** anywhere
(only `Server.Count()`, `session/server.go`), no metadata retained to describe a live
session, and **no safe way to steer one**.

**Design.** One small store method, plus additions to the session server. The steer goes
through a **line-framed server→client notification**, not the raw byte pipe — the
backend→peer pump was made line-aware and a per-session send lock guarantees an injected line
lands on a boundary.

```go
// session/store.go — enumerate persisted sessions (FileStore scans <dir>/*.json).
type SessionStore interface {
    Save(PersistedSession) error
    Load(id string) (PersistedSession, bool, error)
    DeleteIfOwner(id, owner string) error
    List() ([]PersistedSession, error)   // shipped
}

// session/server.go — serverSession gained meta + createdAt so a live view is possible.
type SessionInfo struct { ID, Peer string; Age time.Duration } // shipped
func (s *Server) Sessions() []SessionInfo                       // shipped

// Steering a live session = a line-framed server→client NOTIFICATION, not ep.Send(bytes).
func (s *Server) Steer(id, method string, params any) error {  // shipped
    sess, ok := s.sessions[parseSessionID(id)]  // guarded by s.mu
    if !ok { return ErrNoSession }
    line, _ := json.Marshal(notification{"2.0", method, params})
    return sess.sendLines(append(line, '\n'))   // sendMu-guarded, chunked to the frame cap
}
```

- **`List()`** on `FileStore` is a directory scan of the files it already writes
  (`<dir>/<id>.json`); `MemStore` returns its map values.
- **Line-safe steer, not `endpoint.Send`.** `ep.Send` is a raw ordered byte pipe and the
  old backend→peer pump forwarded `maxPayload` chunks with no line boundary — injecting there
  could splice mid-JSON-RPC-line. The pump is now **line-aware**: it buffers backend output
  and only ever `Send`s complete-line regions under a per-session `sendMu`; `Steer` marshals a
  JSON-RPC **notification** (no id → no response noise) and `sendLines` it under the same lock,
  so it always lands on a boundary. `TestSteerLineFraming` proves it (including a steer injected
  mid-partial-line and an oversize, multi-frame backend line). The end client must understand
  the steer method to *act*; the transport is generic, the semantics opt-in.
- **`Sessions()` retains just what the session layer knows** — id, peer FQDN, age (from the new
  `createdAt`); a gateway can enrich with a backend label it holds elsewhere.
- **Governance/audit live at the gateway (still proposed).** The session layer is mechanism
  only. Exposure via `control/control.go` — `GET /v1/sessions`, `POST /v1/steer` gated by
  control-plane auth and audited — plus the `air_sessions`/`air_steer` tools (§6) is the next
  increment, not yet built.

---

## 4 · P3 — Task steer / augment  ✅ *shipped*

Implemented in `mcp/tasks.go` (`task.steer` channel, `SteerChan(ctx)`, `taskManager.steer`),
`mcp/server.go` (`tasks/steer` dispatch + `taskSteer`), `mcpclient/tasks.go`
(`Client.SteerTask`), with `TestTaskSteer` in `mcp/tasks_test.go`. The sketch below is what
landed.

**Problem.** A task is **immutable once started** — `tasks/cancel` exists (the JSON-RPC
method is dispatched at `mcp/server.go:378-379` and handled by `taskCancel`,
`mcp/server.go:514-525`; governed in `examples/live-task.yaml:21-23`), but there is no way
to feed new guidance to a running task. *(The separate `notifications/cancelled` handler at
`mcp/server.go:326-341` is the cancel-notification path, not the method.)*

**Design.** Add an input channel to the task and a governed `tasks/steer` method that
mirrors the existing cancel path. The handler receives the steer via **context plumbing**,
the same way the session and tool-call info already reach handlers today — there is no
`TaskContext` type.

```go
// mcp/tasks.go — task gains a steer channel. The real struct (tasks.go:19-28) is:
//   task{ id, tool string; mu sync.Mutex; status string; result ToolResult; errMsg string;
//         cancel context.CancelFunc }
// add:  steer chan json.RawMessage   // sends must respect t.mu / be a buffered channel

// mcp/server.go — dispatch beside tasks/list|get|result|cancel (server.go:372-379).
case "tasks/steer":  tm.steer(taskID, params.payload)   // non-blocking send to t.steer

// handler-facing accessor: a context helper mirroring WithSession / withToolCall
// (mcp/tasks.go:70), NOT a method on a new type. A cooperative handler selects on it.
func SteerChan(ctx context.Context) <-chan json.RawMessage
```

Client helper in `mcpclient/tasks.go`, beside `CancelTask` (`tasks.go:74`):

```go
func (c *Client) SteerTask(ctx context.Context, id string, payload json.RawMessage) error
```

- **Cooperative:** like cancellation, only handlers that select on `SteerChan(ctx)` react;
  others ignore it. No handler is forced to change.
- **Governed:** `tasks/steer` is a real MCP method reaching the backend through the policy
  filter, so it *is* governed by a `methods:` rule just like `tasks/cancel` — a rule can deny
  it (`methods: ["tasks/steer"] allow: false`) exactly as `live-task.yaml` denies cancel.
- **Subagents:** when the target task is itself an orchestrator/router hop, steering the
  parent task propagates via the origin `_meta` (`router.go:174-176`) so the child sees who
  steered it.

---

## 5 · P4 — Launch (spawn an agent or a workflow)

**Problem.** There is no first-class "start new work on the mesh" verb; agents are launched
by hand and there is no parent→children workflow object.

**Design.**

- **Launch an agent:** `air launch --role <role> <gateway>` spawns a new agent identity by
  reusing `cmdAgent` / `roleScripts` (`agent.go:25-96`) with a fresh `--nb-config`, so it
  joins as its own WireGuard key and immediately appears in `peers` and in the gateway's
  sessions view. With P1 it also opens a steer port.
- **Launch a workflow:** a declarative `examples/air-workflow.yaml` — a list of steps
  (`launch` agents, `steer` tasks, `call` tools), sequential or parallel — run by a small
  runner that reuses the orchestrator's dial-and-call shape (`orchestrate.go:91-145`) and,
  for fan-out, the router's upstream pool (`router.go:198`). The workflow itself is a mesh
  identity; each step is an audited call.

```yaml
# examples/air-workflow.yaml  (proposed)
name: nightly-scan
steps:
  - launch: { role: reader,  gateway: 100.64.0.2:9101 }
  - launch: { role: analyst, gateway: 100.64.0.2:9101 }
  - steer:  { target: "agent:analyst.mesh", type: task, tool: read_customer, args: { id: 42 } }
  - call:   { target: 100.64.0.2:9101, tool: summarize }
```

Every launch is deny-by-default and audited (`air/launch`); the spawned identity is subject
to the same firewall as any caller.

---

## 6 · Assistant-facing MCP tools  ✅ *shipped*

`meshmcp mcp` exposes these (each registered like `toolDropFile`, `mcpapp.go`); the session
tools reach the gateway's Air control endpoint over the mesh via an
`http.Transport{DialContext: mesh.Dial}` (pass `--control <gateway-ip:port>`):

| Tool | Args | Wraps |
|---|---|---|
| `air_sessions` | — | `GET /v1/sessions` → gateway `Server.Sessions()` (P2) |
| `air_steer` | `{backend, id, method, params}` | `POST /v1/steer` → gateway `Server.Steer` (P2) |
| `air_tasks` | `{target}` | `mcpclient.ListTasks` (`mcpclient/tasks.go`) |
| `air_task_steer` | `{target, task_id, payload}` | `mcpclient.SteerTask` → `tasks/steer` (P3) |

The **gateway control endpoint** (`config.go` `ControlConfig`, `serve.go`, `aircontrol.go`)
serves `GET /v1/sessions` and `POST /v1/steer {backend,id,method,params}` on a mesh port,
gated by the caller's WireGuard identity + an `allow` ACL and audited into the shared ledger;
`session.ErrNoSession`/unknown-backend → 404, ACL deny → 403. Tests: `aircontrol_test.go`.

So an assistant can say: *"list the live sessions"* → `air_sessions`; *"steer session 9f2a on
fs to re-read customer 42"* → `air_steer`; *"what tasks are running on the analyst?"* →
`air_tasks`; *"nudge task-17 to focus on the API"* → `air_task_steer` — each a governed,
audited mesh call, never a backdoor. (Agent-target steer + `air_launch` land with P1/P4.)

---

## 7 · Governance & security (all reused)

- **Deny by default — but at three different gates, not one.** Each steer transport is
  authorized where it crosses the boundary:
  - **`tasks/steer` (P3)** is a real MCP method reaching a backend through the policy filter,
    so it *is* governed by a `methods:` rule **exactly like `tasks/cancel`** (`policy/filter.go`
    `handleMethod` → `policy.DecideMethod`, `policy/policy.go:60,149`;
    `examples/live-task.yaml:21-23`).
  - **`air/steer` to an agent inbox (P1)** is gated by the drop-receiver **sender ACL**
    (`acl.go`), not a `methods:` rule.
  - **`air/launch` and the control-plane `/v1/steer` (P2/P4)** are gated by **control-plane
    auth** on those HTTP endpoints.
  Three distinct, deny-by-default gates — do not conflate them under one "governed like
  `tasks/cancel`" claim; that phrase is exact only for `tasks/steer`.
- **Identity-attributed.** Every steer/launch resolves to the caller's WireGuard key; the
  ledger records who steered/launched what, when — provable with the public key alone.
- **ACL'd inbox.** An agent's steer port admits only allow-listed senders (`acl.go`,
  `examples/drop.yaml` `allow:`).
- **Broadcast = N audited records.** A broadcast expands to one governed, audited call per
  resolved target — never a single unattributable fan-out.
- **Origin propagation.** Cross-hop steers carry the origin `_meta` (`router.go:174-176`),
  so "who steered this subagent" survives the hop.
- **No new trust.** A steered call still traverses the gateway firewall (rate, taint,
  labels, co-sign); Steer cannot bypass policy — it is just another governed client action.

---

## 8 · Build order

1. **P3 tasks/steer** — ✅ **done.** Cancel-symmetric augmentation in `mcp/tasks.go` +
   `mcp/server.go` + `mcpclient/tasks.go`, with `TestTaskSteer` in `mcp/tasks_test.go`.
2. **P2 session List + Steer** — ✅ **session core done.** `SessionStore.List`,
   `Server.Sessions`, and the line-safe `Server.Steer` in `session/store.go` + `session/server.go`,
   with `TestStoreList`/`TestSteerLineFraming`/`TestSteerUnknownSession`. Gateway exposure
   (control endpoint + tools + CLI) still to do.
3. **P1 steerable agent** — ✅ **done.** `--steer-port` inbox on `agent.go` (`steerenvelope.go`,
   `steerinbox.go`) + `air agent-steer` sender, with `TestRunAgentLoopSteerTask`/`TestRecvEnvelopes`.
4. **P4 launch + workflow** — the runner + a new `examples/air-workflow.yaml` (proposed file).
5. **Air surface** — `air_sessions`/`air_tasks`/`air_steer`/`air_launch` in `mcpapp.go`;
   the Steer tab in `site/air.html`; the `air steer`/`air launch` CLI verbs.

Each step is independently shippable and independently governed. Until they land, the
[Steer tab in `site/air.html`](../site/air.html) is a visual mockup only.
