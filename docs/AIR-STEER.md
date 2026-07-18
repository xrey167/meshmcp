# Air · Steer — build spec

**Status: proposed.** This is a code-ready design for the *Steer* capability of
[Air](AIR.md): address and drive **live work** — an **agent** (by name), a **session**
(by id), or a **task/subagent** (by id) — and act on it (**send** · **cancel** ·
**nudge** · **broadcast** · **launch**). Nothing here ships yet; each primitive names
the exact existing seam it reuses so the diff stays small and idiomatic.

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
| Server → client push mid-call | bidirectional MCP request/notify | `mcp/server.go:161,224`, `bidir_test.go` |
| Async work + interrupt | MCP Tasks + governable `tasks/cancel` | `mcp/tasks.go`, `mcpclient/tasks.go`, `examples/live-task.yaml` |
| Resumable session + injection seam | `endpoint.Send`, `Server.sessions[id].ep` | `session/endpoint.go:80-125`, `session/server.go` |
| Receive-a-payload-by-identity pattern | drop receiver + framing | `drop.go:302-432`, `push.go:33-46` |
| Sender ACL · audit | firewall ACL + hash-chained ledger | `acl.go`, `policy/` |

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
consumes the subset it understands. It is authorized before delivery: a steer is a
governed method (`air/steer`), audited with the caller's WireGuard identity.

---

## 2 · P1 — Steerable agent (the receive path)

**Problem.** `agent.go` is a script-driven **pure client** (`runAgentLoop`,
`agent.go:100-118`) with no way to accept an external instruction.

**Design.** Give the agent an inbox by reusing the drop receiver verbatim. Alongside
dialling its backend, the agent runs a `session.NewServer` on a **steer port**, whose
backend factory parses steer envelopes and pushes them onto a channel the loop selects on.

```go
// new: a control backend for the agent's steer port — mirrors newDropFactory (drop.go).
func newSteerFactory(ch chan<- steerEnvelope, acl *ACL) session.BackendFactory { … }

// agent.go: the loop gains one more select case.
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

- **Reuses:** `dropReceive` / `newDropFactory` (`drop.go:302-432`) for the listener,
  `sendData` (`push.go:33-46`) for the sender, `acl.go` for the sender allow-list, and the
  `policy` audit for one record per delivered envelope.
- **Governance:** the steer port is ACL'd exactly like a drop receiver (`examples/drop.yaml`
  `allow:`), so only permitted identities may steer this agent.
- **`type=task`** injects a `mc.CallTool` step; **`nudge`** updates a guidance field the
  agent's next step reads; **`cancel`** breaks the loop. The agent stays a governed mesh
  client — every steered call still hits the gateway firewall.

`meshmcp agent --steer-port 9120 --role reader <gateway>` starts an agent that also
listens for steers.

---

## 3 · P2 — Session enumeration + injection

**Problem.** Sessions have durable, resumable ids, but there is **no `List()`** anywhere
(only `Server.Count()`, `session/server.go:349-353`) and **no out-of-band injection**.

**Design — three small additions:**

```go
// session/store.go — enumerate persisted sessions (FileStore scans <dir>/*.json).
type SessionStore interface {
    Save(PersistedSession) error
    Load(id string) (PersistedSession, bool, error)
    DeleteIfOwner(id, owner string) error
    List() ([]PersistedSession, error)   // NEW
}

// session/server.go — live view + the injection seam.
type SessionInfo struct { ID, Peer, Backend string; Age time.Duration }
func (s *Server) Sessions() []SessionInfo            // NEW: from s.sessions keys/meta
func (s *Server) Steer(id string, payload []byte) error {  // NEW
    sess, ok := s.sessions[parse(id)]                 // guarded by s.mu
    if !ok { return ErrNoSession }
    return sess.ep.Send(payload)                       // endpoint.go:80-125 — server→peer DATA
}
```

- **`List()`** on `FileStore` is a directory scan of the files it already writes
  (`<dir>/<id>.json`, `session/store.go:96`); `MemStore` returns its map values.
- **`Steer()`** delivers bytes into the live session's endpoint — for a resumable client
  bridge (`connect --resumable`, `bridge.go`) that surfaces on the client's stdio, i.e. it
  steers the connected MCP client/agent.
- **Expose** via `control/control.go`: `GET /v1/sessions` (list) and `POST /v1/steer`
  (`{id, payload}`), both governed and audited; and via the `air_sessions` / `air_steer`
  MCP tools (§6).
- **Safety:** injection is a privileged, deny-by-default method; the ledger records the
  steerer's identity, the session id, and a content hash of the payload.

---

## 4 · P3 — Task steer / augment

**Problem.** A task is **immutable once started** — `tasks/cancel` exists
(`mcp/server.go:326-341`, governed in `examples/live-task.yaml:20-23`), but there is no way
to feed new guidance to a running task.

**Design.** Add an input channel to the task and a governed `tasks/steer` method that
mirrors the existing cancel path.

```go
// mcp/tasks.go — task gains a steer channel next to its cancel func (tasks.go:19-28).
type task struct { id, tool, status, result, errMsg string; cancel context.CancelFunc; steer chan json.RawMessage }

// mcp/server.go — dispatch beside tasks/list|get|result|cancel (server.go:372-379).
case "tasks/steer":  tm.steer(taskID, params.payload)   // non-blocking send to t.steer

// handler-facing accessor, symmetric with ctx cancellation.
func (tc *TaskContext) Steer() <-chan json.RawMessage    // a cooperative handler selects on this
```

Client helper in `mcpclient/tasks.go`, beside `CancelTask` (`tasks.go:74`):

```go
func (c *Client) SteerTask(ctx context.Context, id string, payload json.RawMessage) error
```

- **Cooperative:** like cancellation, only handlers that select on `TaskContext.Steer()`
  react; others ignore it. No handler is forced to change.
- **Governed:** `tasks/steer` is a policy method just like `tasks/cancel` — a rule can deny
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

## 6 · Assistant-facing MCP tools

Add to `meshmcp mcp` (`mcpapp.go`), each with the same registration + handler shape as
`toolDropFile` (`mcpapp.go:196-231`):

| Tool | Args | Wraps |
|---|---|---|
| `air_sessions` | — | `Server.Sessions()` / `/v1/sessions` (P2) |
| `air_tasks` | `{target}` | `mcpclient.ListTasks` (`mcpclient/tasks.go:44`) |
| `air_steer` | `{target, type, tool?, args?, text?, broadcast?}` | agent inbox (P1) · `Server.Steer` (P2) · `tasks/steer`/`tasks/cancel` (P3) |
| `air_launch` | `{role \| workflow, gateway}` | P4 |

So an assistant can say: *"steer the analyst agent to re-read customer 42"*, *"cancel task
9f2a"*, *"nudge the running summarize task to focus on the API"*, *"broadcast a pause to all
reader agents"*, *"launch a reader agent against the fs backend"* — each a governed, audited
mesh call, never a backdoor.

---

## 7 · Governance & security (all reused)

- **Deny by default.** `air/steer`, `air/launch`, and `tasks/steer` are policy methods
  governed exactly like `tasks/cancel` (`examples/live-task.yaml:20-23`).
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

1. **P3 tasks/steer** — smallest, self-contained (`mcp/tasks.go` + `mcp/server.go` +
   `mcpclient/tasks.go`), lands cancel-symmetric augmentation with tests beside
   `mcp/tasks_test.go`.
2. **P2 session List + Steer** — one store method, one server method, one control endpoint.
3. **P1 steerable agent** — the drop-receiver pattern applied to `agent.go`.
4. **P4 launch + workflow** — the runner + `examples/air-workflow.yaml`.
5. **Air surface** — `air_sessions`/`air_tasks`/`air_steer`/`air_launch` in `mcpapp.go`;
   the Steer tab in `site/air.html`; the `air steer`/`air launch` CLI verbs.

Each step is independently shippable and independently governed. Until they land, the
[Steer tab in `site/air.html`](../site/air.html) is a visual mockup only.
