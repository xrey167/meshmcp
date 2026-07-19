# Air — the AirDrop-native face of meshmcp

**Air** is one name and one product surface for meshmcp's payload + human-in-the-loop
layer: **discover** who's on your mesh, **drop** a file, **push** a snippet or a task,
**fetch** a blob by content hash, **steer** live work (an agent, a session, a task) or
**launch** a fresh one, and **approve** a held call — from a phone, an assistant, or a
laptop.

It looks like Apple AirDrop. It is not. Every Air transfer is between **cryptographic
identities on a dark mesh** — no cloud, no accounts, no open ports — is **resumable**
across a network roam, is **policy-gated** by the receiver's firewall, and is
**provable** in a tamper-evident ledger. AirDrop asks "is this person near me?"; Air
asks "does this WireGuard key prove who they are, and may they do this?" — and writes
down the answer.

> Air is a coherent face over primitives meshmcp already ships (`peers`, `drop`, `push`,
> `fetch`, `approvals`) plus the **steer** and **launch** primitives built on top — the agent
> steer inbox, session enumeration + a line-safe session steer, `tasks/steer`, the gateway
> control endpoint, and the `meshmcp air` CLI. All seven verbs ship today; see
> [docs/AIR-STEER.md](AIR-STEER.md) for how steer/launch are built and
> [§6](#6--whats-real-today-vs-proposed) for the full real-vs-proposed table.

---

## 1 · What Air is

meshmcp's moat is that the **same WireGuard key that authorizes a tool call also
stamps a dropped file, a pushed task, and a co-sign**. So "who sent what to whom, and
who approved it" is cryptographic by construction — not a header, not a claim. Air is
the consumer-facing product of that one fact.

| Air action | Backed by (exists today) | One line |
|---|---|---|
| **Discover** — who's on my mesh | `peers.go` · `client.Status()` | Each row is a WireGuard identity + mesh FQDN, not a claim. |
| **Drop** — send files | `drop.go` (`sendFiles`, `session` client) | Resumable, E2E-encrypted, sender-ACL gated, content-hash audited. |
| **Push** — send clipboard / a task | `push.go` (`sendData`) | A small stdin payload to a peer's resumable inbox, by identity. |
| **Fetch** — pull by content hash | `cas.go` · `fetch` | Zero-exposure content-addressed retrieval from a peer's store. |
| **Steer** — drive live work | `agent.go` · `session/server.go` · `mcp/tasks.go` · `aircontrol.go` | Send/cancel/nudge to an agent (steer inbox), a session (line-safe server→client notify), or a task (`tasks/steer`). |
| **Launch** — spawn agent / workflow | `air.go` · `airworkflow.go` | Start a new agent (`roleScripts`) or run a declarative workflow as its own mesh identity. |
| **Approve** — co-sign a held call | `approvals.go` · `policy.FilePending` | The phone is the human identity the firewall was waiting for. |
| **Prove** — receipts | `audit.go` · `policy/` | Every Air action lands in the hash-chained (optionally signed) ledger. |

---

## 2 · The verbs, grounded

Each Air verb maps to a command that runs **today**. Air is the surface that makes them
feel like one thing.

### Discover
```bash
meshmcp peers            # connected identities — the "who can I drop to" view
meshmcp peers --all      # include offline peers
```
Rows come straight from the mesh (`client.Status()` in `peers.go`): status, mesh IP,
FQDN, short public key. The identity is the transport's, so it can't be spoofed.

### Drop
```bash
meshmcp drop 100.x.y.z:9110 ./report.pdf ./photo.png     # send files to a peer
meshmcp drop --config examples/drop.yaml                 # run a receiver (mesh port 9110)
```
The receiver joins the mesh, listens **only** on the mesh interface, admits only
senders matching its `allow` ACL (FQDN glob or exact pubkey), verifies each file's
content hash on landing, and writes one audit record per file (`drop.go`,
`examples/drop.yaml`). A roam mid-transfer resumes — that's the `session/` layer.

### Push
```bash
echo "meet at 15:00"  | meshmcp push 100.x.y.z:9110         # universal clipboard
pbpaste               | meshmcp push --name clip.txt 100.x.y.z:9110
task.json             | meshmcp push 100.x.y.z:9110         # hand a task to an agent
```
`push` streams a small payload from stdin to the **same** drop inbox over the same
resumable, audited channel (`push.go`). Anything on one device's clipboard — or a task
for an agent — lands on another by identity.

### Fetch
```bash
meshmcp fetch 100.x.y.z:9101 <sha256>      # pull a blob by content hash from a peer's CAS
```
Content-addressed and zero-exposure: you ask for a hash, the peer's store answers over
the mesh (`cas.go`). Nothing is published; the corpus never leaves its owner's boundary.

### Steer — address and drive live work *(shipped — [AIR-STEER.md](AIR-STEER.md))*

`push` hands a payload to a passive **inbox**; **Steer** addresses **live work** and acts
on it. Three target types, one vocabulary:

| Target | Addressed by | Backed by the seam |
|---|---|---|
| **Agent** | mesh FQDN / registry name (`peers.go`, `registry/`) | the agent **inbox** — `--steer-port` + `air agent-steer` (**shipped**, the `drop` receiver pattern on `agent.go`) |
| **Session** | 16-byte session id (`session/`) | `SessionStore.List` + `Server.Sessions` + a line-safe `Server.Steer` server→client notification (**shipped**) — *not* raw `endpoint.Send` |
| **Task / subagent** | task id (`mcp/tasks.go`) | a governed `tasks/steer` (**shipped**), symmetric with the existing `tasks/cancel` |

Five actions across those targets:

```bash
meshmcp air steer agent:analyst.mesh   --task read_customer --arg id=42   # send an instruction
meshmcp air steer task:9f2a            --cancel                           # interrupt (tasks/cancel, today)
meshmcp air steer task:7b1c            --nudge "focus on the API"         # augment in-flight
meshmcp air steer group:reader         --pause                           # broadcast → N audited records
```

The addressing (`peers`, registry, `<name>.<tool>` namespacing, origin `_meta`) and the
transports (bidirectional MCP `Server.Request`, MCP Tasks) **already exist**. **Shipped:** the
`tasks/steer` method + `Client.SteerTask` (task augment, the counterpart to `tasks/cancel`),
the **session core** (`SessionStore.List`, `Server.Sessions`, line-safe `Server.Steer`), the
**gateway control endpoint** (`/v1/sessions`+`/v1/steer`, identity-gated + audited), the
`air_*` assistant tools, and the **`meshmcp air` CLI** (`sessions` · `steer` · `launch`).
All of this ships today. Every steer is deny-by-default, identity-attributed, and audited —
it cannot bypass the firewall. See [AIR-STEER.md](AIR-STEER.md) for the spec.

### Launch — spawn an agent or a workflow

```bash
meshmcp air launch --role reader 100.x.y.z:9101          # spawn a new agent identity
meshmcp air workflow examples/air-workflow.yaml          # run a declarative multi-step workflow
```

An agent launch child-execs `meshmcp agent` (reusing `roleScripts`) with a fresh
`--nb-config`, so the new worker joins as its own WireGuard key and immediately shows up in
`discover` and the sessions view. A **workflow** is a small declarative file (launch these
agents, steer these sessions, call these tools — run in order), run by `airworkflow.go` which
reuses the orchestrator's dial→`CallTool` shape. Each launch is audited; the spawned identity
is subject to the same firewall as any caller.

### Approve
```bash
meshmcp approvals --store ./demo/cosign     # phone-first co-sign inbox, served on a mesh port
```
When the firewall holds a `require_cosign` call, it records a pending request
(`policy.FilePending`). `approvals` serves a responsive page plus `GET /v1/pending`,
`POST /v1/approve`, `POST /v1/deny` — **on the mesh**, so the approver is the caller's
own WireGuard identity. Approving writes an attributed grant (`approver: <your-fqdn>`)
and the held call proceeds. This is the killer phone use case, and it works today (see
[docs/MOBILE.md §2](MOBILE.md)).

---

## 3 · Three surfaces, one experience

Air is the same verbs wherever you are. The three surfaces differ only in how you
reach them.

### A · Phone-first web over the mesh — *ships fastest*

One responsive page on a **mesh port, no public port**, opened from any device already
on the mesh — exactly the pattern `meshmcp approvals` and `meshmcp room` already use.
Zero install: a phone joined via the NetBird app opens `http://<gateway-mesh-ip>:<port>`
and gets Nearby / Drop / Push / Steer / Approvals / Receipts.

This is what [`site/air.html`](../site/air.html) mocks up — the "how it could look"
deliverable. It reuses:
- the peer list shape from `peers.go`,
- the drag-to-drop → `meshmcp drop …` interaction already in
  [`site/knowledge-canvas.html`](../site/knowledge-canvas.html),
- the pending → approve/deny flow from `approvals.go`,
- the audit-record fields from [`docs/spec/AUDIT-RECORD.md`](spec/AUDIT-RECORD.md).

```
 phone / laptop (mesh peer · own WireGuard identity)
   │  opens http://<gateway-mesh-ip>:<air-port>   (no public port)
   ▼
 meshmcp air   ── serves Nearby · Drop · Push · Steer · Approvals · Receipts
   │  calls peers / drop / push / fetch / steer / launch / approvals internally
   ▼
 gateway: policy · audit · secrets  ──▶  peers / drop inboxes / CAS / agents · sessions · tasks
```

### B · The assistant MCP app — *Air from Claude Code / Codex*

`meshmcp mcp` already runs meshmcp as an MCP server so an assistant can operate the
mesh as governed tool calls (`mcpapp.go`, [docs/MCP-APP.md](MCP-APP.md)). It already
exposes the Air-shaped tools **`drop_file`**, **`network`**, **`pending_approvals`**,
and **`approve`/`deny`**. The **shipped** Air tools (pass `--control <gateway-ip:port>` for
the session ones) wrap the same commands the way `drop_file` wraps `drop`:

| Tool | Status | Wraps | Assistant can say |
|---|---|---|---|
| `air_sessions` | ships | `GET /v1/sessions` → `Server.Sessions()` | "List the live sessions." |
| `air_steer` | ships | `POST /v1/steer` → `Server.Steer` | "Steer session 9f2a on fs to re-read customer 42." |
| `air_tasks` | ships | `mcpclient.ListTasks` | "What tasks are running on the analyst?" |
| `air_task_steer` | ships | `mcpclient.SteerTask` → `tasks/steer` | "Nudge task-17 to focus on the API." |
| `air_peers` · `air_push` · `air_fetch` | ships | `client.Status()` · `sendData` · `fetchBlob` | "Who's on the mesh?" / "Push this task." / "Fetch blob `<sha>`." |
| `air_launch` | ships (opt-in) | `spawnAgent`, gated by `--allow-launch` | "Launch a reader agent." |

Agent-target steer is the `meshmcp air agent-steer` CLI; `air_launch` is **off by default** —
start the app with `--allow-launch` to let the assistant spawn agent processes.

Config is unchanged from the existing app:
```jsonc
{ "mcpServers": {
    "meshmcp": {
      "command": "meshmcp",
      "args": ["mcp", "--audit", "./demo/audit.jsonl", "--cosign-store", "./demo/cosign"],
      "env": { "NB_SETUP_KEY": "<your-reusable-setup-key>" }
} } }
```
Then, in the assistant: *"AirDrop report.pdf to Rey's phone"* → `drop_file`;
*"list the live sessions"* → `air_sessions`; *"steer session 9f2a on fs to re-read customer
42"* → `air_steer`; *"nudge task-17 to focus on the API"* → `air_task_steer`;
*"approve the transfer for billing.mesh"* → `approve`. Every one is a governed mesh
client — audited, firewalled, never a backdoor.

### C · Native mobile (gomobile) — *the milestone*

The richest Air surface is a native app that binds meshmcp's Go client into iOS/Android
via `gomobile`, per the surface sketched in [docs/MOBILE.md §3](MOBILE.md). Air is the
app that binding powers: a Face-ID-gated **Approve**, a **Receive** sheet for incoming
drops, a share-sheet **Drop/Push**, all with roaming-proof `session/` connections and
the WireGuard key in the secure element. This is a design target here, not this task's
build — but the binding surface (`Join`, `Dial`, `Call`, `Approvals`) is already
specified.

---

## 4 · Architecture

```mermaid
flowchart TB
  subgraph surfaces ["Air surfaces — same verbs everywhere"]
    W["A · phone-first web<br/>(mesh port, no public port)"]
    M["B · assistant MCP app<br/>(meshmcp mcp tools)"]
    N["C · native mobile<br/>(gomobile) — proposed"]
  end
  subgraph plane ["meshmcp — identity · policy · audit"]
    P1["WireGuard identity"] ~~~ P2["firewall: allow · rate · taint · co-sign"] ~~~ P3["hash-chained audit"]
  end
  subgraph peers ["mesh peers (no open ports)"]
    D1["drop inbox · 9110"]
    D2["CAS / fetch"]
    D3["cosign store"]
  end
  W & M & N --> plane
  plane --> D1 & D2 & D3
```

Nothing in the gateway, policy, or audit changes for Air. A phone or laptop joining the
mesh gets its own WireGuard key → its own cryptographic identity → policy and audit
already distinguish it. Air is just a nicer door onto the same rooms.

---

## 5 · Security model

Air inherits meshmcp's invariants and the phone-approver model from
[docs/MOBILE.md §5](MOBILE.md):

- **Zero open ports.** Every Air surface listens only on the mesh interface. `nmap` on
  the public internet finds nothing.
- **Identity is cryptographic, never claimed.** A drop/push/approve resolves to the
  sender's WireGuard key + FQDN — the root of the receiver's `allow` ACL and of every
  audit record.
- **Key in the secure element (phone).** The device's WireGuard private key sits in the
  Secure Enclave / StrongBox; the mesh identity is as strong as the hardware.
- **Biometric before the action, not the tunnel.** Gate `Approve` (and, if you like,
  `Drop`) behind Face ID / fingerprint, so a stolen unlocked phone still can't act.
- **Sender ACL + taint on drops.** The receiver admits only `allow`-listed identities
  (FQDN glob or pubkey), verifies each file's content hash, and can refuse a drop into a
  tainted session — the same firewall vocabulary as tool calls (`drop.go`, `policy/`).
- **The device never holds a secret.** Air moves files, payloads, and *references* to
  actions; credential injection stays server-side (see [docs/SECRETS.md](SECRETS.md)).
  Losing the device loses an approver/endpoint, not a credential.
- **Non-repudiable receipts.** Every Air action is a hash-chained record — a drop's
  content hash, a push, an attributed co-sign — provable complete-and-unedited with the
  public key alone.
- **Instant revocation.** Remove the device's key from NetBird and it's off the mesh: it
  can no longer discover, drop, push, fetch, or approve.

---

## 6 · What's real today vs. proposed

Honesty about the seam, so nobody mistakes the mockup for shipped product:

| Piece | Status | Where |
|---|---|---|
| `discover` / `drop` / `push` / `fetch` / `approvals` CLI | **Ships now** | `peers.go` · `drop.go` · `push.go` · `cas.go` · `approvals.go` |
| Resumable, E2E, sender-ACL, per-file audit on transfers | **Ships now** | `session/` · `drop.go` · `policy/` |
| Assistant Air tools `drop_file` · `network` · `pending_approvals` · `approve`/`deny` | **Ships now** | `mcpapp.go` · [MCP-APP.md](MCP-APP.md) |
| Phone-first web over the mesh (approver + room) | **Ships now** | `approvals.go` · `room.go` |
| `site/air.html` unified Air mockup | **This change** (mockup only) | `site/air.html` |
| **Steer** — P3 task augment · P2 session core · P1 agent inbox | **Ships now** | `mcp/tasks.go` · `session/server.go` · `agent.go` · `steerinbox.go` (+ tests) |
| **Steer** — gateway `/v1/sessions`+`/v1/steer` endpoint · `air_sessions`/`air_steer`/`air_tasks`/`air_task_steer` tools | **Ships now** | `config.go` · `serve.go` · `aircontrol.go` · `mcpapp.go` · `aircontrol_test.go` |
| **Steer/Launch** — the `meshmcp air` CLI (`sessions` · `steer` · `launch` · `agent-steer` · `workflow`) + P4 runner | **Ships now** | `air.go` · `airworkflow.go` · `examples/air-workflow.yaml` |
| Assistant tools `air_peers` · `air_push` · `air_fetch` · `air_launch` (opt-in) | **Ships now** | `mcpapp.go` · `mcpapp_air_test.go` |
| A served **live** Air web page over the mesh (`meshmcp air serve`) | **Ships now** | `airserve.go` · `site/air-live.html` · `airserve_test.go` |
| Push-wake seam (device registry + notify hook; vendor APNs/FCM pluggable) | **Ships now** | `pushwake.go` · `approvals.go` · `pushwake_test.go` — [MOBILE.md §4](MOBILE.md) |
| Native mobile **binding package** (`mobile/`, compiles; `gomobile bind` external) | **Ships now** | `mobile/mobile.go` · `mobile/mobile_test.go` — [MOBILE.md §3](MOBILE.md) |
| A shipped native mobile **app** (bound + built + on a device) | **External** | needs the iOS/Android toolchain + a device |

Invariants that never move: **no open ports**, **identity is cryptographic**, **deny is
the default**.

---

## 7 · Roadmap

Mirrors the staged path in [docs/MOBILE.md §7](MOBILE.md), Air-branded:

1. **Done — the full Air surface.** `discover` / `drop` / `push` / `fetch` / `approve`, and
   **Steer/Launch**: the P1–P4 primitives ([AIR-STEER.md](AIR-STEER.md)), the gateway control
   endpoint, the `air_*` assistant tools, and the `meshmcp air` CLI (`sessions` · `steer` ·
   `launch` · `agent-steer` · `workflow`). Usable end-to-end today.
2. **Next — a served Air page + the remaining wrapper tools.** A `meshmcp air` command that
   serves the mockup on a mesh port (reusing the `approvals`/`room` pattern), plus the
   `air_peers`/`air_push`/`air_fetch` assistant tools.
3. **Then — push-wake.** The device-registration + APNs/FCM notify seam so a phone *buzzes*
   on a pending drop, approval, or steer instead of polling ([MOBILE.md §4](MOBILE.md)).
4. **Later — the native Air app.** `gomobile`-bound identity + resumable sessions, Face-ID
   approvals, receive/share sheets ([MOBILE.md §3](MOBILE.md)).

## Reference points

- `peers.go` · `drop.go` · `push.go` · `cas.go` — discover / drop / push / fetch.
- [AIR-STEER.md](AIR-STEER.md) — the code-ready spec for **steer** + **launch** (P1–P4),
  grounded in `agent.go`, `session/endpoint.go`, `mcp/tasks.go`, `orchestrate.go`, `router.go`.
- `approvals.go` · `policy/pending.go` — the phone-first co-sign inbox.
- `mcpapp.go` · [MCP-APP.md](MCP-APP.md) — Air from an assistant, governed + audited.
- [MOBILE.md](MOBILE.md) — phone = a hardware-backed human identity; the push seam; the
  gomobile binding surface.
- [IDEAS.md](IDEAS.md) — the payload-layer thesis (F1 AirDrop, S2 "My Devices" vault).
- `examples/drop.yaml` — a ready-to-run drop receiver.
- [`site/air.html`](../site/air.html) — the visual mockup of surface A.
