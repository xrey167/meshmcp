# Air Continuity — “Continue on…” for agents

Air already has the recognizable parts of a device ecosystem: Nearby/Home,
Drop, Universal Clipboard (`push`), Cast/Screen, Ring, Steer, Shortcuts-like
workflows, approvals, and a shared receipt stream. **Continuity is the connective
tissue:** move the *meaning of active work* to another trusted mesh identity,
then continue it under that destination's own policy and authority.

The first shipped primitive is **Air Handoff**:

```text
source agent/device              destination device                    destination agent
       │                                  │                                    │
       │  target-key-bound Context Capsule│                                    │
       ├─────────────────────────────────►│  offered (inert, local inbox)       │
       │◄─────────────────────────────────┤  stored/replayed ACK or rejection   │
       │                                  │                                    │
       │                                  │  explicit accept                    │
       │                                  │  receiver chooses tool + exact key  │
       │                                  ├───────────────────────────────────►│
       │                                  │    claimed dispatch + task steer    │
       │                                  │◄───────────────────────────────────┤
       │                                  │  validated + audited + enqueued ACK │
       │                                  │  state = continued                  │
```

The offer command reports success only after a bounded application ACK confirms
storage (or an identity-bound replay); transport closure alone is not success.
“Continued” means the destination inbox returned a valid application ACK after
strict validation, receipt audit, and enqueue—not that the tool succeeded. The
tool's result belongs to the destination's normal execution/audit path.

## Try it

On the destination workstation, start a deny-by-default inbox:

```bash
meshmcp air handoff receive \
  --inbox ~/.meshmcp/handoffs \
  --nb-config ~/.meshmcp/handoff-destination.json \
  --port 9140 \
  --allow 'pubkey:<source-wireguard-key>'
```

The receiver prints its full target key. Keep both endpoint identities stable
with `--nb-config`; without it, each command registers a new peer. From the
source:

```bash
meshmcp air handoff offer \
  --nb-config ~/.meshmcp/handoff-source.json \
  --target-key '<destination-wireguard-key>' \
  --work task:task-17 \
  --goal 'Continue the ACME outage analysis' \
  --summary 'Three suppliers are affected; validate the ERP exposure.' \
  --cursor ./resume-cursor.json \
  --artifact exposure.json=sha256:<64-hex-content-hash> \
  --memory-ref corpus:acme \
  --secret-ref secret:erp-readonly \
  --sensitivity sensitive \
  100.64.0.22:9140
```

On the destination:

```bash
meshmcp air handoff list --inbox ~/.meshmcp/handoffs  # sensitive goals are redacted here
meshmcp air handoff show --inbox ~/.meshmcp/handoffs <handoff-id>
meshmcp air handoff accept --inbox ~/.meshmcp/handoffs <handoff-id>

# Start (or separately provision) the destination agent with a persistent key,
# an exact allow entry for the controller, and its own receipt chain.
meshmcp agent --nb-config ~/.meshmcp/handoff-agent.json \
  --role reader --steer-port 9120 \
  --steer-allow 'pubkey:<controller-wireguard-key>' \
  --steer-audit ~/.meshmcp/handoff-agent-steer.jsonl \
  100.64.0.2:9101

# Run the agent in its own terminal. During provisioning, `air whoami` with
# each persistent --nb-config prints the full controller/agent key to pin here.

# The receiver—not the capsule—chooses the tool that imports/continues work.
meshmcp air handoff continue \
  --inbox ~/.meshmcp/handoffs \
  --nb-config ~/.meshmcp/handoff-controller.json \
  --agent-key '<destination-agent-wireguard-key>' \
  --tool resume_analysis \
  <handoff-id> 100.64.0.31:9120

# If delivery times out/crashes, it remains dispatching. Check the agent's
# receipts first; only then explicitly re-arm that unknown outcome.
meshmcp air handoff rearm --inbox ~/.meshmcp/handoffs \
  --note 'checked agent receipt: no matching delivery' <handoff-id>

# Move old terminal receipts—and expired unknown dispatches—out of the bounded
# active inbox without deleting their evidence or replay/collision tombstones.
meshmcp air handoff archive --inbox ~/.meshmcp/handoffs --older-than 168h
```

The destination agent's steer inbox must independently allow the persistent
controller identity. The controller verifies the literal agent IP against
`--agent-key` before claiming the dispatch and on every reconnect, so accepted
context is not released to an address-only target. `resume_analysis` follows
that agent's normal tool path; gateway firewall policy applies when the agent
is connected through a governed meshmcp gateway. A sender cannot put a tool
name in the capsule and cause it to execute.

## Context Capsule v1

The portable wire and state types live in `air/handoff.go`:

- exact `TargetKey` (the destination's WireGuard public key);
- 128-bit random correlation and offer-replay ID;
- creation/expiry with a maximum 24-hour TTL;
- a descriptive work reference (`agent`, `session`, `task`, or `workflow`);
- goal, summary, and a bounded JSON cursor;
- content-addressed artifact references—large bytes stay in CAS;
- logical memory and intended secret-reference fields (free-form content is not DLP-scanned);
- labels and sensitivity metadata;
- a SHA-256 content hash over the canonical capsule JSON.

The whole inline capsule is capped at 256 KiB. Its wire parser is bounded, IDs
are path-safe, artifact names cannot traverse directories, and every
caller-influenced display/audit field is bounded or sanitized.

The durable inbox uses atomic write + fsync + rename, serializes cooperating
processes with an OS advisory lock, and never silently evicts history. On POSIX
it repairs the directory/record modes to `0700`/`0600`. Windows `chmod` does not
install private DACLs, so place the inbox below a user-private profile directory
whose inherited ACL excludes other users. Ancestor path components remain an
operator-controlled trust boundary. The state machine is deliberately small:

```text
offered ──► accepted ──► dispatching ──► continued
   ├────────► declined         └─ rearm --note ─► accepted
   └────────► expired
accepted ───► expired
```

Offer retries with the same ID, content hash, and verified source key are
idempotent. The same ID with different content or a different source key is
rejected. Continuation is different: `accepted → dispatching` is claimed under
the cross-process lock before network I/O. Concurrent dispatches therefore lose
the claim. A timeout/crash leaves `dispatching` as an unknown outcome; after
checking downstream receipts, the operator must use the distinct, noted
`rearm` command. Retrying ordinary `accept` cannot re-arm it. There is no
exactly-once tool-execution claim. Each claim durably records the selected
agent address, exact agent key, tool, claim time, and—when received—the
application-ACK time. Unknown attempts remain in that bounded history after a
re-arm, preserving where context may have gone. Once an unknown dispatch is
expired and past retention, `archive` can free its active-inbox slot without
changing `dispatching` or erasing its receipt/tombstone.

## Trust boundaries

Air Handoff preserves six invariants:

1. **The source is transport-derived.** `SourcePeer` and `SourceKey` come from
   the mesh connection (`session.Meta`), never from capsule JSON.
2. **Each target is exact.** The receiver compares the capsule's `TargetKey`
   with its own transport key. Before sending context—and on every reconnect—
   the source resolves the destination device IP to that exact transport key.
   Continuation applies the same check to the receiver-selected agent IP and
   `--agent-key`. Hostnames, groups, and globs are not legal context-bearing
   destinations.
3. **Received context is inert.** Receive only validates, rate-limits, stores,
   and audits. It never launches an agent or calls a tool.
4. **Consent precedes continuation.** `offered → continued` is illegal. The
   local owner must accept first.
5. **Destination authority is fresh.** The destination chooses the tool.
   Sender labels never become policy execution labels. The continuation carries
   explicit `handoff`/`untrusted-context` handling hints for the destination
   tool, but the current `policy.Filter` does not interpret argument hints as
   taint labels; gateway rules apply through the agent's normal configured path.
6. **Secrets and grants are not authority.** `SecretRefs` are intended for
   logical names only, and a destination must independently possess permission
   to resolve them. The format cannot detect a credential pasted into free-form
   goal/cursor text, so senders must treat capsule authoring as sensitive input
   handling. Source-bound capabilities/tokens must not be placed in a capsule.

The receiver writes restart-seeded, hash-chained audit records for accepted and
fully parsed offer decisions. Repetitive pre-ACL and rate-limit denials are
sampled at most once per minute per identity to bound hostile log growth. Valid
stored offers use only the correlation ID and capsule hash as provenance—not
inline goal, cursor, or secret references. Malformed framing has no trustworthy
ID/hash, and a fail-closed audit error is returned even though an atomic store
may already have completed. A `receipt_unconfirmed` NACK therefore means
“inspect the destination”; a fresh CLI invocation cannot reproduce the same
sealed bytes merely by reusing the ID. Accept/decline are local inbox state; the
destination agent writes separate `air/steer/authorize` and `air/steer/enqueue`
records to its own configured audit sink. Only an enqueue `allow` is positive
downstream delivery evidence; authorization alone is not. The shared ID makes
those records correlatable, but it does not make them one atomic chain or
deduplicate tool execution. If enqueue succeeds but its second audit append
fails, the sender receives `audit_unavailable` and work may still execute; the
Handoff deliberately remains `dispatching` until the operator checks receipts.

Use a dedicated audit file per Handoff receiver and per steerable agent. Those
commands enforce one cooperative writer and restart-seed their own chain, but a
different meshmcp service writing the same path does not participate in that
sidecar lock; sharing the file would fork its cursor.

Offer and steer application ACKs are a coordinated protocol upgrade. Upgrade
the controller and destination agent together; mixed old/new peers do not fall
back to transport-only success.

## What v1 is not

Handoff v1 is **application-level continuation in a fresh agent/session**. It
does not move a live byte-stream session between device identities.

That distinction is security-critical. `session.Server` binds reattachment to
the original `CreatorKey`; weakening it would turn knowledge of a session ID
into a takeover primitive. Current migration is gateway failover for the same
client identity, not ownership transfer to a different key. The source work is
therefore left running if Handoff fails.

Also, the content hash is an integrity/correlation address, not a sender
signature. Sender authenticity comes from the WireGuard transport identity and
the receiver's ACL.

## The ecosystem around Handoff

The next useful additions are shared layers, not more unrelated verbs:

| Layer | Experience | Technical direction |
|---|---|---|
| **Air Manifest** | “What can this device/agent do?” | A well-known, versioned availability manifest (`context.import`, `agent.launch`, `display.image`, `approval`). It is a hint; policy remains authority. |
| **Air Presence** | Trusted device and agent status | Short-lived, identity-stamped leases over governed PubSub. NetBird reachability is “Nearby,” not proof of physical proximity. |
| **Smart Targeting** | `Continue on… → RTX workstation` | Deterministic resolution over exact device IDs, trusted groups, required capabilities, load, and user preference; result still binds an exact key. |
| **Air Spaces** | Personal/team selective sync | Trust groups and scoped knowledge/memory replication with destination-side authorization. |
| **Air Shortcuts** | One automation experience | Unify Workflow + Bind + Scheduler + PubSub with idempotency, recursion, concurrency, time, and cost bounds. |
| **Air Keychain UX** | Reuse authority safely | Synchronize logical references and re-issue destination-bound grants; never synchronize raw secrets or source-bound tokens. |
| **Find Work** | Locate task/session/artifact | Search identity-stamped presence, catalogs, receipts, CAS, and task/session views from Air Home. |

True live session movement is a distinct protocol, not a UI toggle. Its first
slice now ships (next section): owner epochs and fencing, an exact-target
single-use grant, and atomic freeze/commit. Exactly-once byte delivery remains
distinct from exactly-once tool execution.

The product rule remains simple: every new experience uses **a transport-derived
identity, destination-side authority, and one correlation ID across every
receipt-producing boundary**.

## Live session move (v2 — first slice)

Where Handoff v1 moves an inert Context Capsule for continuation in a *fresh*
session, **Live Session Move** relocates the OWNERSHIP of one already-running
session from a source gateway to a destination gateway — the backend's live
state travels, and the same creator reattaches to the destination and keeps
going. This is the hardest correctness surface in the repo (two runtimes must
NEVER both process one session's traffic), so v1 is scoped honestly and every
edge is tested.

### What v1 does

A deliberate, operator/creator-initiated **prepare → ready → commit** move of one
live session, driven gateway-to-gateway by `session.Server`:

```text
source gateway (owns @G, serving)        destination gateway
       │                                        │
       │  PREPARE {session, gen G, mode}        │
       ├───────────────────────────────────────►│  spawn + (replay) backend into a
       │                                        │  warming map — NO lease, NO client
       │◄───────────────────────────────────────┤  READY   (still source@G everywhere)
       │  freeze: detach client + final ckpt @G │
       │  COMMIT {session, gen G}               │
       ├───────────────────────────────────────►│  consume single-use grant, then the
       │                                        │  ONE TakeoverLease CAS  G → G+1,
       │                                        │  promote warm backend to serving
       │◄───────────────────────────────────────┤  COMMITTED {gen G+1}
       │  yield (fenced; DeleteIfOwner no-op)   │
```

- The **source keeps owning and serving** at generation G through PREPARE and
  READY. It freezes (detaches the client, drains to a quiescent boundary, writes
  a final checkpoint at G) only after READY, and it does **not** release its
  lease — quiesce ≠ release.
- The **destination only pre-warms**: it spawns (and, for the replay mode,
  handshake-replays) the backend into a separate `warming` map, taking **no
  lease**, registering **no** live session, pumping **no** client.
- **Commit is one generation-fenced CAS** — the same `TakeoverLease` G→G+1 the
  reactive failover paths already use. The destination promotes its warm backend
  to serving **only after** that CAS wins; the source's next `SaveIfOwned`/renew
  then fails (fenced) and it yields.

### Supported backend modes

| Mode | v1 | How the move handles it |
|---|---|---|
| `MigrateBackend` (checkpoint-capable / EventStore) | **Supported** | Warm spawn restores from `MESHMCP_SESSION_ID`; no replay; the backend is authoritative and dedups any residual, so no source drain is required. The warm backend takes no input while parked, so there is never a double-writer to the shared store during the warm window. |
| `MigrateHandshake` (stateless) | **Supported** | Warm spawn replays and discards the captured handshake; the source detaches and drains to a quiescent request/response boundary before the final checkpoint, or **refuses** the move if it cannot be shown quiescent (deny-by-default). |
| `MigrateFull` (re-executes the whole input log) | **Refused** at prepare | Re-execution would duplicate external side effects. |
| stateful with no checkpoint / no EventStore | **Refused** at prepare | No safe reconstruction: replay duplicates side effects and there is no state to restore. |
| degraded generation-0 (never held a lease) | **Refused** | Unfenceable, so a move could split-brain. |

### The invariants it preserves

1. **Single-writer.** Commit is ONE `TakeoverLease` CAS; the destination serves
   only after it owns; the source freezes its client before the final checkpoint
   and is hard-fenced by the generation bump. At no instant do two runtimes
   process the session's traffic.
2. **Resumable by exactly one.** The source holds the live lease at G through
   every pre-commit step, and the CAS is a single indivisible flip: a crash
   before it leaves the source resumable at G; a crash after it leaves the
   destination resumable at G+1 — never both, never neither. The full
   crash-recovery matrix is proven deterministically (`session/move_test.go`,
   `-count=20`).
3. **Identity untouched.** `TakeoverLease` stays reserved for the
   verified-creator reattach. The operator move instead gates commit on a
   **consumed single-use grant** — "this destination may receive this one
   session, once" (`air move grant`, consumed exactly once at commit via
   `air.ConsumeMoveGrant`) — never an arbitrary peer. The client that later
   attaches to the moved session is still the creator (`CreatorKey` unchanged).
4. **Additive.** New `session/move.go` + a `warming` map + an inert
   `endpoint.detach()` + a control verb. No new `MigrationMode`; v1 Handoff, the
   reactive rehydrate, the standby sweep, and clean shutdown are all unchanged.

### What v1 is NOT (scope boundary)

- It does **not** redirect the client. The move relocates ownership and
  pre-warms the destination; the creator lands on the destination by the same
  client-driven reattach + mesh discovery that crash-failover already uses (an
  operator draining a gateway redirects discovery to the destination). Do not
  point the client at the destination before commit succeeds. A creator that
  instead reattaches to the source after commit is a normal, allowed creator
  reattach (the source re-takes via `TakeoverLease` at the new generation).
- It is **not** exactly-once tool execution — exactly-once *byte* delivery
  across the move stays distinct from exactly-once *tool* execution.
- The prepare/ready/commit transfer is a **gateway-to-gateway** operation
  (`session.Server.MoveSessionTo` / `ServeMoveControl`), pinned to the exact
  destination key like Handoff. The CLI ships the one discrete operator action —
  `air move grant` (the single-use destination authorization). The transfer
  trigger and destination listener are now **wired into the gateway control
  plane** (see "Triggering a move" below).

### Triggering a move (control-plane wiring, F30)

The move engine is unchanged — F30 only *dials and calls* the two tested
methods, so all four invariants stay entirely inside `session/move.go`.

- **Source trigger — `POST /v1/move`** on the Air control endpoint
  (`cmd/meshmcp/aircontrol.go`). Body `{backend, id, dest_key, dest_addr}`. It is
  gated on the **same operator/control ACL as `/v1/steer`** (default-deny,
  fail-closed on an empty allow even after a SIGHUP), audits both allow and deny
  as `air/move`, and honours on-behalf attestation identically. After the ACL it
  re-checks the *target backend's own* ACL, then dials `dest_addr` over the mesh
  and runs `MoveSessionTo`. Status is truthful about ownership: `200 moved`
  (destination owns), `409` refused/CAS-lost (source thawed, still serving),
  `502` outcome-unknown (source retains until fenced), `403/404` for the ACL /
  unknown-backend cases. **The source presents no credential** — authorization is
  entirely destination-side, so a rogue trigger still cannot force a move.
- **Destination listener — per-backend `move_port` + `move_grant_store`**
  (`cmd/meshmcp/config.go`, `serve.go`). A backend opts in; each listener binds to
  *its* `session.Server` (the move protocol carries a session id but not a backend
  name, so routing is per-backend). The commit `authorize` closure consumes a
  single-use grant keyed to **this gateway's** WireGuard key + the exact session
  id (`air.ConsumeMoveGrant`); a nil store or empty identity refuses every commit
  (deny-by-default). Requires `resumable` + `session_store` + a
  handshake/backend mode.
- **Room drag-to-handoff** (`cmd/meshmcp/room.go`, `--control <gateway-addr>`).
  Token-gated `/api/sessions` and `/api/move` proxy the gateway's `/v1/sessions`
  and `/v1/move` over the mesh under the room's **own** WireGuard identity (which
  must be on the gateway's `control.allow`). The SPA renders live sessions as
  draggable rows and destination gateways as drop targets; a drop confirms, then
  POSTs the move and surfaces the gateway's verdict **unchanged** — delivered only
  on a real `200 moved`, refused on `409`, failed otherwise.

### Tested

- `session/move_test.go`: the full crash-recovery matrix (crash at prepare,
  after ready, pre-commit, mid-commit, after-CAS-before-promote, post-commit,
  dest-mid-prepare), abort at every pre-commit step, idempotent commit,
  single-use/unauthorized/unsupported-mode refusals, and the end-to-end happy
  path for both supported modes (client reattaches to the destination on the
  pre-warmed backend, source fenced) — deterministic under `-count=20`.
- `session/storetest.RunSessionLiveMove`: the public-API move proven against
  `MemStore` on every run and live PostgreSQL (`pgstore`) when
  `MESHMCP_TEST_PG_DSN` is set — the store-observable ownership swap and source
  fence across what would be separate hosts.
- `air/move_grant_test.go`: the single-use grant is consumed exactly once,
  scoped to the exact (destination, session), deny-by-default, revocable, and
  durable.
- `cmd/meshmcp/aircontrol_test.go`: the `POST /v1/move` trigger — allowed
  operator routes with exact args, ACL deny (and empty-ACL fail-closed), backend
  ACL deny, the full status mapping (moved/refused/cas-lost/outcome-unknown),
  bad-request/405, on-behalf attribution, and the `gatewayAirControl.move` wiring
  (server resolution + backend ACL before the dial; the dial reaches
  `MoveSessionTo`; unwired dial fails closed).
- `cmd/meshmcp/room_test.go`: drag-to-handoff `/api/move` and `/api/sessions` are
  token-gated, 409 when the room is not wired to a `--control` gateway, and pass
  the gateway's verdict (a 409 refusal + reason) through unchanged.
- `cmd/meshmcp/config_test.go`: `move_port` requires resumable + `session_store`
  + `move_grant_store` + a handshake/backend mode, and dedups against other ports.
