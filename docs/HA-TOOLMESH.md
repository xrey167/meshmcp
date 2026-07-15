# HA & tool-mesh — status and design

Covers the two moonshot tracks: (#3) gateway HA + session migration, and
(#4) the router as a self-healing tool mesh. This is honest about what is
**built and tested** vs **designed but not built** (the latter needs infra —
multiple gateways, a shared store — beyond a single dev machine).

## Built & tested

### Flow-controlled, bounded replay buffer (#3)
`session/endpoint.go`. The unacked send buffer is bounded by a slot semaphore
(`defaultMaxSendFrames`, default 1024, per direction). `Send` takes a slot;
an ACK returns slots. When the buffer is full `Send` blocks — **backpressure
to the producer** (a chatty backend or a fast client) — instead of growing
without bound. If a disconnected peer stays behind past `sendOverflowTimeout`
(60s) the session is closed with `errSendOverflow`. Tests: `session/flowcontrol_test.go`
(backpressure, ack-releases-slot, unblocks-on-close), all under `-race`.

This removes the "unbounded buffer during a long client absence" risk and is
the reliability floor HA is built on.

### Replica load-balancing + failover (#4)
`router.go`. An upstream may list several replica addresses. `upstreamPool`
round-robins across them and, on a **transport** error, marks the replica down
and fails over to the next (re-dialing after `replicaCooldown`, 5s). An
**application** RPC error (a tool returning an error) is returned as-is — the
replica is healthy, so no failover. Config accepts a string or a list per
upstream. Test: `router_test.go` `TestRouterFailsOverToHealthyReplica`
(dead replica + healthy replica → discovery and calls both fail over).

### Multi-gateway session migration (#3) — BUILT
A resumable session now survives a **gateway crash**, not just a client roam.
`session/store.go` defines a `SessionStore` (`MemStore` + `FileStore`); the
server checkpoints `{id, sendSeq, acked, recvSeq, sendBuf, handshake}` **on
every ack** (the consistent point — the peer has confirmed receipt, so
`sendSeq >= client.recvSeq`, and a resuming gateway never reuses a sequence
number). On an ATTACH for a session unknown in memory, the server loads it
from the store, restores the transport cursors, spawns a fresh backend,
**replays the captured client→backend handshake** (discarding the fresh
backend's already-delivered initialize reply), and resumes. Enable per
resumable backend with `session_store: <dir>`; two gateways sharing that
directory hand a session off. Test: `session/migration_test.go`
`TestSessionMigratesAcrossGateways` (gateway 1 handles a session, "crashes,"
gateway 2 rehydrates from the store and serves the next request) under `-race`.

**Migration modes** (`session_store_mode`):
- `handshake` (default) — replay the captured init/initialized handshake.
  Stateless backends.
- `full` — replay the entire client→backend log (discarding the responses it
  re-produces, counted by `countRequests`). Backends whose per-session state
  is a deterministic function of their input (internal/idempotent).
- `backend` — no replay; the backend restores its **own** per-session state
  from `MESHMCP_SESSION_ID` (its own EventStore). For truly stateful backends.
  Tested: `backendmode_test.go` `TestBackendManagedMigration` (a counter
  survives a gateway crash with no meshmcp replay).

**Lease** — each stored session carries an `Owner`; a gateway only deletes via
`DeleteIfOwner`, so a reaper on a superseded gateway never deletes a session
another gateway resumed. This makes a **live roam between two running
gateways** safe, not just the crash-failover path. Tested: `lease_test.go`.

### Full bidirectional MCP through the router (#4) — BUILT
The router now relays server-initiated **requests** (sampling/createMessage,
elicitation/create, roots/list) — not just notifications. `mcpclient` handles
inbound requests via `SetOnRequest`; `mcp.Server` can issue `Request` to its
client and correlates the response (the `Serve` loop routes id-only messages
to a pending map and dispatches concurrently so a handler can call back
mid-request). The router wires an upstream's `OnRequest` to relay down to the
end client and return the answer up. Test: `bidir_test.go`
`TestRouterRelaysServerRequest` (upstream tool issues a sampling request → routed
to the client → answered → returned) under `-race`. Subscriptions already work
via the existing method-routing (`resources/subscribe`) + notification
forwarding (`notifications/resources/updated`).

### Proactive health & dynamic discovery (#4) — BUILT
- **Proactive health checks**: `upstreamPool.runHealth` re-dials down replicas
  on a `healthInterval` ticker (started per router connection, stopped on
  cleanup), so a recovered replica is ready before the next call. Tested:
  `router_test.go` `TestPoolHealthCheckRecoversReplica`.
- **Discovery registry**: `registry/` is a file-based registry — each backend
  registers `name → mesh-addr` as its own file (`serve` registers on startup,
  deregisters on shutdown, via `registry:` in config). The router reads it per
  connection (`registry:` in the router config), merging with static upstreams,
  so new backends appear dynamically. Tested: `registry/registry_test.go`.

## Summary
**All built and tested (`-race`):** bounded/flow-controlled buffer; replica
load-balancing + failover (live-proven); multi-gateway session migration
(handshake / full / backend-EventStore modes) via a shared `SessionStore` with
ack-consistent checkpoints and an ownership **lease**; full bidirectional MCP
(server→client request relay) through the router; proactive replica health
checks; and a self-registering discovery **registry**.

The durable store (`FileStore`) is now hardened for concurrent multi-gateway
use: writes are atomic (temp + **fsync** + rename) and `Save`/`DeleteIfOwner`
serialize across processes via a **cross-process advisory lock** (`flock.go`,
exclusive lock file with stale-holder stealing), so the lease is enforced
atomically even when two gateways contend. Tested: `flock_test.go`,
`store_test.go`. The only genuinely-open work now is a *replicated* store
backend (e.g. Redis/etcd behind the `SessionStore` interface) for
multi-datacenter HA — a deployment choice, not a missing capability.
