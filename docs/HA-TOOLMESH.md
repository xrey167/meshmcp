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
use: writes are atomic (unique temp + **fsync** + rename) and `Save`/
`DeleteIfOwner` serialize across processes via a **cross-process advisory
lock** (`flock.go`, exclusive lock file with stale-holder stealing), so the
lease is enforced atomically even when two gateways contend. Every mutation
re-verifies its lock token immediately before the commit rename/remove, so a
holder paused past the staleness window whose lock was stolen aborts instead
of renaming a stale image (old owner, old generation) over the new holder's
commit. Tested: `flock_test.go`, `store_test.go`, `flock_steal_test.go`. That
said, the residual instant between the token check and the rename means a
stolen lock is narrowed, not impossible — `FileStore`'s CAS holds only for
crash-or-alive holders on a single host (or a lock-correct shared filesystem).
It remains the single-node default, and the autonomous standby sweep refuses
to run over it (see below).

**Replicated store backend — BUILT (store layer).** `pgstore/` implements
`SessionStore` + `LeaseStore` (and the replay-protection stores) on PostgreSQL:
every lease op is a row-locked transaction, so the CAS/fencing guarantees hold
across hosts, not just across processes on one machine. Enable it by setting
`session_store` to a DSN instead of a directory
(`session_store: postgres://user:pass@host/db`); `serve` detects the DSN form
and `meshmcp doctor` pings it and applies the schema. Conformance-proven by the
shared harness in `session/storetest` (same single-winner / fencing subtests as
`MemStore`/`FileStore`) against a live PostgreSQL.

**Server failover path — WIRED and proven.** The session server acquires the
lease on create, fences every checkpoint through `SaveIfOwned`, and performs an
identity-verified `TakeoverLease` when the session's creator reattaches to a
different gateway; `session/storetest.RunSessionMigration` proves the full
crash → reattach → rehydrate → takeover flow, including against live
PostgreSQL (`MESHMCP_TEST_PG_DSN`). Two gateways sharing one PostgreSQL
session store is a supported deployment.

**Lease renewal + expiry-driven standby failover — BUILT** (`session/failover.go`).
Three pieces, all ordinary lease ops serialized by the store's generation CAS
(safety never rests on timing; the intervals and margin tune availability only):

- **Renewal heartbeat** — always on when the store supports leases: every
  session's lease is renewed at ~TTL/3 (±20% jitter), so `LeaseExpiry` finally
  means "the owner is alive". A *fenced* renewal (another gateway took the
  session over) yields the session, exactly like a fenced checkpoint; a store
  *error* retains it and retries next tick (an outage must not mass-kill
  sessions — the sweep margin absorbs several missed ticks symmetrically).
  Degraded sessions (lease acquire failed at create, generation 0) hold no
  fencing token, so on a lease-capable store they never checkpoint at all —
  they serve without migration rather than writing unfenced state that could
  regress a record a peer has since taken over.
- **Release on clean shutdown** — `Server.Shutdown()` first joins the
  maintenance goroutine (so an in-flight sweep adoption lands before the drain
  and is handed off, never leaked), then checkpoints each session and
  `ReleaseLease`s it (owner cleared, generation + state preserved), so a peer
  gateway claims instantly instead of waiting out an expiry. Termination paths
  (client close, TTL reap, fence yield) keep `DeleteIfOwner`.
- **Standby sweep** — opt-in per backend (`session_failover: standby`,
  `session_sweep_seconds`, default 30); requires a **PostgreSQL**
  `session_store` (config-enforced, and the server disables the sweep over a
  `FileStore` even if reached directly): a file lock stolen from a
  paused-not-dead holder could regress the generation an adoption committed,
  the one split-brain the sweep must never create. Reattach-driven failover
  keeps working on `FileStore`. The gateway lists the store and adopts
  sessions whose lease is released or expired **past a margin of 2×TTL** —
  i.e. only after ≥3×TTL of total owner silence (expiry already trails the
  last renewal by a full TTL). The claim is `AcquireLease`'s generation CAS
  (never `TakeoverLease`, which stays reserved for identity-verified creator
  reattach), so exactly one standby wins and the paused-not-dead owner is
  fenced out of `SaveIfOwned`/`RenewLease` the instant the claim commits. The
  adopter respawns the backend immediately — checkpoints now persist the
  creator's `PeerFQDN`/`PeerAddr` (additive, schema still v1), so the respawn
  runs under the creator's original policy identity; pre-upgrade records
  without those fields — and records stamped with a newer schema version than
  this build (pgstore now stamps and filters `SchemaVersion` exactly like
  `FileStore`, so a mixed-version fleet's older standby never adopts state it
  may misread) — are never adopted (they keep the client-reattach path).
  The client's reattach then lands on a warm session through the unchanged
  identity-bound attach path (attach absorbs a takeover CAS lost to a
  concurrent adopt by re-Loading and retrying, bounded, since the client
  treats an attach rejection as terminal); if it never returns, the adopted
  session is reaped at TTL (which also GCs dead-owner records). **Honest margins:** a
  standby takes over roughly `expiry + 2×TTL` after the owner's last renewal
  (≈6 min at the default 2-min TTL) plus up to one sweep interval — adopting
  earlier would only trade false yields of live-but-slow owners, never
  correctness, because the generation fence is the protection either way.
  Tested: `session/server_lease_test.go` (renewal semantics, shutdown
  release), `session/sweep_test.go` (eligibility matrix, end-to-end
  paused-gateway adoption + reattach, re-load freshness, reap, failure
  release), `session/sweep_race_test.go` (renew-vs-sweep, adopt-vs-rehydrate,
  standby-vs-standby single winner, high `-count`).

What remains open (capability-matrix Phase 6): ambiguous-outcome mutating
calls are still not auto-retried (no enforced idempotency keys), and a
failover from a mid-request checkpoint keeps handshake-mode's existing
in-flight-response window (`MigrateFull`/`MigrateBackend` are the remedies).
