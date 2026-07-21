<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# session

## Purpose
A resumable, exactly-once, in-order session layer over an unreliable mesh connection. It lets a stdio MCP session survive the transport dropping (client roaming, sleep/wake) **and** a gateway process crash, via a bounded flow-controlled buffer, a durable frame store, and an ownership lease so a second gateway sharing the store can take over after failover. Enabled per backend with `resumable: true` (clients use `connect --resumable`).

## Key Files
| File | Description |
|------|-------------|
| `frame.go` | Package doc + the wire framing (DATA/ACK frames, sequence numbers) for the resumable protocol. |
| `endpoint.go` | The shared endpoint `pump`: send/receive, acking, backpressure, and `errRebound` when a connection is replaced by a reattach. |
| `server.go` | `Server`: manages resumable sessions for one backend definition; detach TTL, reattach, reconstruction. Enforces identity binding — a reattach/rehydrate must come from the creator's `PeerKey` (`creatorKey`, else `errSessionIdentity`) (F23). `Server.Steer` injects a server→client notification into a live session (`ErrNoSession` if absent); `Server.Handoff` re-binds a live session to a new `creatorKey` (F30, guarded by `keyMu` + persisted) so it can be transferred by identity; `Server.Sessions()`/`SessionInfo` enumerate live sessions (caller + age). |
| `client.go` | `Dialer` and the client half that reconnects and replays missed frames. |
| `backend.go` | Shared timing knobs, the `Meta` caller-identity struct, and the backend-side session wiring; `MigrationMode` (`MigrateHandshake`/`MigrateFull`/`MigrateBackend`). |
| `store.go` | `PersistedFrame` + the durable file store and ownership **lease** used for cross-process failover; `PersistedSession.CreatorKey` (the identity-binding field checked on failover) and the `SessionStore.List()` enumeration behind the cross-gateway sessions view. |
| `flock.go` | Advisory file locking (`errLockTimeout`) guarding the shared store. |

## For AI Agents

### Working In This Directory
- Timing constants are deliberately generous so a slow CI host doesn't flake; keep that when editing.
- Reconstruction modes matter: `handshake` (stateless backends, default), `full` (replay the whole client→backend log; backend must be idempotent), `backend` (backend restores its own state from `MESHMCP_SESSION_ID`).
- The lease invariant: a store entry is deleted/claimed only by its current owner (see `lease_test.go`).

### Testing Requirements
- `CGO_ENABLED=1 go test ./session/ -race`. Concurrency-heavy: flow control, migration/failover, lease ownership, and store round-trips each have tests. Run the full package under `-race` after any change.

## Dependencies

### Internal
- Wraps backends produced by root `serve.go`; the `Filter` (`policy/`) sits between the session layer and the backend process.

### External
- Standard library only (`os`, `sync`, `time`, `encoding/json`).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
