<!-- Generated: 2026-07-17 | Updated: 2026-07-20 -->

# meshmcp

## Purpose
meshmcp is an **identity-native control plane for agent-to-tool (MCP) traffic**. It exposes local MCP servers as peers on an embedded NetBird userspace WireGuard mesh (no open ports, no admin rights) and enforces policy on every JSON-RPC call by the caller's cryptographic identity. Every request resolves to the peer's WireGuard public key (via `IdentityForIP`) — the root of a three-valued policy engine (allow / deny / co-sign), a tamper-evident hash-chained audit, a credential broker, and signed capabilities. The repository root is Go `package main`: the `meshmcp` CLI and all its subcommands. The reusable enforcement/transport logic lives in the sub-packages.

## Key Files
| File | Description |
|------|-------------|
| `main.go` | CLI entry point and subcommand dispatch (`serve`, `router`, `call`, `capability`, `audit`, …). |
| `serve.go` | `meshmcp serve`: joins the mesh and, per inbound connection, spawns/proxies a backend wrapped in the policy filter. Builds engines, audit, tracer, secret broker, and capability verifier per backend. |
| `config.go` | YAML config: `Config`/`Backend`/`MeshConfig` + `loadConfig` validation (stdio vs http, policy, capabilities, secrets, resumable). |
| `cli.go` | Terminal MCP client commands (`ls`, `call`, `read`, `prompt`, `functions`, `function-call`); `dialMCP`, `--capability @file`. |
| `mesh.go` | `meshOptions` and joining the embedded NetBird mesh. |
| `acl.go` | `Allow` matching: which peers (FQDN glob / `pubkey:`) may use a backend. |
| `bridge.go` | `connect` — stdio ⇄ remote stdio backend bridge (`--resumable`). |
| `router.go` | `router` — aggregating endpoint: load-balance, failover, discovery, bidirectional MCP. |
| `orchestrate.go` | `orchestrate` — a server that calls other servers' tools over the mesh. |
| `federate.go` | `federate` — cross-org boundary exposing only granted tools (delegates to `federation/`). |
| `control.go` | `control` — managed control plane: enrollment, registry, policy distribution (delegates to `control/`). |
| `dash.go` · `room.go` | `dash` (live dashboard) and `room` (interactive Control Room: network view + console REPL + governed/raw shell). Both serve loopback-guarded HTML. |
| `approve.go` · `approvals.go` | Human co-sign: `approve` (CLI) and `approvals` (phone-friendly approver served over the mesh). |
| `audit.go` | `audit verify` / `audit keygen` over the signed hash-chained ledger. |
| `capabilitycmd.go` | `capability keygen` / `capability issue` — mint authority keys and short-lived signed tool grants. |
| `secretscmd.go` | `secrets check` — validate the credential broker config (never prints values). |
| `insight.go` | `insight profile/recommend/simulate/detect` — the firewall's read side (delegates to `insight/`). |
| `mcpapp.go` | `mcp` — run meshmcp *itself* as an MCP stdio server so Claude Code / Codex can operate the mesh (incl. the `air_*` tools). |
| `hookcmd.go` | `hook` — the client-hook firewall (F33): a PreToolUse/PostToolUse/prompt adapter for Claude Code / Cursor / Codex that governs *every* local tool call by policy + DLP + taint + audit (`hook install` prints the settings snippet). |
| `httppolicy.go` | `httpEnforcer` — per-tool policy + audit for HTTP backends (F16), reusing `policy.Engine`. |
| `budgetcmd.go` · `statuscmd.go` · `doctorcmd.go` · `configcmd.go` | `budget` / `status` / `doctor` / `config validate` — observability + pre-flight over the audit ledger and config. |
| `spotlightcmd.go` | `spotlight` — **Mesh Spotlight** (F19): federated semantic search fanned out over the mesh (reuses router discovery + the vectors `search` tool), merged, ranked, provenance-tagged. |
| `commands.go` · `auditsink.go` · `httpserve.go` | Plugin subcommand registry (`plugins`, F13/S40); webhook `AuditSink` (F15/S42); hardened loopback HTTP server (S25/S27). |
| `agent.go` | `agent --role …` — demo agent apps (reader/fetcher/billing/analyst) each with their own mesh identity; `--steer-port` adds a steer inbox (P1). |
| `air.go` · `airserve.go` · `airworkflow.go` | **Air · Steer** CLI: `air sessions/steer/launch/agent-steer/workflow/serve` — drive live work over the mesh (see `docs/AIR.md`, `docs/AIR-STEER.md`). |
| `aircontrol.go` | The gateway Air control endpoint (`/v1/sessions`, `/v1/steer`) served by `serve` when a `control:` block is set. |
| `steerenvelope.go` · `steerinbox.go` | The agent steer inbox: envelope wire type + the drop-receiver-style factory that feeds `runAgentLoop`. |
| `pushwake.go` | Push-wake seam: device registry + `Notifier` (vendor APNs/FCM pluggable), wired into `approvals`. |
| `drop.go` · `push.go` · `cas.go` · `peers.go` | AirDrop payload layer: `drop` / `push` / `fetch` / `peers`, resumable + audited. |
| `probe.go` · `replay.go` | `probe` (handshake diagnostic) and `replay` (re-issue a traced session and diff). |
| `pubsub.go` · `pubsubwire.go` | `pubsub` (identity-gated event-bus daemon), `publish`, `subscribe`; the wire protocol + `session.Backend` adapter over the `pubsub/` core. |
| `hooks.go` | Gateway event hooks: publishes each policy decision (`policy.EventHook`) onto an embedded event bus and/or a webhook — observability, decoupled from enforcement (never blocks a decision). |
| `README.md` · `LICENSE` | Project overview; proprietary license (© Rey Darius). |
| `index.html` | Published GitHub Pages site, merged to the code root (Pages still deploys from the `gh-pages` branch). |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `policy/` | The enforcement core: engine, filter, audit, capabilities, secrets hooks, co-sign, trace, replay (see `policy/AGENTS.md`). |
| `mcp/` | Minimal dependency-free MCP **server** framework (see `mcp/AGENTS.md`). |
| `mcpclient/` | Minimal MCP **client** + typed function calls + task client (see `mcpclient/AGENTS.md`). |
| `session/` | Resumable, exactly-once session layer that survives roaming and gateway failover (see `session/AGENTS.md`). |
| `secrets/` | Identity-gated credential broker (`{{secret:NAME}}` injection) (see `secrets/AGENTS.md`). |
| `insight/` | Audit → policy: observe, recommend, simulate, detect (see `insight/AGENTS.md`). |
| `pubsub/` | The identity-native event fabric: deny-by-default topic ACL, taint containment, hash-chained events, bounded fan-out (see `pubsub/AGENTS.md`). |
| `control/` | Managed control plane: enrollment, policy store (see `control/AGENTS.md`). |
| `federation/` | Cross-org tool bridging with identity mapping (see `federation/AGENTS.md`). |
| `registry/` | File-based service registry for router discovery (see `registry/AGENTS.md`). |
| `mobile/` | gomobile-bindable `Mesh`/`Conn`/`Approvals` surface for an iOS/Android app (`gomobile bind ./mobile`). |
| `cmd/` | Standalone MCP servers used as backends: demo (mcpserver/echo/http), payload (kg, vectors, memory), and the Wave-2 dark backends `vault` (F26), `scheduler` (F27), `bus` (F28) (see `cmd/AGENTS.md`). |
| `docs/` | Design docs and open specs (see `docs/AGENTS.md`). |
| `examples/` | Ready-to-adapt gateway configs and the HITL bridge (see `examples/AGENTS.md`). |
| `demo/` | Live-demo run scripts (see `demo/AGENTS.md`). |
| `site/` | Source of the published showcase page (see `site/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Language is **Go 1.26**, module `meshmcp`. The root is `package main`; every `cmd*.go` file adds one CLI subcommand dispatched from `main.go`.
- This is **security-critical** code with fail-closed invariants (see `policy/AGENTS.md`). Preserve the ordering guarantees: audit → trace → secret injection **last**; capability/secret tokens are stripped before the backend, trace, and audit.
- Commit style: focused, direct to `main`, then push (no CI — GitHub Actions are billing-locked, so the local gate below *is* CI).

### Testing Requirements
- **Always** run the race suite with CGO on: `CGO_ENABLED=1 go test ./... -race`. On Windows `-race` **requires** `CGO_ENABLED=1` — omitting it is the most common failure.
- Full green gate: `CGO_ENABLED=1 go build ./... && CGO_ENABLED=1 go vet ./... && CGO_ENABLED=1 go test ./... -race`.

### Common Patterns
- Errors are wrapped with `fmt.Errorf("…: %w", err)` and returned (fail-closed), not logged-and-continued.
- HTML surfaces escape `&<>"'` via `esc()` and avoid inline event handlers (XSS-hardened; use DOM APIs).
- Config validation lives in `loadConfig`; per-connection enforcement is built in `serve.go`'s `backendFactory`.

## Dependencies

### External
- `github.com/netbirdio/netbird` — embedded userspace WireGuard (`client/embed`), source of `IdentityForIP`.
- `github.com/pion/*` — ICE/DTLS/STUN transport stack (indirect, via NetBird).
- `crypto/ed25519` (stdlib) — audit checkpoints and signed capabilities.
- `gopkg.in/yaml.v3` — config parsing.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
