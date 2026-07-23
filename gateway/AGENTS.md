<!-- Parent: ../AGENTS.md -->

# gateway

## Purpose
openclaw's multi-channel Gateway folded into meshmcp as an INGRESS ADAPTER to
the same governed harness — a front door, not a parallel brain. An inbound
message from any channel maps to a harness `RunRequest` driven by a
per-channel-user mesh identity, so the same firewall, audit, secrets, and
continuity apply to a Slack message as to a CLI run. Optional: the harness is
fully usable head-less over MCP + CLI.

## Key Files
| File | Description |
|------|-------------|
| `gateway.go` | `Gateway`: registers channels, routes an inbound message to a governed harness run under a per-channel-user identity, enforces DM pairing, delivers the reply. |
| `slashcommands.go` | Maps openclaw's session commands (`/status /new /reset /compact /think /verbose /trace /usage /stop /pair /restart /activation /help`) onto harness/control ops without running the pipeline. |
| `channels/channels.go` | The `Channel` adapter interface; `WebChat` (in-process, real) and `TokenChannel` (broker-token, fail-closed without a token); the 22-transport `KnownChannels` roster. |

## For AI Agents

### Working In This Directory
- The gateway never bypasses the harness. Every message opens a governed run —
  do not add a path that calls a provider or a tool directly.
- A channel with no broker token reports `Authorized()==false` and is refused;
  a mis-provisioned transport must fail closed, never serve anonymously.
- Non-main channel sessions are meant to be sandboxed and restricted by default
  (`DMPairing.DefaultSandbox`, the per-channel-user identity's role posture).

### Testing Requirements
- `CGO_ENABLED=1 go test ./gateway/... -race`. `gateway_test.go` asserts a
  message opens a governed run whose audit chain verifies, DM pairing blocks
  unpaired sessions, slash-commands map to control ops, and an unprovisioned
  channel is refused.

## Dependencies

### Internal
- `harness` (the engine), `gateway/channels`. Served by `cmd/meshmcp gateway serve`.

### External
- Standard library only.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
