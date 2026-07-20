<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# secrets

## Purpose
An identity-gated credential broker on the mesh. Agents reference a secret **by name** (`{{secret:NAME}}`) inside tool arguments and never hold the value; the gateway resolves and injects the real credential on the way to the backend, gated by the caller's identity, the tool, and session labels. Every use is audited by name (never value), and injection is refused into a **tainted** session so untrusted content can't trigger a credential use. Implements the `policy.SecretResolver` seam.

## Key Files
| File | Description |
|------|-------------|
| `store.go` | Package doc + `Store` abstraction: file store (`0600` JSON), env store (`prefix+NAME`), and a `Chain` layering them. |
| `broker.go` | `Broker`: matches `{{secret:NAME}}` refs (`refRe`), checks `Grant`s (by peer / tool / `block_labels`), and rewrites the outbound line with resolved values. Refuses on ungranted / tainted / unavailable. |

## For AI Agents

### Working In This Directory
- Resolution happens at the enforcement point (inside the `Filter`) and is the **last** step before the backend write — so the resolved value reaches only the backend, never audit or trace.
- A grant with `block_labels: ["tainted"]` must never resolve once the session is tainted. This taint-refusal is a core security property; keep it covered by `broker_test.go` (`TestBrokerTaintBlocksInjection`).
- Never log or echo a resolved value. Config validation (`secrets check`) proves configs without revealing anything.

### Testing Requirements
- `CGO_ENABLED=1 go test ./secrets/ -race`. `integration_test.go` uses a recording backend to assert the value reaches the backend and nothing else.

## Dependencies

### Internal
- Constructed in root `serve.go`; wired into `policy.Filter` via `SetSecretResolver`. Shares the backend's hash-chained `policy.AuditLog`.

### External
- Standard library only.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
