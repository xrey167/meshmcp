<!-- Parent: ../AGENTS.md -->

# harness

## Purpose
The identity-native, mesh-governed agent orchestration engine. It plans,
delegates, spawns, verifies, and loops multi-agent coding/assistant work as
control-plane logic, so every orchestration action inherits meshmcp's existing
guarantees (default-deny firewall, hash-chained audit, secrets-by-reference,
air continuity) instead of re-inventing them. It unifies the capability surface
of four external harnesses (oh-my-openagent, oh-my-claudecode, gajae-code,
openclaw). It DRIVES external provider CLIs/APIs; it is not an inference engine.
See `../docs/harness/DESIGN.md` and `SPEC.md`.

## Key Files
| File | Description |
|------|-------------|
| `governor.go` | The single authorization + audit choke point. `Guard(GovernedAction)` → `policy.Engine.DecideToolCall` verdict + one `policy.AuditLog` record. |
| `role.go` | Canonical role registry; `CompilePolicy` → default-deny `policy.Policy` (roles are policy subjects, matched by the `"<role>--*"` FQDN glob). |
| `category.go` | Category → model-class routing table (a policy artifact insight/config can tune). |
| `mode.go` | Modes and which pipeline stages each runs; `stagesFor`, `loopKindFor`. |
| `orchestrator.go` / `orchestrator_stages.go` | The run lifecycle state machine (`Engine`): intake→…→settle, persisted to `Continuity` per stage. |
| `loop.go` | One parameterized loop driver (ralph/ultrawork/autopilot) with guaranteed termination. |
| `scheduler.go` / `worker.go` | Governed, bounded fan-out; each spawn authorized before an identity is minted; workers retired on completion. |
| `planner.go` / `verify.go` | Interview/plan/plan-review; review_work fan-out + ultragoal check. |
| `intent.go` | IntentGate: keyword → heuristic → (optional) model classification. |
| `continuity.go` | `Continuity` over `air/checkpoint.Store` (identity-bound, audited) + in-mem. |
| `identity.go` | `Identity` + `Minter` (`MemMinter`; production via `control.NetBirdIssuer`). |
| `provider/` `sandbox/` | Provider adapters (mock/CLI + fallback) and exec backends (local/worktree + fail-closed stubs). |
| `hooks/` | Lifecycle hook engine: `(Event) → Effect` chain; safety hooks can't be disabled; a user hook that weakens a safety label is refused at load. Wired into `guard`. |
| `skills/` | `SKILL.md` loader (front-matter + body), builtin/project/user scopes, trigger auto-match. |
| `insight.go` | `Tuner`: profile→recommend→simulate→apply over the harness audit stream. |
| `config.go` `budget.go` `label.go` `action.go` `types.go` | Typed config, budgets, data-flow labels, the `GovernedAction` envelope, and the persisted data model. |

## For AI Agents

### Working In This Directory
- The harness NEVER enforces its own access rules. It compiles roles to a
  `policy.Policy` and honors `policy.Engine`'s verdict. To change what a role may
  do, edit `role.go`'s registry (it compiles to policy), not an ad-hoc check.
- Every action that matters goes through `Governor.Guard` so it is authorized
  AND audited. Do not add a side path that spawns/executes/egresses without it.
- Worker FQDNs follow `"<role>--<run>--<n>"`; the compiled `"<role>--*"` peer
  glob relies on `path.Match`'s `*` spanning the dot-free `--` separator.
- Run state that must survive a crash/roam goes through `Continuity` (air), not
  local disk. Serialize into `RunState`.

### Testing Requirements
- `CGO_ENABLED=1 go test ./harness/... -race`. The golden pipeline test asserts
  the full audit chain verifies (`policy.VerifyChain`) and no worker is left
  un-retired — keep both invariants.

## Dependencies

### Internal
- `policy` (engine + audit), `air/checkpoint` (continuity), `insight` (tuning);
  `secrets`/`control`/`federation` are the production backings (broker keys,
  worker minting, remote reach). Consumed by `mcp/orchestrator` and `cmd/meshmcp`.

### External
- Standard library + `gopkg.in/yaml.v3` (config). Provider CLIs are invoked as
  subprocesses when present.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
