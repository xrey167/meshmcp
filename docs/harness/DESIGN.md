# meshmcp `harness` — Design & Implementation

**An identity-native, mesh-governed agent orchestration engine and MCP server.**

This document mirrors `SPEC.md` and records how the spec maps onto meshmcp's
*real* control-plane APIs, what is implemented, and what is deferred. The harness
absorbs the useful capability surface of four external agent harnesses
(oh-my-openagent, oh-my-claudecode, gajae-code, openclaw) and re-implements it
natively so every orchestration action inherits meshmcp's guarantees.

## Guarantees (inherited, not re-invented)

| Guarantee | Spec | Real meshmcp API the harness uses |
|---|---|---|
| Transport-bound identity | §4 | `harness.Identity{Key,FQDN,Role}` + `Minter`; production via `control.NetBirdIssuer.Enroll/Deregister`; `MemMinter` for tests |
| Default-deny agent firewall | §9 | Role capability sets compile (`harness.CompilePolicy`) to `policy.Policy{DefaultAllow:false}`; `policy.Engine.DecideToolCall` is the single authority |
| Tamper-evident audit | §11 | `policy.AuditLog.Append` (Ed25519 hash chain + Merkle checkpoints); `policy.VerifyChain` |
| Secrets by reference | §10 | `secrets.Broker.Resolve` over `{{secret:NAME}}`; providers pull keys via `provider.KeySource` (satisfied by `secrets.Store`) |
| Continuity via air | §12 | `air/checkpoint.Store` (identity-bound, audited, resumable) wrapped by `harness.AirContinuity` |
| Adaptive behavior | §9.3 | `insight.Profile/Recommend/Simulate/Detect` via `harness.Tuner` |
| Federation / remote providers | §13 | `federation.NewBoundary` + `Boundary.OrgFor/Allowed/Check` (documented touchpoint) |

## The governed-action choke point

Every action that matters is wrapped in a `harness.GovernedAction` and passed
through `harness.Governor.Guard`, whose path is identical for all actions:

```
Decide(policy.Engine) → (deny | allow | needs-cosign) → [approve] → Execute → Emit(policy.AuditLog)
```

`Governor` holds a `policy.Engine` compiled from the role registry and a
`policy.AuditLog`. It emits one hash-chained record per action; harness-specific
context (run/job/category/mode/provider, the action's labels, the redacted args
digest) is folded into the record's `Reason` so it is covered by the chain
without modifying the shared `policy.AuditRecord` type.

## Roles → policy (the firewall, compiled)

`harness/role.go` defines the canonical role registry (union of the source
projects' agents, de-duplicated). `CompilePolicy` turns it into a default-deny
`policy.Policy`: per role, a co-sign rule (placed first), an allow rule carrying
the role's emit-labels, matched by the `"<role>--*"` FQDN glob that every worker
of that role satisfies. Roles are policy subjects; the harness enforces nothing
itself — it honors the `policy.Engine` verdict.

## Run lifecycle (the merged pipeline)

`intake → interview → plan → plan-review → approve → execute → verify → fix → settle`

`harness/orchestrator.go` + `orchestrator_stages.go` implement it as a state
machine (`Engine`). `Mode` selects which stages run; loop modes (ralph /
ultrawork / autopilot) drive `execute→verify→fix` per round via `LoopSpec.Drive`,
which guarantees termination (max-rounds, budget, operator stop, no-diff). Run
state is persisted to `Continuity` after every stage, so a crash/roam resumes
from the recorded stage. High-risk runs park on `approve` until a human co-signs
(`policy.CosignStore`); the stop-continuation guard refuses to resume a cancelled
run.

## Modes and categories

- **Modes** (`harness/mode.go`): quick, team, autopilot, ralph, ultrawork,
  synthesize, interview-only, plan-only — clamped by policy/config.
- **Categories** (`harness/category.go`): a *policy artifact* mapping a work
  class → model class, fan-out, interview, reviewers. `insight` can tune it and
  config can override it (policy-clamped).

## Providers, sandboxes, scheduler

- **Providers** (`harness/provider/`): one `Provider` interface; `Mock`
  (deterministic, the default so headless runs execute), `CLI` (drives
  Claude/Codex/Gemini as subprocesses, key from the broker via `KeySource`),
  `MCPProvider` (reaches a model exposed as an MCP tool over a dialed
  connection — a mesh dial in production, so a remote/cross-org provider is
  reached via federation with transport-bound identity), and a `Registry`
  fallback chain resolving a model class to the first available provider.
- **Sandboxes** (`harness/sandbox/`): `local`, real git `worktree` isolation,
  and fail-closed `Stub`s for tmux/docker/ssh/openshell (an unavailable
  isolation backend never degrades to host execution). `AtLeast` ensures a
  policy minimum can't be weakened.
- **Scheduler** (`harness/scheduler.go`): governed, bounded fan-out. Each spawn
  is authorized before a worker identity is minted; each worker runs in its own
  sandbox and is retired on completion (identity sealed).

## MCP server (`mcp/orchestrator/`)

A dark MCP service exposing the tool catalog with the source projects' tool
names. **Governance is a global middleware**, so no tool escapes the firewall:
each call is authorized against the caller's role via `Governor.Guard` and
audited. Tools registered: delegation (task, call_agent, background_*,
synthesize), planning/verify (plan, plan_review, interview, start_work,
review_work, ultragoal_check), code intel (grep/glob/edit real; lsp_*, ast_grep_*,
look_at governed with Phase-2 backends), sessions + task store, terminal
(interactive_bash real), browser/canvas/nodes/cron (governed, Phase-2/4 driver),
skills + market.

## Hooks (`harness/hooks/`)

A lifecycle hook engine: a middleware chain of pure `(Event) → Effect` decisions
(`continue|mutate|block|retry|inject`) evaluated at defined points (pre-plan,
pre-tool, post-tool, pre-spawn, post-run, on-error, on-notify). Built-ins merge
the source projects' 54–61 hooks into a representative governed set
(keyword-detector, stop-continuation-guard, write-existing-file-guard,
taint-egress-guard, tool-output-truncator, runtime-fallback). Governance: a
`Safety` hook cannot be disabled, and a user hook declaring `WeakensSafety()` is
refused at load. The `Engine` optionally runs pre-tool hooks in its guard path,
so a safety hook can veto an otherwise-policy-allowed action.

## Skills (`harness/skills/`)

A `SKILL.md` loader (YAML front-matter + markdown body) over three scopes
(builtin, project `.harness/skills/`, user `~/.harness/skills/`, later scopes
overriding earlier). Triggers auto-match a skill to a request. A skill that
embeds an MCP declares it (`EmbeddedMCP`); installation is a governed `market`
transaction, so the loader only reads local, provenanced files. The MCP `skill`
tool serves the registry (list / match-by-context / fetch instructions).

## Gateway (`gateway/`) — Phase 4

openclaw's multi-channel ingress folded in as a *front door to the same governed
harness*, not a parallel brain. An inbound message maps to a harness
`RunRequest` driven by a per-channel-user mesh identity, so the same firewall,
audit, and continuity apply to a Slack message as to a CLI run. Channel adapters
(`gateway/channels/`) authenticate via broker-held tokens — an un-provisioned
channel is refused (fail-closed). DM pairing gates unpaired sessions. Session
slash-commands (`/status /new /reset /compact /think /verbose /trace /usage
/stop /pair /restart /activation /help`) map to harness/control ops. 22 known
transports are enumerated; webchat is in-process and real, the rest are token
channels pending live transport wiring.

## CLI (`meshmcp harness ...` and `meshmcp gateway ...`)

`harness serve` (stdio dark service), `run`, `plan`, `interview`, `verify`,
`roles`, `status`; `gateway serve` (webchat over stdin), `gateway channels ls`.
Shared flags wire a governed `Engine`: `--audit` (hash-chained log, continued
across restarts), `--cosign-store`, `--state-dir` (air continuity).

## Implemented vs. deferred

**Implemented and tested (Phases 0–4 core):** role→policy compilation and the
default-deny matrix; the governed-action choke point + audit chain; the full
run lifecycle with all modes; loop termination; category routing; budgets;
provider interface + mock + CLI adapter + fallback; local/worktree sandboxes +
fail-closed stubs; air-backed and in-memory continuity with identity binding;
the MCP tool catalog with global governance middleware; the hook engine
(wired into the guard path); the skills loader (wired into the `skill` tool);
the gateway ingress with channels, DM pairing, and session slash-commands; the
`harness` and `gateway` CLI verbs; insight adaptive-tuning
(profile→recommend→simulate→apply).

The orchestrator dark service now serves over the mesh (`harness serve
--listen`, mirroring `cmdOrchestrate`'s accept loop) as well as stdio; remote
providers are reachable over MCP (`MCPProvider`); and `EnrollMinter` mints real
ephemeral mesh worker identities — it generates a WireGuard (X25519) keypair per
worker (so the public key IS the transport-bound identity), obtains a scoped
one-off enrollment credential from the control plane (`control.NetBirdIssuer`
via the `harness.Enroller` interface), and deregisters on retire. Selected with
`harness serve|run --minter netbird` (PAT via `--nb-token`/`$NB_API_TOKEN`);
`mem` (in-process keys) remains the default.

**Deferred (wiring, not design):** live provider CLIs require the binaries +
broker keys; LSP/AST/browser/canvas/nodes/cron live backends (Phase 2/4); the
worker-process spawner that launches a minted identity onto the mesh with its
`WorkerCreds`; the non-webchat channel transports (Phase 4 live wiring); Live
Canvas / voice surfaces. Every deferred tool/channel is still *registered and
governed* — a call passes the firewall and is audited, and it fails closed rather
than silently succeeding.

## Tests

`go test ./harness/... ./mcp/orchestrator/... -race`. Covers: the role→policy
allow/deny/cosign matrix; the golden pipeline (team/quick/ralph) with full audit
chain verification and worker-retirement assertions; high-risk co-sign
block/resume; the stop-continuation guard; continuity roundtrip + identity
binding; provider fallback; sandbox isolation (worktree writes don't touch the
source repo) and fail-closed stubs; the MCP governance boundary (orchestrator may
grep but not edit; executor may edit); malformed-args no-panic; insight tuning.
