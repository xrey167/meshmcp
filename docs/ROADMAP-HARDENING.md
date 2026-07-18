# meshmcp — Hardening & Enhancement Roadmap (Wave 2)

> The second grounded ideation map. Wave 1 (`IDEAS.md`, **F1–F12** + **S1–S10**) turned meshmcp
> from a control plane that *governs* other people's tools into a fabric that *carries valuable
> payloads* — knowledge, memory, files — with provenance and governance built in. Wave 2 continues
> the same ID convention from **F13 / S11**, and does two things at once: it **hardens** the
> guarantees that are already the moat, and it makes the whole plane **extensible** — a plugin
> platform, new dark backends, and an observability spine, each novel *because of* the primitives
> that already exist.

---

## The thesis

Wave 1 proved the primitives. Wave 2's move is to make them **pluggable and provable**: the same
WireGuard key that authorizes a tool call — and stamps a knowledge triple or a shared file — should
also key a **typed extension seam**, so a DLP scanner, an external policy service, a SIEM sink, or a
whole new tool is a first-class, testable, invariant-preserving plugin rather than a fork. And the
same fail-closed discipline that makes the audit non-repudiable should hold *everywhere* — under a
full disk, a mis-typed window, a stray session id.

| Primitive (proven in Wave 1) | What Wave 2 does with it | Where |
|---|---|---|
| **Cryptographic identity** | Bind sessions, co-signs, and SSO to the proven key | `acl.go`, `session/`, `federation/` |
| **Three-valued policy engine** | A `DecisionHook` seam: plugins add allow / deny / co-sign | `policy/engine.go` |
| **MCP middleware chain** | Tool plugins via `Use`/`UseTool`, config-driven | `mcp/middleware.go` |
| **Hash-chained signed audit** | A swappable `AuditSink` (OTel · SIEM · webhook) + a fail-closed mode | `policy/audit.go` |
| **Signed capabilities** | A real revocation store and delegation | `policy/capability.go` |
| **Resumable + migratable sessions** | New dark backends (vault · scheduler · bus) ride the channel | `session/` |
| **Router · federation · insight** | Federated Spotlight, shadow-policy canary, a plugin marketplace | `router.go`, `federation/`, `insight/` |

> **Grounding (both explorations confirmed):** extension in meshmcp is **compile-time via Go
> interfaces** — there is **no dynamic loading anywhere**, and that is deliberate (an external
> "fabric" plugin pack of foreign provenance was reviewed and **not** merged, `EXTENSIONS.md`). Wave 2
> honors that bar: **fresh code against meshmcp's own baseline (MCP 2025-06-18, the three-valued
> engine, the hash-chained audit), every invariant proven by a `-race` test, no untrusted code loaded
> at runtime.**

---

## Implemented status

Shipped in this branch (tested, `CGO_ENABLED=1 go build/vet/test ./... -race` green):

- **P0-1, P0-2, P0-3** — all three fix-now issues.
- Flagships: **F13** (plugin seams — `DecisionHook`, `AuditSink`, subcommand registry + `plugins`),
  **F18** (pattern DLP hook), **F21** (capability revocation store + `capability revoke/list`),
  **F22** (fail-closed audit mode), **F23** (identity-bound sessions).
- Minors: **S11–S14, S16–S18, S20, S22–S23, S25–S30, S32, S36–S40, S48** (plus `config validate`).

Forward backlog: flagships **F14–F17, F19, F20, F24–F32** and the remaining minors.

---

## P0 · fix now — before any roadmap work

Three issues are exploitable today. Each is small and localized; each has a flagship that carries the
full treatment.

| P0 | Issue | Where | Immediate fix |
|----|-------|-------|---------------|
| **P0-1 · session takeover by id** | `attach` resumes / rehydrates a session from the 16-byte ATTACH id alone; the creator's identity is never re-checked, and ids are logged and shared for migration. Any mesh peer that learns an id takes over the backend and its buffered output. | `session/server.go` | Record the creator's WireGuard key in the session; reject ATTACH / rehydrate from a different identity. → **F23** |
| **P0-2 · unauthenticated local shell** | `room --local-shell` runs a raw shell with a loopback bind and CSRF / DNS-rebinding guards but **no auth** — any local process can POST `/api/shell`. | `room.go` | Require a startup-generated bearer token on `/api/shell` (and `/api/call`) even on loopback. → **S36** |
| **P0-3 · audit-write fail-open** | `AuditLog.write` swallows marshal / write errors and the call proceeds to the backend regardless; a full disk drops the record and still authorizes — breaking *"audit is a control."* | `policy/audit.go`, `policy/filter.go` | Propagate write errors and deny when the sink fails; make a missing signing key fatal rather than silently regenerating it. → **F22** |

---

## Flagship tier — F13–F32

Twenty deeply-developed features, capability-first, each novel *because of* meshmcp's primitives.

### F13 · Mesh Extension SDK — the plugin platform  ⭐ *the anchor*
A first-class, **compile-time Go-interface** plugin system unifying the five seams the codebase
already exposes or nearly exposes: **tool plugins** via `mcp.ToolMiddleware` (`Use`/`UseTool`);
**decision plugins** via a new `policy.DecisionHook` invoked after `Engine.DecideToolCall`, before the
default branch; **per-connection collaborators** via the established `SecretResolver`/`PendingStore`/
`CosignStore` + `SetXxx` idiom wired in `serve.go`'s `backendFactory`; **sink plugins** via an extracted
`AuditSink`/`TraceSink` interface (a single call site in `filter.go`); and a **subcommand registry**
(`init()`-populated map) replacing the hand-maintained switch in `main.go`. Plugins are declared in
config, listed by `meshmcp plugins`, and each ships a `-race` test proving it preserves the fail-closed
and strip-before-forward ordering. No dynamic loading — ever.
> **Why it's revolutionary:** every control-plane concern becomes a typed, testable, invariant-preserving
> plugin — without forking the gateway or trusting an external binary.

### F14 · Governed plugin marketplace over the mesh
Extend `federation/` + `registry/` into a signed **plugin exchange**: publish and discover plugin bundles
(policy packs, tool backends, decision hooks) by identity, capability-gated, metered, and audited on both
sides of the trust seam — reusing the F12 crossing model and signed-capability admission.
> **Why it's revolutionary:** a zero-exposure marketplace for control-plane extensions where every install
> is a mintable grant and every use is attributable — no public registry, no unsigned code.

### F15 · Observability plane — `meshmcp status` + OTel / SIEM export
Deliver the open Phase 7: live sessions, peers, and per-tool call rates, plus the audit / trace stream
shipped to any sink through the F13 `AuditSink` plugin (OpenTelemetry, a SIEM, a webhook). Reuses
`policy/analyze.go` aggregation.
> **Why it's revolutionary:** *"who called what, from where, when"* becomes queryable **and** exportable for
> an entire agent fleet — through a plugin, with nothing exposed.

### F16 · HTTP-backend policy parity
Close the biggest honest limitation: HTTP backends today get only a network ACL, not per-tool parsing.
Parse the Streamable-HTTP JSON-RPC at the reverse proxy so **policy, audit, secret injection, and
capabilities apply to HTTP backends too**, reusing the exact `Filter` pipeline stdio backends already run.
> **Why it's revolutionary:** the firewall stops being stdio-only — every backend, on any transport, gets
> the same identity-keyed policy and tamper-evident audit.

### F17 · Group-based policy via the NetBird management API
Policy matches FQDN and pubkey today. Add **group-membership rules** through the management API, reusing
the `control/netbird.go` `Doer` pattern so it stays mockable and testable.
> **Why it's revolutionary:** authorization by role and group at org scale, not just per-key — the mesh
> firewall learns to speak the language of the directory.

### F18 · Semantic firewall — DLP as a decision-hook plugin
A `DecisionHook` (F13) that scans tool arguments and results against the local deterministic embedder
(`embed/`) for PII / secret / topic patterns, then **emits data-flow labels or denies inline** — reusing
the `emit_labels` / `block_labels` lattice and the taint machinery.
> **Why it's revolutionary:** content-aware data-loss prevention enforced at the network layer, below the
> model where no jailbreak reaches — shipped as a swappable plugin.

### F19 · Mesh Spotlight — federated semantic search
Finally build the one unbuilt Wave-1 flagship (F4): one query, semantically searched across **every** file
and corpus on peers your identity is authorized to see (F1 discovery + F3 RAG over the router), ranked and
provenance-tagged, each peer answering only within its own policy.
> **Why it's revolutionary:** private, permissioned, federated *"search my entire mesh"* — Spotlight for a
> distributed org, with no central index and nothing exposed.

### F20 · Provable human authorization — signed co-sign
Turn co-sign approvals into **Ed25519-signed records** verified at the enforcement point and restricted to
an operator identity allowlist. Today an approval is a filesystem file that grants merely by existing.
> **Why it's revolutionary:** non-repudiable human-in-the-loop — the approver's identity is cryptographic
> and lands in the ledger, so an insider with write access to the store still can't forge an approval.

### F21 · Capability lifecycle — a mesh-distributed revocation store
Wire the verifier's revocation predicate (present in code, unwired today) to a config-driven, mesh-distributed
revocation store, and add `capability revoke` / `capability list`.
> **Why it's revolutionary:** short-lived grants gain a real kill-switch — capabilities become a managed
> lifecycle, not a fire-and-forget TTL.

### F22 · Fail-closed audit mode
An opt-in posture where an audit or checkpoint **write failure denies the call**, and every checkpoint /
anchor I/O error is surfaced rather than swallowed. Makes *"audit is a control"* literally enforced.
> **Why it's revolutionary:** the tamper-evident ledger becomes a true gate — provable completeness even
> under disk failure, not best-effort logging. (Carries **P0-3**.)

### F23 · Identity-bound sessions — takeover defense
Bind every resumable and migratable session to its creator's WireGuard key, and reject ATTACH / rehydrate
from a different identity.
> **Why it's revolutionary:** the continuity layer that survives roaming and a gateway crash becomes
> identity-bound — resilience without a takeover surface. (Carries **P0-1**.)

### F24 · Shadow policy — a live canary and CI gate
Extend `insight/` into a mesh service and a shadow `DecisionHook`: run a candidate policy **against live
traffic in shadow mode**, diff its verdicts (reusing `insight/simulate.go`), and gate a deploy on regressions.
> **Why it's revolutionary:** a policy change gets a live, provable canary before it ever enforces — no more
> *"deploy and pray"* on an allowlist.

### F25 · Multi-tenant control plane
Extend `control/` to serve many orgs / teams with **per-tenant** policy stores, enrollment, and audit
isolation, over one dark control service.
> **Why it's revolutionary:** managed meshmcp-as-a-service, cryptographically identity-isolated per tenant,
> with no shared attack surface.

### F26 · Mesh secrets vault — `cmd/vault`
A new dark MCP backend that stores and **rotates** secrets, fronted by the existing broker so agents still
reference `{{secret:NAME}}` and never hold the value — upgrading the file / env store to a first-class,
identity-gated vault on the mesh.
> **Why it's revolutionary:** a zero-exposure secrets manager as an MCP tool, where every use is audited by
> name and refused into a tainted session — no cloud KMS, no exposed endpoint.

### F27 · Governed scheduler / cron — `cmd/scheduler`
A new dark backend firing **identity-attributed scheduled tool calls** over the mesh, each fired call
policy-gated and audited like any other, with co-sign supported for privileged jobs.
> **Why it's revolutionary:** automation where every scheduled action is attributable and provable — cron
> for an agent fleet that cannot act outside its policy.

### F28 · Governed event bus — `cmd/bus`
A new identity-stamped, policy-filtered **pub/sub** MCP backend riding resumable sessions, so agents
subscribe to event streams by identity and receive only what their labels permit.
> **Why it's revolutionary:** a zero-exposure event fabric where subscription is a capability and every
> delivery is attributable — reactive agents without a broker to expose.

### F29 · Cost & budget governance plane
Deliver the open Phase 5 on the rate / cost primitive already in the engine: per-identity token and cost
accounting across tools, budgets, **denied-by-budget inline** (the same mechanism as a policy deny), and a
spend view in the dashboard.
> **Why it's revolutionary:** FinOps for agent fleets — spend caps enforced at the network layer, keyed to
> cryptographic identity, not reconciled by a billing webhook after the fact.

### F30 · Continuity 2.0 — first-class live agent handoff
Build the UX on the proven session-migration substrate (F5): a `meshmcp handoff` command and a Control-Room
**drag-to-handoff** that moves a live agent session — context and in-flight state — between devices,
gateways, or teammates by identity.
> **Why it's revolutionary:** Apple-Continuity handoff for AI agents, now a first-class governed operation
> over a zero-exposure mesh.

### F31 · Federated identity — SSO mapping at the seam
Map external IdP identities (OIDC) to mesh identities at the federation boundary, reusing the identity
mapping already in `federation/boundary.go`, so **org SSO drives policy**.
> **Why it's revolutionary:** enterprise SSO meets cryptographic mesh identity — a user's directory role
> becomes their tool-call authorization, end to end and audited.

### F32 · Compliance & attestation pack
One command bundles a **verifiable evidence package**: the signed audit, its Merkle checkpoints, the
effective policy, and the provenance receipts (F6) — exportable and independently verifiable with the
public key alone.
> **Why it's revolutionary:** *"prove to an auditor what the fleet did — with math, not trust"* becomes a
> single command; compliance-grade, non-repudiable, reproducible.

---

## Supporting tier — S11–S60

Fifty items, higher value for lower lift — mostly primitive reuse. The Wave-1 hardening sweep is
concentrated here.

### Hardening — S11–S36 · closing the sweep

| # | Idea | Reuses / where |
|---|------|----------------|
| **S11** | Reserve an audit sequence only on a **successful** write (no silent chain gap) | `policy/audit.go` |
| **S12** | Surface checkpoint / anchor I/O errors instead of ignoring them | `policy/checkpoint.go` |
| **S13** | A missing `audit_signing_key` is **fatal**, never silently regenerated | `serve.go` |
| **S14** | Audit, trace, and persisted-session files at **0600**, not 0644 | `serve.go`, `session/store.go` |
| **S15** | Bound an audit record's size at write time (matches the verify cap) | `policy/audit.go`, `chain.go` |
| **S16** | A malformed `when` window becomes **inactive / deny**, not fail-open true | `policy/engine.go` |
| **S17** | Reject `rate.max <= 0` at load (don't silently disable the limit) | `policy/engine.go`, `config.go` |
| **S18** | Deny / label an **unparseable single** JSON-RPC line under an active engine | `policy/filter.go` |
| **S19** | An optional capability **jti replay cache** for single-use grants | `policy/capability.go` |
| **S20** | Cap the filter's write-reassembly and backend line buffers (memory-DoS) | `policy/filter.go` |
| **S21** | A bounded / tailing dashboard read instead of a full-file `ReadAll` every 1.5–2 s | `policy/analyze.go`, `dash.go` |
| **S22** | Require explicit `peers` on a secret grant (empty ≠ everyone) | `secrets/broker.go`, `config.go` |
| **S23** | `Stat` and refuse / warn on a group- or world-readable secrets file | `secrets/store.go`, `serve.go` |
| **S24** | Document that taint labels must cover any tool echoing untrusted content | `docs/SECRETS.md` |
| **S25** | Wrap `dash` in the same loopback / rebinding guard `room` uses | `dash.go` |
| **S26** | `http.MaxBytesReader` on `/v1/approve` and `/v1/deny` | `approvals.go` |
| **S27** | `ReadHeaderTimeout` / `ReadTimeout` on dash / room / approvals (Slowloris) | `dash.go`, `room.go`, `approvals.go` |
| **S28** | A **`Policy.Validate()`** at load: compile every glob, parse every duration / window / TZ | `config.go`, `policy/policy.go` |
| **S29** | Validate the `session_store_mode` enum at load (typos silently downgrade) | `serve.go` |
| **S30** | Deny when `IdentityForIP` fails (no empty-identity admission) | `acl.go` |
| **S31** | Bound YAML expansion / document the config trust model | `config.go` |
| **S32** | Remove the committed prebuilt ELF binaries (`kg`, `memory`); gitignore; build from `cmd/` | repo root |
| **S33** | Add `govulncheck` and a periodic audit of the `replace`-directive fork pins | `go.mod`, the gate |
| **S34** | An operator **allowlist** for the co-sign approve / deny endpoints (no self-approval) | `approvals.go` · with **F20** |
| **S35** | Sign co-sign approval records; fail closed on a parse error (not exists-⇒-approved) | `policy/cosign.go` · with **F20** |
| **S36** | A startup bearer token for `room`'s `/api/shell` + `/api/call`, even on loopback | `room.go` · with **P0-2** |

### Plugin & observability plumbing — S37–S44 · enables F13 / F15

| # | Idea | Reuses |
|---|------|--------|
| **S37** | A `meshmcp plugins` list / inspect command | F13 subcommand registry |
| **S38** | Extract the `AuditSink` / `TraceSink` interfaces (a narrow, single-call-site seam) | `policy/audit.go`, `trace.go`, `filter.go` |
| **S39** | The `policy.DecisionHook` interface, its composition, and `-race` tests | `policy/engine.go` |
| **S40** | A subcommand registry (`init()`-populated map) replacing the `main.go` switch | `main.go` |
| **S41** | An OpenTelemetry / Prometheus metrics exporter plugin | F13 sink + `analyze.go` |
| **S42** | A webhook audit-sink plugin (Slack / PagerDuty on deny or cosign) | F13 sink |
| **S43** | `meshmcp status` with JSON output and per-tool call rates | `policy/analyze.go` |
| **S44** | Config-driven per-tool `Timeout` / `LimitConcurrency` middleware | `mcp/middleware.go` |

### New capability & tooling — S45–S60

| # | Idea | Reuses |
|---|------|--------|
| **S45** | A thin `connect`-only client build (drops the heavy daemon dep tree) | build tags, `bridge.go` |
| **S46** | A single physical-roam integration test | `session/` `-race` harness |
| **S47** | `meshmcp doctor` — a mesh / backend health probe | `probe.go` |
| **S48** | A `meshmcp config validate` command | `loadConfig` + S28 |
| **S49** | `meshmcp policy lint` plus templates / `policy init` | `insight/`, the POLICY-DSL spec |
| **S50** | Policy hot-reload (watch the config, atomic swap) | `serve.go`, `config.go` |
| **S51** | Audit-log rotation / compaction preserving chain continuity | `policy/audit.go` `SeedFrom` |
| **S52** | Audit export to CSV / Parquet for BI | `policy.AuditRecord` |
| **S53** | `drop --resume` progress and resumable transfer receipts | `drop.go`, `session/` |
| **S54** | Content-addressed store garbage collection / `fetch --gc` | `cas.go` |
| **S55** | `--json` / machine-readable output across the CLI (`peers`, `ls`, …) | `cli.go`, `peers.go` |
| **S56** | Rate-limit denial metadata (retry-after) in the JSON-RPC error | `policy/engine.go`, `filter.go` |
| **S57** | Capability delegation / sub-grants, bounded by the parent | `policy/capability.go` |
| **S58** | Federation metering / billing export | `federation/` · extends **F12** |
| **S59** | A natural-language mesh-ops verb expansion | `mcpapp.go` · extends **S10** |
| **S60** | Control-Room multiplayer presence + drag-to-handoff | `room.go` · extends **S9**, supports **F30** |

*Flagship F13–F32 (20) + supporting S11–S60 (50) = 70 grounded items.*

---

## Recommended build order

1. **P0-1 · P0-2 · P0-3** — the exploitable-now fixes; small and localized.
2. **The F13 plugin seams** via **S38 · S39 · S40** (extract `AuditSink`/`TraceSink`, add the
   `DecisionHook`, add the subcommand registry) — these unlock F14 · F15 · F18 · F24 and *are* the plugin ask.
3. **F16** (HTTP policy parity) and the **F22 · F23** postures — the highest-leverage correctness work.
4. Capability flagships that ride existing primitives cheaply: **F19** (Spotlight), **F20 · F21**
   (co-sign + revocation), **F29** (cost governance), then the new backends **F26 · F27 · F28**.
5. The fifty minor absorbed opportunistically — the hardening block **S11–S36** alongside whichever
   flagship touches the same file.

## Design invariants these must honor

1. **No open ports, ever** — every new backend and plugin rides the mesh interface only.
2. **Identity is cryptographic, never claimed** — a session bind, a co-sign, an SSO mapping keys off the
   WireGuard key the transport proves.
3. **Deny is the safe default** — a plugin decision hook, like a rule, may tighten but never silently widen;
   a malformed window, rate, or glob fails closed.
4. **Audit is a control, not best-effort** — a write that can't land is a denial, not a dropped record.
5. **Pure transport where possible** — plugins authorize and observe; they never rewrite tool semantics.

## Verification

- **The repo gate, on every change:** `CGO_ENABLED=1 go build ./... && CGO_ENABLED=1 go vet ./... && CGO_ENABLED=1 go test ./... -race`.
- **A per-feature invariant test**, in the pattern every package already follows — e.g. a `DecisionHook`
  that cannot override an explicit deny or a co-sign; a denied `tools/call` that never reaches an HTTP
  backend; an ATTACH from a foreign identity that is rejected; a write error that denies the call.
- **An end-to-end drive:** each new backend ships an `examples/*.yaml`, validated by `meshmcp config
  validate` (S48), exercised over the mesh with `probe` / `ls` / `call`, and watched in `dash` / `room`.
- **A red-team regression per closed finding** — a session-takeover repro before F23, a malformed-window
  fail-open before S16 — so each fix carries a proof it stays fixed.

---

<sub>Wave-2 ideation map for meshmcp · © Rey Darius · see <a href="IDEAS.md">IDEAS.md</a> (Wave 1) and <a href="VISION.md">VISION.md</a> (the grounded roadmap).</sub>
