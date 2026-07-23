# The Apple-Standards Gap Analysis

**What is missing for meshmcp to be a full, Apple-grade product from day one.**

> Method: every claim below was checked against the tree (code, docs, CI, git history),
> not inferred from file names. "Apple-grade" is used the way the project's own
> [UX-AGENT-OS.md](UX-AGENT-OS.md) defines its ambition — *one identity, one vocabulary,
> automatic discovery, continuity, progressive disclosure, dependable feedback* — plus the
> parts of Apple's bar that live outside the UI: you can legally acquire it, install it in
> one step, it works out of the box, it never ships a regression, it is supported, and it
> is one focused product rather than forty promising features.

---

## The verdict in one paragraph

The engineering substance is unusually strong — an honest threat model, a capability
maturity matrix, deny-by-default everywhere, a signed audit chain, a written design system
with an accessibility contract, and a served Air app that actually implements much of it.
What is missing is almost everything that surrounds engineering in an Apple launch: **the
product is not legally runnable (license unresolved), has never been released (zero git
tags), cannot be installed without a Go toolchain and a third-party SaaS account, and
ships ~40 CLI verbs and 10 side binaries where Apple would ship five polished surfaces.**
The gap is not "build more features" — it is *finish the shell around the core*: legality,
distribution, focus, native surfaces, quality gates, and the support/business scaffolding.

---

## Scorecard

| Dimension | Grade | One-line reason |
|---|---|---|
| Security engineering & honesty | **A** | Threat model, capability matrix, four-state audit verify, fail-closed defaults |
| UX specification | **A−** | UX-AGENT-OS.md is a real design system: tokens, IA, a11y contract, state language |
| Served web surfaces (Air Home, approvals, dash, room) | **B+** | Real, embedded, API-backed; strong ARIA in `air-live.html` |
| CLI craft | **B** | NO_COLOR/TTY handling, glyph+text states; but error copy is inconsistent |
| Documentation depth | **B** | 30+ docs, cookbook, demo, specs with JSON Schemas — but engineer-voiced, no user manual |
| Test breadth | **B−** | 214 test files / 275 source files, 3 fuzz targets — but no e2e, no coverage gate, 0 benchmarks |
| **Release & distribution** | **F** | 0 tags ever; pipeline never exercised; builds 1 of 10 binaries; no install channel |
| **Legal ability to use the product** | **F** | Proprietary read-only license; the README quick start is forbidden by the LICENSE |
| Out-of-box experience | **D** | Requires Go toolchain + NetBird account + YAML before the first magic moment |
| Product focus | **D+** | ~40 verbs incl. `air osint`, `air film`; Labs boundary admitted but not enforced |
| Native apps & notifications | **D** | Real gomobile bindings, real push seam — but zero shipped app, no APNs/FCM, no menu bar |
| Trust lifecycle UX (lost device, rotation, recovery) | **D** | Pairing/grants/revocation primitives exist; no human story for "my laptop was stolen" |
| Diagnostics & supportability | **C−** | `doctor`/`status`/`probe` exist; no structured logging, no support bundle, no guided recovery |
| Accessibility | **B−** | Served app strong; static demo pages have zero ARIA; admin pages lack focus styles |
| Internationalization | **F** | Nothing. All strings hardcoded English; no locale handling at all |
| Business/support surface | **F** | No support channel, no privacy policy, no issue templates, no pricing, bus factor of one |

---

## What already meets the Apple bar (do not rebuild these)

Credit where it is due — these are genuinely rare in open repos and must be preserved:

- **Honesty as a design value.** [CAPABILITY-MATRIX.md](CAPABILITY-MATRIX.md) separates
  Stable/Beta/Labs/Planned per capability with guarantees *and limits*;
  [THREAT-MODEL.md](THREAT-MODEL.md) states what each control does **not** defend against;
  `audit verify` reports four honest states instead of a fake green check. This is the
  substance behind Apple's "privacy" marketing that most vendors fake.
- **A written design system.** [UX-AGENT-OS.md](UX-AGENT-OS.md) has real tokens
  (light+dark), a five-destination IA (Home/Nearby/Activities/Share/Security), a shared
  object model, motion rules, and a responsive + accessibility contract (44px targets,
  `:focus-visible`, polite live regions, "a 403 never renders as zero").
- **Safe-by-default scaffolding.** `air init` (cmd/meshmcp/airinit.go) writes a
  deny-by-default config with audit on, keeps the one secret out of the file, and treats
  its absence as "a friendly one-step nudge, not a failure."
- **CLI accessibility.** `cmd/meshmcp/style.go` honors `NO_COLOR`/`MESHMCP_NO_COLOR`,
  detects non-TTY output, and always pairs color with a glyph **and** text (`● running`,
  `○ waiting`, `✓`), so no state is color-only — the UX spec's claim holds in code.
- **The served Air app is real.** `air serve` embeds and serves `air-live.html` (1,700
  lines, 77 ARIA attributes, skip link, `prefers-reduced-motion`, live regions) backed by
  real `/api/home`, `/api/nearby`, `/api/drop`, `/api/steer` handlers — not a mockup.
- **Supply-chain hygiene in CI.** Actions pinned by commit SHA, 3-OS matrix with
  `-race`, gofmt/vet/mod-verify gating, a fuzz smoke test, Dependabot.
- **Copy-paste interop.** Working `mcpServers` snippets for Claude Code / Desktop /
  Cursor / Codex / Windsurf ([MCP-APP.md](MCP-APP.md), [CLIENT-HOOKS.md](CLIENT-HOOKS.md),
  [reference.md](reference.md)) plus a real client-hook firewall.

---

## Blockers — without these it is not a product at all

### 1. Nobody may legally run it

`LICENSE` is proprietary and read-only; [LICENSE-DECISION.md](../LICENSE-DECISION.md) is
explicitly unresolved and even documents the contradiction: *"A reader who follows the
quick start would be doing something the license forbids."* Apple never ships anything you
cannot legally use. Every other gap in this document is moot until the owner picks an
option (the decision doc already recommends Apache-2.0 core + commercial control plane).

**Fix:** the owner decides. Then: replace `LICENSE`, add `NOTICE`/third-party attributions
for the embedded NetBird/WireGuard components, update README badges.

### 2. There has never been a release

`git tag` returns **zero tags**. The tag-triggered `release.yml` has never run; its own
comments admit the cross-compile matrix "may need per-target adjustment on the first real
release." It builds only `cmd/meshmcp` — 1 of the 10 `main` packages (`bus`, `kg`,
`mcpecho`, `mcphttp`, `mcpserver/prompt_mcp`, `memory`, `scheduler`, `vault`, `vectors`
are never shipped). CHANGELOG.md has only `[Unreleased]`. `go install @tag` cannot work.
The Capability Matrix itself lists "signed releases + SBOM" as *Planned, Phase 11*.

**Fix:** cut `v0.1.0` now, even with a reduced surface. A product that has shipped a small
v0.1 is a product; a repo with a perfect unreleased pipeline is not. Fold the demo/side
binaries into the main binary or into `examples/` (see Blocker 4) so one release artifact
covers the product.

### 3. The out-of-box experience requires a compiler and a third-party account

The quick start requires: a Go 1.26 toolchain, `git`, building two binaries, and a
**NetBird SaaS setup key** (`export NB_SETUP_KEY=<key from app.netbird.io>`) before the
first magic moment. There is no installer, Homebrew tap, winget/Scoop/apt package, Docker
image, `install.sh`, or auto-update ([RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) line 57
defers all of it). The iPhone bar this project cites — power on, a few taps, it works — is
structurally impossible today for anyone who is not a Go developer with a NetBird account.

**Fix (ordered):** prebuilt signed binaries (Blocker 2) → `brew install` + `install.sh` +
Docker image → make `air up` complete the mesh enrollment itself (guided NetBird signup or
a bundled/self-hosted control-plane path via the existing `control` command) so the first
session is: *download → `meshmcp air up` → QR/pair from second device → drop a file*.
Target: under five minutes, no YAML, no browser tab to a third-party dashboard.

### 4. It is forty features, not one product

`cmd/meshmcp` alone has 165 source files and ~40 user-facing verbs — including `air
osint`, `air film`, `air dns`, `air drive`, `air graph`, `air kg`, `air rag` — beside the
security core, plus 9 sibling binaries. Two overlapping dashboards (`dash`, `room`) plus
Air Home plus the approver. The Capability Matrix admits Labs capabilities are "slated to
move behind an explicit Labs boundary" — i.e., the boundary does not exist in the CLI a
user actually touches. Apple's discipline is the opposite: few surfaces, each finished;
experiments live behind a flag or don't ship.

**Fix:** draw the line in the binary, not just in a doc. Core = mesh + firewall + audit +
Air (init/up/pair/home/drop/send/approve) + insight. Everything Experimental moves under
`meshmcp labs <verb>` (or a build tag), prints a Labs banner, and is excluded from the
default help. Kill or merge one of `dash`/`room` into the Air shell (the UX doc's own
Phase 3 migration says exactly this — execute it).

---

## Major gaps — clearly below the bar

### 5. The killer native moment does not ship

The single most Apple-like flow this product owns — *approve your agent's money-moving
tool call from your phone's lock screen* — dies one step before reality. `mobile/mobile.go`
is a real, tested gomobile binding (Mesh/Conn/Approvals) and `pushwake.go`/`webhooknotify.go`
are a real device-registry + webhook seam, but there is **no built iOS/Android app, no
APNs/FCM delivery, no App Store presence, no desktop menu-bar app, no tray icon** — repo-wide.
[MOBILE.md](MOBILE.md) candidly calls the native shell "the remaining external step."

**Fix:** ship one 3-screen SwiftUI companion (pair · approvals · nearby) over the existing
bindings with real APNs, then Android. A menu-bar approver on macOS is a weekend of work on
the same seam and delivers half the value.

### 6. Four design languages instead of one

A shared token layer exists (`cmd/meshmcp/site/agent-os.css`, consumed by dash, approvals,
room) — but the flagship `air-live.html` ships its **own** inline token set with a
*different* accent (`--blue:#0866ff` vs `--mesh-accent:#1265f5`), the marketing site uses a
third palette (brass on dark), and `site/air.html`/`knowledge-canvas.html` a fourth
(crimson/cyan, dark-only). `airserve.go` even registers the shared CSS that its own page
never links. Apple's products are recognizable from one screenshot because there is one
language.

**Fix:** make `agent-os.css` the single source of truth (it already ships compatibility
aliases for incremental adoption); port `air-live.html` first, then restyle or clearly
retire the concept-mockup pages; align the marketing site to the product tokens.

### 7. No structured logging, no support bundle, no guided recovery

`doctor` (pre-flight), `status` (ledger rollup), and `probe` (live handshake) are real and
good. But: there is no logging framework at all (stdlib `log` + **242** raw
`fmt.Fprintln(os.Stderr, …)` calls in `cmd/meshmcp` alone), no log levels or documented log
locations for the CLI itself, no `sysdiagnose`-style support bundle, and no guided recovery
when the mesh is unreachable or pairing fails — a declined pairing surfaces as
`air join: request declined` with the remote reason *intentionally dropped*
(`airnearby.go:447`) and nothing telling the user what to do next.

**Fix:** adopt `log/slog` with levels behind `--verbose`/`MESHMCP_LOG`; add
`meshmcp diag --bundle` (config-sanitized, audit tail, doctor output, versions, mesh
state); give the three most common failures (no setup key, mesh unreachable, pairing
declined/timeout) dedicated multi-line guidance the way `airpaircli.go:82` already does
for the timeout case — that one string is the standard the rest should meet.

### 8. Error copy is two products in one binary

A minority of errors are Apple-grade (`air init: config.yaml already exists (use --force
to overwrite)`); the majority are plumbing dumps (`marshal config: %w`, `read header: %w`,
`bad response: %w`) surfaced raw through `log.Fatal` with a timestamp prefix. Apple's rule
is one sentence of what happened + one action, always.

**Fix:** an error-presentation layer at the command boundary: wrap the returned chain into
*what failed / likely cause / next command*, keep the raw chain behind `--verbose`. A
style rule in CONTRIBUTING.md ("every user-facing error names a next step") makes it stick.

### 9. Regressions can ship

Zero `func Benchmark` in the repo. Coverage is neither measured nor gated. There is no
automated multi-node mesh test — the only real client→gateway→backend-over-WireGuard flow
is the manual `demo/run-mesh.sh` (needs a live NetBird key, never run in CI); everything
else is in-process. `TestTaskSteer` has been quarantined in CI "until PR #7 merges" —
PR #68 has merged since, and it is still skipped. `staticcheck` and `govulncheck` are
`continue-on-error: true`. For a security product claiming "it just works," the release
gate must make regressions impossible, not advisory.

**Fix:** fix or delete the flaky test (a permanent `-skip` is a silent hole in the
`tasks/steer` surface); promote staticcheck/govulncheck to required; add coverage
reporting with a ratchet; add benchmarks for the hot path (policy decision, session
resume, audit append) with CI thresholds; build a two-node e2e using network namespaces
or two containers with static WireGuard keys (the `serve → call` path does not need the
NetBird SaaS if keys are pre-shared) and make it a required check.

### 10. There is no story for a lost device

The primitives exist (pairing store with `air pair revoke`, capability revocation,
approver ACLs) — but there is no human-facing lifecycle: no documented or guided **"my
laptop was stolen"** flow (revoke the peer everywhere: paired store + policy + NetBird +
capabilities, in one command), no key rotation UX, no identity backup/escrow story
(Apple: iCloud Keychain, Find My revocation), and approvals are still ambient per
(peer, tool) rather than request-bound — the project's own Phase 3. No external security
audit or pentest is referenced anywhere; for a security product approaching 1.0, a
third-party audit is table stakes.

**Fix:** `meshmcp revoke-device <name>` as one atomic, audited operation + a RUNBOOK doc;
implement Phase 3 request-bound approvals before any 1.0 claim; document identity
backup/rotation; budget for an external audit and say so in SECURITY.md.

### 11. Internationalization does not exist

No i18n scaffolding, no locale handling, no message catalogs; every string is hardcoded
English; `golang.org/x/text` appears only as an indirect dependency. Even the time
formatter hardcodes `s/m/h/d`. Apple launches in 40 languages; a German-market product
launching English-only is below even the indie bar.

**Fix:** it need not block v0.1, but the *foundation* must exist before strings multiply
further: route user-facing strings (CLI + served pages) through a catalog now, ship
German as the proving second locale.

### 12. There is no company behind the curtain

No issue/PR templates, no CODEOWNERS, no code of conduct, no support doc or channel beyond
"contact the maintainer through their GitHub profile" (SECURITY.md), no privacy policy for
the GitHub Pages demo (which requests **camera, screen, and mic** in-browser — even if
processing is local, Apple would ship a privacy sheet saying so), no pricing/edition
model (the license decision blocks this too), no crash reporting or opt-in analytics of
any kind (privacy-pure, but it means zero field-quality signal), and a bus factor of one.
The name **"Air"** with explicit AirDrop analogies carries real trademark exposure — the
README's "not affiliated with Apple Inc." disclaimer helps but does not clear
`air drop`-adjacent branding for a commercial launch.

**Fix:** community health files (templates, CoC, SUPPORT.md); a one-page privacy note for
the demo site; a security contact that is not a personal profile; an opt-in,
documented crash/diagnostics channel; a legal review of the Air/drop naming *before*
marketing hardens around it; and a written support/pricing intention even if it is
"free during beta."

---

## Polish gaps — the last 10% that Apple actually does

- **Static pages break the a11y contract the served app keeps.** `site/air.html` and
  `site/knowledge-canvas.html`: zero ARIA, zero `prefers-reduced-motion`, dark-only.
  `dash`/`approvals`/`room`: no focus styles. The marketing site's skip link uses
  `left:-9999px` instead of visible-on-focus.
- **Docs are for engineers, not users.** Thirty-plus excellent specs, but no task-oriented
  user manual ("Share a folder with your other laptop", "Approve from your phone") and the
  README leads with threat-model language. Apple splits marketing / user guide / developer
  docs cleanly. `mcpclient` (the public SDK) has no `example_test.go`; runnable examples
  live only in prose.
- **Go-only ecosystem.** No TypeScript/Python client SDK (only a Python HITL bridge), which
  caps third-party adoption of the catalog/steer/approvals APIs.
- **No performance narrative.** No startup-time or reconnect-latency numbers anywhere;
  "calm under change" is specified for the UI but never measured. Apple treats performance
  regressions as release blockers — that requires baselines first (see gap 9).
- **Version surfacing.** `-X main.version` is wired in release.yml, but with no releases,
  `meshmcp --version` semantics, update checks, and "what's new" surfaces are all unproven.

---

## If this had to launch like an Apple product: the order of operations

1. **Decide the license** (owner-only decision; everything queues behind it).
2. **Cut v0.1.0** — small surface, real tag, exercise release.yml end-to-end, sign and
   notarize the binaries themselves (not just SHA256SUMS), publish brew tap + install.sh
   + Docker.
3. **Draw the Core/Labs line in the binary** — one product (mesh · firewall · audit · Air
   home/pair/drop/send/approve · insight), everything else behind `labs`.
4. **Make `air up` the whole setup** — no NetBird dashboard detour, no YAML, five minutes
   from download to a paired second device.
5. **Ship the phone approver** — SwiftUI shell over the existing `mobile/` bindings with
   APNs; macOS menu-bar approver from the same seam.
6. **One design language** — `agent-os.css` everywhere, starting with `air-live.html`.
7. **Close the quality gates** — un-quarantine `TestTaskSteer`, required
   staticcheck/govulncheck, coverage ratchet, benchmarks with thresholds, a two-node e2e
   as a required check.
8. **Trust lifecycle** — atomic device revocation, request-bound approvals (Phase 3),
   rotation/backup docs, external audit commitment.
9. **Supportability** — slog + levels, `diag --bundle`, guided recovery for the top three
   failures, community health files, demo privacy note.
10. **Foundation for scale** — i18n catalog (German second), TS/Python SDK stubs, a
    task-oriented user guide, performance baselines.

Items 1–4 are the difference between "impressive repository" and "product." Items 5–7 are
the difference between "product" and "feels like Apple made it." Items 8–10 are what keep
it feeling that way after launch.

---

*This analysis intentionally lists nothing the repo already has. Where the project's own
roadmap already names a gap (Phase 3 approvals, Phase 11 signed releases, the Labs
boundary, Ecosystem 6 native companion), this document's contribution is priority and
sequencing; the genuinely unplanned blind spots found here are: structured logging and a
support bundle, error-copy consistency, benchmarks/coverage/e2e gating, the design-token
fragmentation, i18n, the demo-site privacy note, the lost-device runbook, the Air
trademark review, and the release pipeline having never been exercised.*
