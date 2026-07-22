# MeshMCP Agent OS — UX/UI system

> **Status:** living product specification · Phase 1 implemented in Air Home

MeshMCP is the secure agent platform. **Air is its user-facing operating
system.** The UX goal is not to imitate another company's pixels; it is to
create the same feeling of coherence: one identity, one vocabulary, automatic
discovery, continuity between devices, progressive disclosure, and dependable
feedback after every action.

The reference screens for the first implementation are the
[desktop Home](design/agent-os-home-desktop.png) and
[mobile Home](design/agent-os-home-mobile.png).

## Product principles

1. **Work first, infrastructure second.** Lead with “Continue working”, a
   friendly agent name, and the next action. Put IPs, ports, keys, hashes, and
   policy internals behind details or JSON output.
2. **Appears everywhere.** One verified Presence/Activity update should become
   visible in Home, Nearby, CLI, and assistant tools without parallel setup.
3. **One state language.** Availability is `available · busy · focus · away`;
   work is `queued · running · blocked · completed · failed · cancelled`;
   governance is `allowed · waiting · denied`. Color always accompanies text
   or an icon.
4. **Seeing and acting stay adjacent.** A live Activity offers `Steer session`
   only when a matching live session exists; otherwise it honestly offers
   `View agent`. A waiting approval offers Review; a Nearby service offers its
   relevant Air action. No user should copy an address between screens.
5. **Trust stays visible.** Every surface shows the verified/acting identity.
   Presence is labeled as discovery metadata; actual actions still pass through
   the destination's policy. Relay attribution is never presented as direct
   cryptographic proof.
6. **Calm under change.** Heartbeats do not animate or redraw unchanged UI.
   Polling preserves focus. Empty, stale, denied, loading, and partial states
   explain what is known without turning normal absence into an alarm.

## Information architecture

| Area | User question | Objects and actions |
|---|---|---|
| **Home** | What matters now? | Continue Activity, needs attention, quick actions, live sessions, recent events |
| **Nearby** | Who is here and what can they receive? | Presence, identity, availability, services, capability hints |
| **Activities** | What is running, blocked, or finished? | Activities, sessions, tasks, workflows, artifacts, steer |
| **Share** | What can I move between agents/devices? | Send, Drop, Ring, Cast, Screen, Vision, content references |
| **Security** | What needs a human or proof? | Approvals, policy decisions, receipts, audit integrity, identity details |

Desktop uses a persistent left rail. Mobile uses the same five destinations in
a safe-area-aware bottom navigation. Deep operational tools—Catalog, Control
Room, raw audit tables, policy editors, and local shell—remain available through
progressive disclosure and an explicit operator/developer mode.

## Shared object model

The interface should compose a few stable objects rather than inventing a new
shape per page:

| Object | Primary label | Secondary detail | Safe actions |
|---|---|---|---|
| `Identity` | Friendly name | FQDN, verified key on demand | inspect, select |
| `Presence` | Agent/device + availability | advertised services | open service, share |
| `Activity` | Human work title + state | actor, progress, context reference | continue, inspect, steer |
| `Approval` | Requested action | actor, target, exact bounded context, expiry | review, approve, deny |
| `Receipt` | What happened | identity, decision, time, proof | inspect, verify, export |
| `Artifact` | File/image/result name | type, hash, provenance | preview, send, fetch |

Stable IDs and the same JSON must survive web, terminal, and MCP rendering. A
surface may hide technical detail, but it must not rename the underlying state
or fabricate a capability.

## Design system

### Tokens

| Role | Light | Dark | Use |
|---|---:|---:|---|
| Canvas | `#F6F8FC` | `#090B10` | application background |
| Surface | `#FFFFFF` | `#151820` | focused content |
| Raised surface | `rgba(255,255,255,.78)` | `rgba(28,31,40,.82)` | navigation/material only |
| Primary text | `#111827` | `#F7F8FC` | titles and actions |
| Secondary text | `#647084` | `#A5ADBD` | metadata |
| Separator | `rgba(72,86,110,.16)` | `rgba(171,183,205,.18)` | open lists and boundaries |
| Accent | `#1265F5` | `#4B8CFF` | selected state and primary action |
| Available/allowed | `#159B62` | `#36C987` | positive verified state |
| Waiting/blocked | `#E86F16` | `#FF9C54` | attention without danger |
| Denied/failed | `#D63C48` | `#FF6672` | destructive or failed state |

- System sans stack for interface copy; mono only for addresses, hashes, IDs,
  and code.
- 4/8px spacing rhythm; 18–24px primary radii; 12–14px controls and compact
  rows; hairline borders; shadows only for elevation.
- One signature motif: a faint orbit/connection line between a continuing
  Activity and the agents capable of receiving it. It never conveys authority.
- Motion is 150–320ms and communicates selection, arrival, or state change.
  `prefers-reduced-motion` disables nonessential transforms and pulses.

### Core components

- `AppShell`: sidebar on desktop, bottom navigation on mobile, acting identity,
  verified connection state.
- `ContinueActivity`: strongest current Activity, progress, actor, next action.
- `NearbyRail`: horizontally browsable Presence cards; connected peers without
  a Presence announcement remain visible as fallback cards, without duplicating
  peers that do have a verified card.
- `AttentionRow`: a single held/blocked summary with direct review path.
- `QuickActions`: Send, Drop, Steer, and Browse tools; each enables only when
  its corresponding relay, live session, or catalog surface is connected.
- `SessionList` and `ActivityTimeline`: open lists with thin separators, not a
  nested card grid.
- `ActionSheet`: exact target and action, state-specific fields, result as an
  `aria-live` region.
- `IdentityDetail`: friendly facts first; full key, address, protocol, and
  provenance on demand.

## Responsive and accessibility contract

- Primary controls are at least 44×44 CSS pixels; layouts work at 320px width
  and 200% zoom without horizontal page overflow.
- Every icon-only control has an accessible name. Decorative identity art is
  hidden from assistive technology.
- Keyboard order follows visual order. `:focus-visible` has a high-contrast
  two-pixel ring and is never removed.
- Polling must not move focus or rebuild a list when its material signature is
  unchanged. Status/toast results use polite live regions; destructive failures
  use assertive announcements sparingly.
- Tables get scroll containers or semantic list alternatives on small screens.
- Empty states distinguish unavailable, unauthorized, unconfigured, and truly
  empty. A `403` never renders as “zero”.

## Whole-product migration

| Phase | Outcome | Surfaces |
|---|---|---|
| **1 · Agent OS spine** | Unified Air Home shell + responsive nav; Presence/Activity drive Continue and Nearby. | `air-live.html`, `air home`, `air_nearby` |
| **2 · Governance** | Approvals uses the same tokens/components while retaining direct browser-to-approver identity. | `approvals.go`, Security area |
| **3 · Observation** | Dashboard and Control Room become Activity/Operator views in the shared shell; raw shell stays explicit developer mode. | `dash.go`, `room.go` |
| **4 · Logical actions** | Select a verified agent/service everywhere; raw `host:port` remains an advanced compatible input. | Share, Steer, Ring, Cast, CLI |
| **5 · Continuity** | Context Capsule details and a real prepare/accept/commit Handoff flow. | Activities, Home action sheet |
| **6 · Native shells** | The same objects, states, and navigation map to iOS/macOS/Android without redefining behavior. | `mobile/`, native apps |

## New experience features

- **Focus policy:** a node in `focus` can advertise which attention classes it
  accepts; Ring and notifications explain suppression rather than disappearing.
- **Universal command palette:** search agents, Activities, services, and safe
  actions by name; results resolve through the same Presence directory.
- **Activity deep links:** a stable Activity reference opens the same object in
  web/CLI/assistant and never embeds a bearer credential.
- **Spaces:** user-owned groups collect selected nodes and Activities; group
  membership does not grant tool authority, and fan-out remains individually
  policy-checked/audited.
- **Continuity confidence:** before Handoff, show capsule freshness, target
  compatibility, missing adapters, policy drift, and what will remain at the
  source. Never present “Continue” as a silent identity transfer.
