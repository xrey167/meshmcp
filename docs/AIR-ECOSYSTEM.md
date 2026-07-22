# Air Ecosystem

> **North star:** any agent, any device, one continuous activity — private by
> default, governed at every action, and independently provable afterward.

Air already has the useful verbs: discover, drop, push, fetch, ring, cast,
screen, steer, approve, launch, automate, inspect, and replay. The ecosystem is
the layer that makes those verbs feel like one product instead of a toolbox.
It gives each nearby agent or device a verified identity card, lets work appear
as a stable Activity, resolves friendly recipients to the service they actually
offer, and moves a bounded, explicitly accepted context capsule between runtimes
without weakening session identity. Transactional checkpoint migration remains a
separate future protocol.

## Product model

| Primitive | What the user experiences | Security boundary |
|---|---|---|
| **Presence** | Agents and devices appear automatically with availability and supported actions. | The gateway stamps the transport-proven public key, FQDN, and observed IP. An announcement cannot claim them. |
| **Activity** | One privacy-safe card says what is running, blocked, or waiting for the user. | A card contains description and content references, never credentials, raw prompts, or executable action parameters. |
| **Resolver** | “Send to analyst” replaces `100.x.y.z:9120`. | Resolution selects an advertised address; the real action still re-enters the receiver's ACL and policy. Presence is never authorization. |
| **Air Node** | One always-on runtime represents a device or agent and hosts its enabled Air services. | One mesh identity, explicit service allowlists, bounded listeners, and one audit story. |
| **Context Capsule** | Work can be prepared for application-level continuation elsewhere. | Mesh-encrypted transport, content-addressed and size-bounded references, exact target binding, short expiry, and no secrets or bearer authority. |
| **Handoff v1** | The destination receives an inert offer, explicitly accepts it, and selects a governed continuation tool. | Both network hops pin exact keys; application ACKs, atomic dispatch claims, replay tombstones, and bounded attempt receipts make uncertainty explicit. It does not move a live session. |
| **Transactional Handoff v2** | A future checkpoint-capable runtime prepares, readies, and commits a true move. | Requires single-use grants, policy binding, lease fencing, compatible checkpoint adapters, and split-brain recovery tests. |
| **Spaces** | A named group of agents/devices shares selected activities and automations. | Membership is separate from tool authorization; every fanned-out action is individually policy-checked and audited. |

## Shipped: Nearby v1 and Handoff v1

Nearby is the connective foundation:

1. A node sends a short-lived `air.presence/v1` announcement to the Air control
   endpoint.
2. The control endpoint ignores any claimed network identity and stamps the
   card with the public key/FQDN resolved from the WireGuard connection plus the
   observed source IP.
3. Only service **ports** are announced. Addresses are reconstructed from the
   observed IP, so a card cannot redirect a caller to an arbitrary host.
4. A bounded in-memory registry keeps one card per public key. Heartbeats extend
   the TTL; a graceful node removes its card; a crashed node disappears on
   expiry.
5. `air nearby`, Air Home, the served page, and the assistant's `air_nearby`
   tool consume the same cards. A selector can resolve an exact name, FQDN, or
   full public key to a requested service.

An optional Activity on the card is deliberately read-only metadata: stable ID,
kind, title, short summary, state, progress, typed target, revision, update time,
and an optional content-addressed context reference. It does not embed a command
or bypass the existing `air steer`, `air task-steer`, or approval paths.

## Shipped in this slice: Universal Actions

Air Home now turns the Presence directory into one coherent action surface:

- `Command/Ctrl-K`, the Actions shortcut, and every Nearby card open the same
  searchable Universal Actions model.
- A node sheet shows only actions backed by its currently advertised services.
  Send and Drop require `inbox`; Ring requires `ring`; Steer requires a live
  session associated through a transport-stamped FQDN, public key, or IP.
  Client-authored Presence names and Activity targets never select a session.
- Browser Send, Drop, and Ring carry a logical full-public-key recipient. The
  relay performs a fresh, browser-attributed `/v1/presence` read immediately
  before the action, selects the required service with `ResolvePresence`, and
  fails closed on ambiguity, expiry, missing services, or control failure.
- `push`, `drop`, `air ring`, `air cast`, and the sending side of `air screen`
  accept the same logical selector with `--control <gateway>`. A syntactically
  valid raw `host:port` remains an explicit compatibility path.
- Discovery still grants nothing: the resolved destination independently
  applies its mesh ACL, policy, rate limits, and audit controls.

### Trust rules

- A public key is kept in full internally and shortened only while rendering.
- On-behalf browser headers may attribute a **read**, but may never register or
  remove Presence. Only the directly connected mesh identity owns its card.
- Presence TTL, card size, strings, labels, services, capabilities, and registry
  cardinality are bounded.
- An advertised capability is a hint for user experience, not a grant. The
  receiver remains deny-by-default.
- Heartbeat-only refreshes do not flood the enforcement ledger; material card
  changes, leaves, reads, malformed writes, and denied attempts are auditable.

Handoff v1 is intentionally an application-continuation protocol. `air handoff
offer` sends a target-bound capsule to a deny-by-default receiver, which stores it
inertly. A local operator accepts or declines it; `air handoff continue` then
claims delivery atomically and invokes a receiver-selected governed tool through
an exact-key-pinned agent connection. It never rebinds a session owner or carries
credentials, capabilities, or hidden model state.

## Why Handoff is not live migration

The existing `session` layer is Continuity for transport failure: it persists
the server-side endpoint and rehydrates it for the **same** `CreatorKey`. The
client's model conversation, tool-loop state, receive/send cursors, and local
memory are not a transferable checkpoint. Rebinding `CreatorKey` or copying a
session file would turn an intentional identity boundary into an account-
takeover primitive and could duplicate side effects during a split brain.

A future transactional or live-migration Handoff requires a stronger protocol:

```mermaid
sequenceDiagram
  participant S as Source
  participant C as Control plane
  participant D as Destination
  S->>C: Prepare capsule + target-bound grant
  C->>D: Offer (metadata only)
  D->>C: Accept and import capsule
  D->>C: Ready (checkpoint + policy verified)
  C->>S: Commit
  S->>C: Source stopped; lease released
```

The commit consumes the grant exactly once with a fencing generation. Expiry,
rejection, destination failure, or policy drift aborts and leaves the source
authoritative. This is the next Continuity phase after compatible Activity/checkpoint
export contracts exist; it is not required for v1's explicit application continuation.

## Build sequence

| Phase | Deliverable | Depends on |
|---|---|---|
| **1 · Nearby** | Presence registry, Activity cards, resolver, CLI/Home/web/MCP views. | Existing Air control endpoint and mesh identity. |
| **2 · Air Node** | One command/config starts selected inbox, ring, cast, screen, approvals, and steer services; publishes them automatically. | Nearby service contracts. |
| **3 · Universal addressing** | **Core shipped:** Push, Drop, Ring, Cast, and Screen accept `name`, `fqdn`, or full `pubkey` plus the required service kind; raw `host:port` remains compatible. | Nearby resolver. |
| **4 · Context Capsule v1** | Shipped bounded work summary, content references, exact-target seal, explicit accept/decline, governed continuation, and durable delivery receipts. | Existing Air Handoff CLI, mesh identity, and destination tool policy. |
| **5 · Transactional Handoff v2** | Prepare → accept → ready → commit/abort, checkpoint adapters, single-use grants, fencing, recovery tests, and a Home action sheet. | Context Capsule v1, durable Activity identity, and runtime checkpoint support. |
| **6 · Spaces** | User-owned agent/device groups, shared Activity board, individually governed fan-out, focus/notification policy. | Nearby, Activities, and the pub/sub event fabric. |

## Success criteria

- A new agent appears everywhere after one announcement and disappears after a
  crash without manual cleanup.
- A user can resolve `analyst` to its `steer` service without copying an IP or
  port, while a backend ACL still independently denies an unauthorized call.
- A malicious card cannot spoof identity, advertise a different host, inject a
  terminal escape, exhaust the registry, or smuggle executable parameters.
- The same Presence and Activity JSON is rendered by terminal, web, and MCP
  surfaces.
- Handoff v1 is described as explicit application continuation, while transactional
  checkpoint migration remains unavailable until its adapters, grants, fencing, and
  two-phase recovery tests ship; transport failover is never mislabeled as either.
