# Air Ecosystem

> **North star:** any agent, any device, one continuous activity — private by
> default, governed at every action, and independently provable afterward.

Air already has the useful verbs: init, up, join, pair, discover, send, drop,
push, fetch, ring, cast, screen, steer, approve, launch, query databases,
automate, inspect, and replay. The ecosystem is
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
| **Transactional Handoff v2** | **First slice shipped:** a checkpoint-capable (or stateless) runtime prepares, readies, and commits a true LIVE ownership move between two gateways; the source serves until one fenced commit CAS, aborts cleanly at every pre-commit step, and crash-recovers to exactly one owner. | The single-writer guarantee is the same generation-fenced `TakeoverLease` CAS; the destination is authorized by a CONSUMED single-use grant (`air move grant`), never an arbitrary peer; `MigrateHandshake`/`MigrateBackend` only; proven by a `-count=20` crash matrix + store conformance (`MemStore` + PostgreSQL). The move is now **operator-triggerable** — `POST /v1/move` (gated on the same operator/control ACL as `/v1/steer`) and a Control Room drag-to-handoff gesture; the destination opts in per-backend with `move_port` + `move_grant_store`. Client redirection and a Home action sheet are the next steps. |
| **Spaces** | A named group of agents/devices shares selected activities and automations. | Membership is separate from tool authorization; every fanned-out action is individually policy-checked and audited. |

## Shipped: Nearby v1, Resolved Send v1, and Handoff v1

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
6. The normal Send/Drop path submits the selected node's full, stamped public
   key—not an address copied from the page—and resolves its current `inbox`
   service again immediately before delivery.
7. The CLI (`air send`), served page, and MCP app (`air_send`) share that
   selector vocabulary. Legacy `host:port` inputs remain explicit compatibility
   paths for operators and scripts.
8. Delivery still enters the existing receiver and its sender ACL/policy. A
   successful discovery or resolution is not an authorization decision.
9. Every **resolved** surface returns the same bounded Action Result only after
   receiver installation is confirmed. Its per-payload
   receipts contain identity, destination, payload name/size, status, and time—
   never the payload itself, a local source path, a secret, or a capability
   token. A payload is at most 8 MiB; a mixed send is at most 64 MiB and 256
   payloads. Explicit raw-target endpoints retain their legacy response shapes;
   they do not return this envelope.
10. A compatible inbox advertises `drop.complete.v1`, for example
    `--service inbox=9110,drop.complete.v1`. The sender terminates the framed
    delivery with a nonce-bound marker; the receiver returns a bounded
    `meshmcp.drop-completion/v1` status plus installed payload/byte totals.
    `delivered` is emitted only for `installed` with the same nonce and exact
    totals. Missing, malformed, rejected, or uncertain completion is an error.
11. Mixed versions remain explicit: resolved clients refuse an inbox without
    the completion capability, current receivers accept legacy EOF senders, and
    operators may still choose a raw `host:port` compatibility route.

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

### What Air Node deliberately does not host

Two services stay out of `air node` by decision, not omission:

- **Approvals.** The co-sign approver serves the *gateway's* pending-approval
  store: the gateway parks a held call in its cosign store and the approver
  resolves entries in that same store. Hosting the approver inside a remote
  `air node` would either split that state (approvals resolved on a device the
  gateway cannot see) or require replicating the pending store across hosts —
  both weaken the one-place, auditable approval story. The supported shape
  stays: `meshmcp approvals` runs gateway-colocated where the store lives, and
  any device (including a node) reaches it over the mesh as an approver
  *client* — the phone taps, the gateway's store records.
- **Steer.** A steer inbox belongs to the runtime that executes the steer. A
  node hosting a steer port would accept envelopes on behalf of some other
  local process and forward them — inserting a hop that makes "who received
  this steer" ambiguous. An agent that wants to be steerable embeds the
  presence client and its own inbox (the `agent` command shows the shape); the
  node's card then advertises the agent's own service, not a proxy.

### Trust rules

- A public key is kept in full internally and shortened only while rendering.
- ACL-filtered session and Home responses include the session owner's full
  **public** peer key solely so clients can bind a Nearby card to the right live
  session. The standard UI does not render that stable identifier.
- A Nearby card may expose Steer only when exactly one live session carries the
  same transport-stamped public key; a card-authored name or session ID is not
  sufficient.
- On-behalf browser headers may attribute a **read**, but may never register or
  remove Presence. Only the directly connected mesh identity owns its card.
- Presence TTL, card size, strings, labels, services, capabilities, and registry
  cardinality are bounded.
- Resolver selectors are limited to 512 valid UTF-8 bytes, reject C0/C1/DEL
  controls before matching, and are never reflected in resolver errors.
- An advertised capability is a hint for user experience, not a grant. The
  receiver's ACL and policy remain authoritative; configure its `allow` list
  when the Inbox must be restricted to selected identities.
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
| **2 · Air Node** | **First slice shipped:** `air node --inbox-port <p> --inbox-dir <d> --inbox-allow <acl>` hosts the drop/push inbox (with `drop.complete.v1`) on the node's own identity and announces it automatically — the listener is up before the card advertises it, and the sender ACL is required (deny-by-default). `--ring-port` likewise hosts the rate-limited ring receiver, and `--screen-port`/`--cast-port` host the bounded per-sender frame receivers (each with its required `-allow` ACL and, for frame services, a `-dir`). Approvals and steer hosting are **deliberately not hosted** — see "What Air Node deliberately does not host" below. | Nearby service contracts. |
| **3 · Universal addressing** | **Shipped:** Push, Drop, Ring, Cast, and Screen accept `name`, `fqdn`, or full `pubkey` plus the required service kind; `air steer --to <node>` binds to the single live session carrying the node's transport-stamped public key (zero or several matches fail closed); raw `host:port` remains compatible. Resolved Send across web, CLI, and assistant surfaces additionally requires `drop.complete.v1` and returns one receiver-confirmed Action Result. | Nearby resolver + session `peer_key`. |
| **4 · Context Capsule + Handoff v1** | Shipped bounded work summary, content references, exact-target seal, explicit accept/decline, governed continuation, and durable delivery receipts. | Existing Air Handoff CLI, mesh identity, and destination tool policy. |
| **5 · Transactional Handoff v2** | **First slice shipped:** prepare → ready → commit/abort LIVE session-ownership move (`session.Server.MoveSessionTo` / `ServeMoveControl`), single-use destination grants (`air move grant`), generation fencing, and the full crash-recovery matrix (`-count=20`) + `storetest.RunSessionLiveMove` conformance. **Control-plane wiring shipped:** `POST /v1/move` trigger (operator/control-ACL gated, audited), a per-backend `move_port`/`move_grant_store` destination listener, and a Control Room drag-to-handoff gesture. Remaining: operator-driven client redirection, checkpoint adapters beyond the two supported classes, and a Home action sheet. | Context Capsule v1, durable Activity identity, and runtime checkpoint support. |
| **6 · Spaces** | **First slice shipped:** operator-defined `groups:` rosters resolve to present members server-side (`GET /v1/groups`, control-gated + audited), and `air steer --to group:<name>` / `air ring … group:<name>` fan out as one existing single-target call per member — every delivery independently re-enters the destination's own ACL/policy (one audited decision per member) and the per-member truth returns as `air.fanout-result/v1` with no aggregate verdict; unknown/empty groups fail loudly before any delivery. The shared Activity board and focus/notification policy are **not** built. | Nearby, Activities, and the pub/sub event fabric. |

## Success criteria

- A new agent appears everywhere after one announcement and disappears after a
  crash without manual cleanup.
- A user can send to `analyst` without copying an IP or port, while the inbox
  ACL still independently denies an unauthorized delivery.
- A malicious card cannot spoof identity, advertise a different host, inject a
  terminal escape, exhaust the registry, or smuggle executable parameters.
- The same Presence and Activity JSON is rendered by terminal, web, and MCP
  surfaces.
- Handoff v1 is described as explicit application continuation, while transactional
  checkpoint migration remains unavailable until its adapters, grants, fencing, and
  two-phase recovery tests ship; transport failover is never mislabeled as either.
