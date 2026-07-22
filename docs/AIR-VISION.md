# Air — the vision beyond discovery and drop

Air today is the AirDrop-native face of meshmcp: **discover** (peers · whoami · catalog ·
map), **drop / push / fetch** payloads, **steer** and **launch** live work, **approve** a
held call — all between cryptographic identities on a dark mesh, firewalled and provable.

This document thinks past that surface to six capabilities — **browse, stream, vision, bind,
computer-use, phone-use** — and grounds each in the primitives meshmcp *already* has, so
they read as a roadmap, not a wish list. The through-line is meshmcp's one fact: **the same
WireGuard key that authorizes a tool call also stamps a shared file, a pushed frame, a
co-sign** — so "who saw / streamed / browsed / did what, and who approved it" is
cryptographic by construction, across every one of these.

Each section marks what is **buildable now** on shipped primitives vs. what is **external**
(needs a device or toolchain this repo can't exercise).

---

## Air · Browse — *a Finder for the mesh*  ·  **buildable now**

Discovery gives lists; browse gives navigation. `air browse <backend>` explores what a
backend actually offers — its tools, resources, and prompts — over the mesh, filtered to
your identity. Walk it further: `whoami → map → browse a backend → inspect a tool's schema`,
a guided descent from "who am I" to "what exactly can I call, and with what arguments."

- **Primitives:** `mcpclient.ListTools/ListResources/ListPrompts` (MCP `*/list`), the ARD
  catalog (what backends exist), the per-caller ACL (you browse only what you may call).
- **The meshmcp angle:** nothing is exposed — every list is per-identity filtered at the
  gateway, and browsing is itself a governed, auditable mesh action.
- **Shipped as the first step of this doc:** `air browse` (see `airbrowse.go`).
- **Next:** an interactive TUI that descends peers → gateways → catalogs → backends → tools
  → schema without retyping addresses.

## Air · Stream — *watch the mesh happen, live*  ·  **buildable now**

The other views are snapshots; a stream is the mesh in motion. `air stream` tails Air
activity — steers, drops, catalog reads, policy decisions — and renders it live, colour-coded,
as it lands. It is the terminal-native counterpart to the served Receipts page.

- **Shipped as the second step of this doc:** `air stream <audit.jsonl>` follows the ledger
  live, colour-coded by decision, rotation-aware (`airstream.go`).
- **Primitives:** the hash-chained audit ledger (already tailed by `tailAuditRecords` and the
  Receipts view), the governed pub/sub event bus (`cmd/bus`, F28), the style layer.
- **Deeper:** subscribe to a *governed* event stream by identity — an agent receives only the
  events its labels permit (reactive agents without a broker to expose), and the stream
  survives a network roam because it rides the resumable `session/` channel.
- **The meshmcp angle:** subscription is a capability; every delivery is attributable; a
  stream is deny-by-default like every other surface.

## Air · Vision — *seeing over the mesh*  ·  **buildable now**

Air already moves bytes; Vision is about moving and viewing **visual context** — a
screenshot, an image, a live frame — with the same identity, ACL, and receipt as a file drop.

- **Shipped as the third step of this doc:** a drop inbox is a directory of files that landed
  by cryptographic identity, each audited by content hash. `air serve --gallery <inbox>` grows
  a **Vision** section on the phone-first page that renders those images inline — a phone *sees*
  what a laptop dropped, served path-safely and gated by the viewer ACL. `air vision <inbox>` is
  the terminal inventory of the same (`airvision.go`, `airserve.go`, `site/air-live.html`).
- **Deeper:** a governed **screen-share** primitive — frames pushed over the resumable session
  channel, viewed on a peer's page, ACL'd and audited frame-by-frame; a roam mid-share
  resumes. The transport (`session/`) already carries ordered, resumable byte regions.
- **As a governed tool:** an agent "sees" a dropped image through a vision-model MCP backend —
  which is just another governed tool call: rate-limited, tainted, audited. A screen it reads
  taints the session, so a later egress is blocked (F7/F18).
- **External:** live camera/screen capture on a device is the device's job; Air governs the
  *transport and the seeing*, not the pixels' origin.

## Air · Bind — *a programmable reaction layer*  ·  **buildable now**

Stream *watches*; Bind *reacts*. [rebind](https://docs.rebind.gg/) is a programmable input
layer — it intercepts an event and runs a script in response. `air bind` is the same idea
turned onto the mesh: it watches the one universal event source meshmcp already produces — the
hash-chained audit ledger — and fires a declared reaction when a record matches. A denial pages
you; a drop landing nudges an on-call agent; a co-sign hold escalates.

- **Shipped as the fourth step of this doc:** `air bind <bindings.yaml> --audit <ledger>` matches
  each audit record against glob triggers (decision · backend · method · tool · peer · reason) and
  fires a `print` (notify) or `run` (a governed child action) reaction, templated with the record's
  fields (`airbind.go`, `examples/air-bindings.yaml`). Built by composing the two primitives it
  needs: the `followAudit` tailer under `air stream`, and the governed child-spawn under `air launch`.
- **The meshmcp angle — the whole point:** the trigger is an *already-governed, already-audited*
  action, and a reaction that *acts* is itself a governed mesh action that re-enters the firewall,
  deny-by-default. So a `run` reaction is refused unless you pass `--allow-exec` — a bindings file
  can never silently execute. rebind scripts arbitrary Luau on your keystrokes; Air scripts
  *governed* reactions on your mesh, and every link in the chain is provable after the fact.
- **Deeper:** trigger on other governed event sources (the pub/sub bus, a catalog change, a
  schedule), and let a reaction be a full `air workflow` rather than a single child — a declarative
  "when X, run this governed flow" that stays deny-by-default and audited end to end.

## Air · Computer-use — *govern the agent's hands*  ·  **pattern buildable now**

meshmcp's firewall governs every MCP tool call. Computer-use is screen/keyboard/mouse exposed
*as* MCP tools — so putting a computer-use backend behind a meshmcp gateway makes **every click,
keystroke, and screenshot a governed, audited, optionally co-signed tool call**. A jailbroken
agent cannot run `delete_everything` or type into a bank form without a policy verdict.

- **Buildable now (a pattern, not new gateway code):** run an OS-control MCP server as a
  meshmcp backend with a policy — `allow` the safe verbs, `require_cosign` the destructive
  ones, `deny` the rest; `taint` a session that reads a sensitive screen so a later exfil is
  blocked. Ships as an `examples/computer-use.yaml` and a how-to.
- **The meshmcp angle:** the firewall reaches *inside* the computer-use loop — the agent may
  see your screen but cannot act without a verdict, and every action is provable after the
  fact. Co-sign a destructive click from your phone (the existing approvals flow).
- **External:** the OS-control MCP server itself (a third-party backend); meshmcp governs it,
  it doesn't ship it.

## Air · Phone-use — *the phone as a governed identity and actuator*  ·  **partly external**

The phone is already the richest Air surface in the design (`docs/MOBILE.md`): a hardware-backed
WireGuard identity with the key in the Secure Enclave / StrongBox, the human the firewall waits
for on a co-sign. Phone-use extends it two ways.

- **The phone as a face — buildable now:** the served page *is* the phone-first surface —
  approve, drop, push, steer, discover (whoami/map/catalog) from any phone on the mesh, no
  install. Biometric gates the *action* (Face ID before Approve), not the tunnel.
- **The phone as an actuator — the milestone:** the phone's camera, location, notifications,
  and biometric exposed as **governed MCP tools** over the mesh. An agent asks "take a photo"
  or "where are you"; the phone prompts (Face ID), returns the result, and the call is audited
  like any other — deny-by-default, rate-limited, co-signable. Losing the device loses an
  *actuator*, not a credential (secrets stay server-side, `docs/SECRETS.md`).
- **External:** the native shell — `gomobile bind ./mobile` → an iOS `.xcframework` / Android
  `.aar`, then a thin app (the binding surface `Join`/`Dial`/`Call`/`Approvals` already exists,
  `mobile/`). Needs the mobile toolchain + a device.

---

## The unifying invariant

Every one of these is the same shape: **a new kind of payload or action, carried between
cryptographic identities on a dark mesh, gated by the same firewall and written into the same
tamper-evident ledger.** Seeing, streaming, browsing, a click, a photo — each resolves to a
WireGuard key that proves who, a policy that decides may, and a hash-chained record that proves
it happened. Air's moat is not any one verb; it is that *all of them share one identity and one
proof*.

Build order: **browse**, **stream**, **vision**, and **bind** (shipped — CLIs, the served page's
Vision gallery, and a governed reaction layer) → a resumable frame stream on top of vision →
**computer-use** (an example + policy pattern) → the **phone actuator** (once the native binding is
built). Discovery was the first leg; this is the rest of the walk.
