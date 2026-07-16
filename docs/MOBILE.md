# meshmcp on phones — feasibility & path

Can the whole thing — mesh identity, policy, audit, MCP — reach a phone? Yes,
and the phone turns out to be one of the *best* fits for the model, because a
phone is exactly what the firewall keeps asking for: **a human identity on the
mesh**. This note lays out the layers, what already exists, the realistic
architectures, the constraints, and a recommended path.

## The three layers to get onto a device

meshmcp is a stack; putting it on a phone is a question per layer.

| Layer | On a phone | Status |
|---|---|---|
| **1 · Connectivity** (WireGuard / NetBird) | iOS `NetworkExtension` (Packet Tunnel) · Android `VpnService` | **Exists** — NetBird ships iOS + Android clients; WireGuard on mobile is mature. |
| **2 · Session + identity + client** (`session/`, `mcpclient/`, `embed`) | Go, compiled to a mobile framework via `gomobile`, or spoken over the OS tunnel | **Buildable** — the code is pure Go; NetBird itself uses `gomobile`. |
| **3 · The app** (MCP client / agent / approver UI) | native, Flutter, or React Native | **New work** — a thin app on top of layer 2. |

The key realization: **a phone joining the mesh gets its own WireGuard key → its
own cryptographic identity → policy and audit already distinguish it.** A phone
is, to meshmcp, just another identity — an agent app that happens to be held by a
human.

## Two architectures

### A. Phone as a mesh peer running a thin client (near-term, realistic)

The phone joins the mesh and *calls* tools on a server-side gateway; the gateway,
policy, secrets, and audit all stay where they are. Nothing sensitive lives on
the phone — it holds a reference, not a secret, exactly like every other agent.

```
 phone (mesh peer, own identity)
   │  WireGuard tunnel (NetBird app or embedded)
   ▼
 meshmcp gateway  ──▶  MCP servers
   policy · audit · secrets (all server-side)
```

Two ways to get connectivity on the phone:

1. **Use the NetBird app** for the tunnel (the phone is a mesh peer at the OS
   level), and a normal app speaks MCP over the mesh TCP address to the gateway.
   *Zero Go embedding on-device* — simplest to ship.
2. **Embed** NetBird + meshmcp's client via `gomobile` into an SDK, so the app
   gets identity + resumable sessions without a separate VPN app. More work, but
   self-contained and gives the `session/` resumability (survives the phone
   roaming between Wi-Fi and cellular — which is exactly what that layer is for).

### B. Phone as a backend (serves tools from the device)

The phone *exposes* tools — camera, location, notifications, on-device models —
as an MCP server reachable over the mesh. Powerful ("your phone is a tool your
agents can call, with no open port"), but constrained by mobile background-execution
rules (see below). Best treated as a later step, and as request/response woken by
a push rather than a long-lived listener.

## The killer near-term use case: co-sign from your phone

The firewall already has `require_cosign` — a privileged call is held until a
**human identity on the mesh** approves it. A phone is the natural approver:

```
 agent → transfer_funds   ──held──▶  gateway (cosign pending)
                                        │  push
                                        ▼
                               your phone: "Approve $500 transfer?"  [Face ID]
                                        │  meshmcp approve  (over the mesh)
                                        ▼
                               gateway routes the held call
```

This needs only architecture **A** plus a small app: receive a push, show the
pending action, and on approval issue `meshmcp approve` over the mesh (the phone's
own identity is the approver, cryptographically). It reuses the existing co-sign
store and `approve` command verbatim. A **mobile Control Room** (the `room` view,
responsive) is the companion: watch the fabric from your pocket.

## Constraints (and how they shape the design)

- **iOS background execution.** The `NetworkExtension` keeps the *tunnel* alive,
  but app-level long-running agents are limited. Design the phone as
  **event-driven** (push-woken approvals, foreground monitoring), not a
  perpetual traffic generator. A phone-as-backend must be woken by a push and
  answer quickly.
- **Android.** A foreground service (with a persistent notification) can keep an
  agent or backend running; `VpnService` provides the tunnel. More permissive
  than iOS, still battery-sensitive.
- **Battery & radios.** meshmcp sessions are already ack-based and resumable;
  favor low-frequency, batched calls and let the session layer ride out network
  changes rather than reconnecting.
- **App Store review.** A VPN/NetworkExtension entitlement is reviewable but
  routine for a mesh client. Embedding your own WireGuard is fine; be clear in
  the privacy disclosure that traffic stays on the user's private mesh.
- **userspace vs OS WireGuard.** The server uses userspace WireGuard (no admin).
  On a phone you'll typically use the OS tunnel (NetworkExtension/VpnService) for
  battery and correctness; the embedded userspace stack is the fallback when you
  can't get the entitlement.

## Recommended path

1. **Now — approver + monitor app (architecture A, NetBird app for transport).**
   A thin Flutter/native app: push-triggered co-sign approvals (Face ID → `approve`
   over the mesh) and a responsive Control Room. Highest value, least new code,
   reuses `approve` / `room` / the co-sign store as-is.
2. **Next — a `gomobile` client SDK.** Bind `mcpclient` + `session` (resumable) +
   `embed` into an iOS framework / Android AAR, so apps get mesh identity and
   roaming-proof sessions without a separate VPN app. This is the real "meshmcp
   on mobile" milestone; NetBird's own mobile clients prove the `gomobile`
   approach for the connectivity half.
3. **Later — phone as a backend.** Expose on-device capabilities (camera,
   location, secure enclave signing) as an MCP server reachable only over the
   mesh, woken by push. Careful background handling; treat as request/response.

## Why it fits

Everything that makes meshmcp work on a server works *better* with a phone in the
mesh: the phone has a real, unforgeable identity; it's the human the co-sign flow
was designed to reach; it never needs to hold a secret; and the resumable session
layer was built for exactly the network churn a phone lives in. The gateway,
policy, and audit don't change — the phone is just one more identity on the dark
network.

## Reference points

- NetBird mobile clients (iOS / Android) — the connectivity layer already exists.
- `gomobile` (`golang.org/x/mobile`) — binds the Go client/session into a mobile framework.
- `session/` — resumable, migratable sessions designed for roaming networks.
- `approve` + `cosign_store` — the human-in-the-loop primitive a phone plugs into.
