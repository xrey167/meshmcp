# meshmcp on phones — feasibility, architecture & path

Can the whole thing — mesh identity, policy, audit, MCP — reach a phone? Yes. And
the phone turns out to be one of the *best* fits for the model, because a phone is
exactly what the firewall keeps asking for: **a human identity on the mesh**.

The killer use case — approving a held `require_cosign` call from your phone —
**already works today** over the mesh (see §2). The rest of this note is the
deeper design: the layers, the two architectures, the on-device SDK, the push
seam, the security model, the constraints, and the path.

---

## 0 · The three layers to get onto a device

meshmcp is a stack; putting it on a phone is a question per layer.

| Layer | On a phone | Status |
|---|---|---|
| **1 · Connectivity** (WireGuard / NetBird) | iOS `NetworkExtension` (Packet Tunnel Provider) · Android `VpnService` | **Exists** — NetBird ships iOS + Android clients; WireGuard on mobile is mature. |
| **2 · Session + identity + client** (`session/`, `mcpclient/`, `client/embed`) | pure Go → a mobile framework via `gomobile bind` | **Buildable** — the code is pure Go; NetBird itself binds Go for its mobile clients. |
| **3 · The app** (approver UI / agent / monitor) | native, Flutter, or a web page served over the mesh | **Partly done** — the approver web app ships now; a native SDK is the next milestone. |

The key realization: **a phone joining the mesh gets its own WireGuard key → its
own cryptographic identity → policy and audit already distinguish it.** To
meshmcp, a phone is just another identity — an agent app held by a human. Nothing
in the gateway, policy, or audit has to change.

---

## 1 · Two architectures

### A. Phone as a mesh peer running a thin client (near-term, realistic)

The phone joins the mesh and *calls* the gateway; policy, secrets, and audit all
stay server-side. Nothing sensitive lives on the phone — it holds a reference,
not a secret, exactly like every other agent.

```
 phone (mesh peer · own WireGuard identity)
   │  WireGuard tunnel (NetBird app, or embedded)
   ▼
 meshmcp gateway ──▶ MCP servers
   policy · audit · secrets (server-side)
```

Two ways to get connectivity:

1. **Use the NetBird app** for the tunnel — the phone is a mesh peer at the OS
   level — and a plain app (or even mobile Safari/Chrome) talks to a
   meshmcp service over the mesh. *Zero Go embedding on-device.* This is how the
   approver already works.
2. **Embed** connectivity + client via `gomobile` (§3) so the app gets identity +
   **resumable sessions** without a separate VPN app — sessions that survive the
   phone hopping Wi-Fi ↔ cellular, which is precisely what `session/` was built
   for.

### B. Phone as a backend (serves tools from the device)

The phone *exposes* tools — camera, location, secure-enclave signing, on-device
models — as an MCP server reachable only over the mesh (no open port). Powerful,
but bounded by mobile background rules (§5): model it as **push-woken
request/response**, not a long-lived listener. Best treated as a later step.

---

## 2 · The killer use case works today: co-sign from your phone

The firewall's `require_cosign` holds a privileged call until a **human identity
on the mesh** approves it. meshmcp now makes that an actual inbox:

- When a `require_cosign` call is held, the gateway **records a pending request**
  in the cosign directory (`policy.FilePending` — peer, tool, backend, rpc id, time).
- `meshmcp approvals --store <cosign-dir>` serves an **approver over the mesh**:
  a phone-first web page plus `GET /v1/pending`, `POST /v1/approve`, `POST /v1/deny`.
- Because it's served on the mesh, **the approver is the caller's WireGuard
  identity** — your phone. Approving writes an identity-attributed grant
  (`approver: <your-phone-fqdn>`); the held call then proceeds and the whole thing
  is in the tamper-evident audit.

```
 agent → transfer_funds ──held──▶ gateway: OutcomeCosign
                                    │  records Pending{peer,tool,…}
   phone (mesh peer) ── opens ──▶  meshmcp approvals  (mesh port, no public port)
        │  GET /v1/pending → "billing.mesh wants transfer_funds"
        │  [Face ID]  POST /v1/approve {peer,tool}
        ▼
   gateway: Grant(peer,tool, approver=<phone fqdn>)  → next call allowed
                                    │  audit: cosign granted by <phone fqdn>
```

**Try it now** (no native app needed — a phone on the mesh opens it in a browser):

```bash
# on the gateway host, or any mesh peer sharing the cosign dir:
meshmcp approvals --store ./demo/cosign          # serves on a mesh port
# from the phone (joined via the NetBird app): open http://<gateway-mesh-ip>:9700
```

This reuses `approve` / `cosign_store` / the audit verbatim — the phone is just
the identity that signs the approval.

**What's still missing for a *great* UX: push.** Today the page polls. To have the
phone *buzz* when an approval is waiting, the gateway must notify APNs/FCM — see
§4. Everything else is done.

---

## 3 · The on-device SDK (`gomobile`)

For architecture A.2 and B, bind meshmcp's Go into a mobile framework. `gomobile
bind` produces an iOS `.xcframework` and an Android `.aar` from a Go package with
a gomobile-friendly surface (exported types, no channels/maps across the
boundary, simple params + callbacks). NetBird's own mobile clients prove this for
the connectivity half.

The surface a `mobile/` binding package would export (thin wrappers over existing
code):

```go
package mobile // gomobile bind target

// Connectivity (wraps client/embed).
type Mesh struct{ /* *embed.Client */ }
func Join(setupKey, mgmtURL, configPath string) (*Mesh, error) // embed.New + Start
func (m *Mesh) Identity() string                               // this device's mesh FQDN
func (m *Mesh) Close() error

// A resumable MCP client to one backend (wraps session.NewClient + mcpclient).
type Conn struct{ /* … */ }
func (m *Mesh) Dial(target string) (*Conn, error)              // over the mesh, --resumable
func (c *Conn) Call(tool, argsJSON string) (string, error)     // mcpclient.CallTool
func (c *Conn) Close() error

// Approver helpers (wrap the /v1 API or call it directly).
type Approvals struct{ /* … */ }
func (m *Mesh) Approvals(gateway string) *Approvals
func (a *Approvals) Pending() (string, error)                  // JSON
func (a *Approvals) Approve(peer, tool string) error
func (a *Approvals) Deny(peer, tool string) error
```

Everything under the hood already exists (`embed`, `session`, `mcpclient`,
`policy.FilePending`); the binding is a flat, JSON-in/JSON-out wrapper so the
gomobile boundary stays simple. The one design rule: keep the exported API
**string/error/callback only** — no Go maps, slices of structs, or channels
crossing into Swift/Kotlin.

---

## 4 · The push seam (the one missing piece)

For the phone to be woken instead of polling, the gateway needs to send a push
when a pending appears. This is a small, well-bounded addition:

1. **Device registration.** A mesh service `POST /v1/devices` — a phone
   registers its APNs/FCM token *and* is identified by its WireGuard key (so only
   real mesh peers can register, and you know which human owns which token).
2. **Notify on pending.** Give `policy.FilePending.Record` (or the approvals
   service watching the dir) a `Notifier` hook: on a new pending, look up the
   approver device(s) and send a push ("billing.mesh wants transfer_funds").
   APNs/FCM delivery is an HTTP call to Apple/Google — no inbound port, fits the
   mesh model.
3. **Wake → approve.** The push opens the approver (deep link), Face ID gates the
   `POST /v1/approve`, done.

This keeps the gateway push-*out* only (it never accepts inbound from Apple/Google),
consistent with the zero-open-ports invariant. It's the natural next PR.

---

## 5 · Security model of the phone-as-approver

- **The key lives in the secure element.** The phone's WireGuard private key sits
  in the Secure Enclave (iOS) / StrongBox-backed Keystore (Android). It never
  leaves the device; the mesh identity is as strong as the hardware.
- **Biometric gate before the action, not the tunnel.** The tunnel can stay up;
  require Face ID / fingerprint immediately before issuing `POST /v1/approve`, so
  a stolen unlocked phone still can't approve without the biometric.
- **Non-repudiable approvals.** The grant records `approver = <phone mesh FQDN>`,
  and the resulting allowed call is in the hash-chained (optionally signed) audit.
  "Who approved this $500 transfer, and when" has a cryptographic answer.
- **The phone never holds a secret.** It approves a *reference* to an action; the
  credential injection still happens server-side (see SECRETS.md). Losing the
  phone loses an approver, not a credential.
- **Revocation is instant.** Remove the phone's key from NetBird and it is off the
  mesh — it can no longer see or approve anything.

Threat notes: protect `/v1/approve` behind the biometric; rate-limit and audit
denials; consider requiring the approver identity to be in an allow-list of human
identities (a policy rule on the approvals service itself), so a *compromised
agent* peer can't approve its own calls.

---

## 6 · Constraints (and how they shape the design)

- **iOS background execution.** `NetworkExtension` keeps the *tunnel* alive, but
  app-level long-running loops are limited. Design the phone as **event-driven**
  (push-woken approvals, foreground monitoring) — never a perpetual traffic
  generator. A phone-as-backend must be push-woken and answer fast.
- **Android.** A foreground service (persistent notification) can keep an agent or
  backend running; `VpnService` provides the tunnel. More permissive than iOS,
  still battery-sensitive.
- **Battery & radios.** Sessions are ack-based and resumable — prefer
  low-frequency, batched calls and let the session layer ride out network changes
  rather than reconnecting.
- **App Store / Play review.** A VPN/NetworkExtension entitlement is routine for a
  mesh client; be explicit in the privacy disclosure that traffic stays on the
  user's private mesh. Embedding your own WireGuard is allowed.
- **userspace vs OS WireGuard.** The server uses userspace WireGuard (no admin).
  On a phone, prefer the OS tunnel (NetworkExtension/VpnService) for battery and
  correctness; the embedded userspace stack is the fallback when the entitlement
  isn't available.

---

## 7 · Recommended path (updated to what exists)

1. **Now — approver + monitor, no native app.** A phone on the mesh (NetBird app)
   opens `meshmcp approvals` and the `room` (both responsive) in the browser.
   Co-sign from your pocket, watch the fabric — **shipping today**, zero new code.
2. **Next — push + a wrapper app.** Add the device-registration + APNs/FCM notify
   seam (§4), and a thin native/Flutter shell that registers for push, deep-links
   into the approver, and gates approval behind Face ID.
3. **Then — the `gomobile` client SDK (§3).** Bind `embed` + `session` +
   `mcpclient` so apps get mesh identity and roaming-proof sessions without the
   separate VPN app. This is the real "meshmcp on mobile" milestone.
4. **Later — phone as a backend.** Expose on-device capabilities (camera,
   location, secure-enclave signing) as an MCP server reachable only over the
   mesh, push-woken, request/response.

## Why it fits

Everything that makes meshmcp work on a server works *better* with a phone in the
mesh: the phone has a real, unforgeable, hardware-backed identity; it's the human
the co-sign flow was designed to reach; it never needs to hold a secret; and the
resumable session layer was built for exactly the network churn a phone lives in.
The gateway, policy, and audit don't change — the phone is just one more identity
on the dark network.

## Reference points

- `approvals.go` / `policy/pending.go` — the pending registry + phone-first approver (ships now).
- `approve` + `cosign_store` — the human-in-the-loop primitive the phone plugs into.
- `session/` — resumable, migratable sessions designed for roaming networks.
- NetBird mobile clients (iOS / Android) — the connectivity layer already exists.
- `gomobile` (`golang.org/x/mobile`) — binds the Go client/session into a mobile framework.
