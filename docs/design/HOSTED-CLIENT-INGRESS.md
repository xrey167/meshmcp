# Hosted-client ingress without the edge's public-listener burden

> **Status:** Design proposal (not yet built). Produced by a multi-agent design
> exploration — six independent approaches, adversarially verified across three
> lenses (security/trust-core, Apple-feel/operator-burden, feasibility/protocol/
> self-host). This doc records the recommendation. Where a claim is grounded in
> shipping code it cites the file.

## The problem

meshmcp's promise is **"every MCP server runs on a private WireGuard mesh — zero
open ports — it just works."** [`meshmcp edge`](../EDGE.md) is the one deliberate
exception, and it breaks that promise for the operator who runs it. To serve a
hosted MCP client that cannot join the mesh — most concretely a **claude.ai custom
connector**, which runs on Anthropic's servers and reaches an MCP server over
public HTTPS with OAuth — the operator must **open a public inbound port**, **own a
public DNS name**, and **obtain and rotate a publicly-trusted TLS cert** (ACME via
certmagic, or hand-managed cert files). That is precisely the yak-shaving the rest
of the product removes. The edge re-establishes the trust core correctly; it just
does so behind a door the operator has to build, expose, and defend.

The goal of this design: let a hosted client reach a mesh tool **without any of
that operator burden**, while keeping the trust core exactly where it is today.

## The invariants any design must keep

These are non-negotiable — they are what makes the edge safe today, and no ingress
redesign may weaken them. Every candidate below is judged against this checklist:

1. **Identity is minted by the gateway, never asserted by the caller.** A hosted
   client is a single synthetic identity `oauth:<client_id>`, derived by the
   gateway from a gateway-issued, revocable bearer — the caller never supplies its
   own identity string.
2. **The capability double-gate runs on the operator's gateway.** Every
   `tools/call` passes the capability gate *then* the deny-by-default policy gate,
   in that order — see `edge/mcp.go:165` `enforceToolCall`: `s.verify.Verify(...)`
   (capability, `mcp.go:170`) precedes `s.engine.DecideToolCallBound(...)` (policy,
   `mcp.go:175`).
3. **The Ed25519 capability signing key never leaves the gateway.** Capabilities
   are minted at token issuance (`edge/token.go:177` `mintTokenSet`) and
   re-verified from the signed grant on every call, so a tampered token record
   cannot widen authority.
4. **The audit ledger is fail-closed and gateway-only.** An unrecorded allow is
   denied (`edge/mcp.go:179-181`); the hash chain lives on the gateway and no
   intermediary can write, reorder, or rewrite it.
5. **The mesh stays sealed.** The gateway reaches the one tool-scoped backend by
   dialing *out* over WireGuard with inbound blocked (`cmd/meshmcp/edge.go:94`
   `client.Dial`, `BlockInbound=true`); the ingress path never gains a route into
   the mesh, the control plane, or any other backend.

## The six approaches, compared

The connector places five hard requirements on whatever it connects to (stable
public HTTPS URL · publicly-trusted cert · `401` discovery · Dynamic Client
Registration with **no** initial token · PKCE · MCP Streamable HTTP). The
publicly-trusted cert is the load-bearing constraint: **someone in the path must
hold a real cert for a real public name**, so the entire design space is "who holds
that name, and what can they see?"

| # | Approach | Who holds the public cert | What the intermediary can see | Operator burden | Self-host | Score / verdict |
|---|----------|---------------------------|-------------------------------|-----------------|-----------|-----------------|
| 1 | **Broker-terminating beacon** ⭐ | Beacon (wildcard cert) | **Plaintext in flight** (relay/replay only; no keys) | One command, **0 inbound ports, 0 DNS, 0 cert** | Yes (small component) | **7.0 — recommended** |
| 2 | **Beacon, TLS-passthrough** | Beacon issues cert, key shipped to gateway; **gateway** terminates inner TLS | **Ciphertext** vs. a *passive* beacon (active name-holder can still MITM) | Same one command | Yes | 6.0 — hardened variant of #1 |
| 3 | Adopt existing tunnel (Cloudflare / Tailscale / ngrok) | The tunnel provider | Provider-dependent (usually plaintext) | One daemon + a third-party account | Provider-bound | *not verified (session limit)* |
| 4 | Reverse-publish over NetBird's own relay infra | Unclear — relays aren't HTTPS-terminating | n/a | Zero new infra (reuse mesh relays) | Yes | *not verified* |
| 5 | Bring-your-own endpoint + token-exchange (RFC 8693) | The operator's **existing** public infra | The operator's own proxy | Zero *new* meshmcp infra, but needs pre-existing public infra | Yes (if you already have infra) | *not verified* |
| 6 | Wildcard-subdomain SaaS beacon (Tailscale-Funnel style) | meshmcp-operated beacon | Nothing, if combined with #2 | The maximal "one command" experience | Escape hatch only | *(is #1/#2 operated as a service)* |

Approaches 3–5 were designed but not adversarially verified before the run hit its
session limit; they are folded in below as grafts and follow-ups, not dismissed.
Approach 3 in particular deserves the completeness check called out at the end — it
may be the lowest-effort **MVP** even if the beacon is the better end-state.

## Recommendation — "meshmcp Beacon"

Build a **beacon**: a lightweight public relay that a gateway reaches by dialing
**out**, so the operator never opens an inbound port. The beacon owns the public
name and cert; the gateway keeps the entire trust core.

### The move

Split the connector's requirements at the one seam that matters:

- **On the beacon** go the three things that cause operator burden: the stable
  public name, the publicly-trusted cert, and the inbound port.
- **On the gateway** stays everything that *mints or verifies authority*: the
  Ed25519 signing key, the deny-by-default policy engine, and the fail-closed audit
  ledger — i.e. the **unchanged `edge` package**.

This works because the connector contract is a property of *the URL and the HTTP
conversation* (satisfy it at the beacon), while the trust core is a property of
*who holds the signing key and the ledger* (keep it on the gateway).

### Wire flow

```
  claude.ai                          beacon (public)                 operator gateway (0 inbound)
  ─────────                          ───────────────                 ───────────────────────────
  TLS to                             holds *.beacon.meshmcp.io        dials OUT ─────────────┐
  g-ID.beacon.meshmcp.io  ──TLS──►   cert; maps subdomain g-ID  ◄═════ persistent reverse    │
                                     to this gateway's tunnel         tunnel (mTLS/Noise,     │
                                     │                                yamux; 1 stream/req)    │
                                     │  forwards raw HTTP request ═════════════════════►      │
                                     │                                each stream = net.Conn  │
                                     │                                served by the UNCHANGED  │
                                     │                                edge.Server.Handler()    │
                                     │                                (server.go:210):         │
                                     │                                  401 discovery          │
                                     │                                  /register DCR (pending)│
                                     │                                  /authorize + consent   │
                                     │                                  /token → Ed25519 cap   │
                                     │                                  /mcp double-gate+audit  │
                                     ◄══ response bytes ══════════════════════════════════════┘
                                                                       then dial the tool over
                                                                       WireGuard (edge.go:94,
                                                                       BlockInbound=true)
```

Net footprint on the operator: **one outbound tunnel + one outbound mesh dial.
Nothing listens.** The gateway serves each tunnelled stream through the existing
`edge.Server.Handler()` `ServeMux` as plain HTTP (TLS already handled upstream) —
the only wiring change is where the listener comes from, not what the handler does.

### The honest crux: who sees plaintext

Because the connector demands a publicly-trusted cert and the beacon presents it,
there are two postures, and we are explicit about the trade:

**Posture A — Broker-terminating (default, simplest, top-scored).** The beacon
terminates the public TLS and therefore **sees plaintext in flight**: bearer
tokens, tool names, tool-call arguments and results. What it *cannot* do is the
part that matters: it holds no signing key (cannot mint or widen a capability), no
policy ruleset (the engine is deny-by-default), and no ledger (cannot forge or
rewrite audit). A malicious beacon can, at worst, **relay or replay** in-flight
bytes within a token's ≤1h lifetime — and **every** such request still lands on the
gateway's capability gate → policy gate → fail-closed audit, recorded under
`oauth:<client_id>`. Net new trust versus today's edge: **exactly one
confidentiality-trusted party** (the beacon operator), where today there are zero.

**Posture B — TLS-passthrough (hardened variant).** The beacon ACME-issues a
per-subdomain cert, ships the key down the tunnel, and does pure SNI/TCP
forwarding, so the **gateway** terminates the inner TLS and the beacon sees only
**ciphertext**. This defeats a *passive* beacon — but a beacon that controls the
public name can always issue *its own* cert and actively MITM, so passthrough is
**defense-in-depth, not a hard trust boundary.** Ship A first; offer B for
operators who want to raise the cost of a passive compromise.

### Why it beats today's edge on Apple-feel

| | today's `edge --config` | `edge --beacon` |
|---|---|---|
| Inbound ports | 1 public | **0** |
| Public DNS the operator owns | required | **none** |
| TLS cert to obtain/rotate | required (ACME/files) | **none** (beacon's) |
| Listener to harden | yes | **no** |
| Operator steps | port + DNS + cert + config | **one command** |
| Trust core | on the gateway | **byte-identical, on the gateway** |

## Grafts from the runners-up

- **Self-host escape hatch (from #5, token-exchange-BYO).** The beacon must be a
  small, self-hostable binary — an operator with existing public infra runs their
  own beacon, or points claude.ai at any public endpoint they already run and has
  it hand the gateway a verifiable identity assertion (RFC 8693 token-exchange).
  This removes any *hard* dependency on a meshmcp-operated service.
- **MVP via existing tunnels (from #3).** Before building the beacon, an
  `edge --tunnel` mode that binds `edge.Server.Handler()` to loopback behind
  Cloudflare Tunnel / Tailscale Funnel / ngrok delivers the zero-inbound-port win
  *today* with almost no new code — at the cost of a third-party account and that
  provider's plaintext visibility. Good first rung; the beacon is the branded,
  self-hostable end-state.
- **Reuse the mesh's own transport (from #4).** The gateway↔beacon tunnel should
  reuse the embedded NetBird/WireGuard outbound-dial machinery already in the
  binary rather than inventing a new transport, and certmagic (already in the
  module graph) for the beacon's wildcard cert.

## Coexistence with today's edge

This is a **new mode of `meshmcp edge`, not a replacement.**

- `meshmcp edge --config edge.yaml` — own your public listener — stays exactly as
  documented for operators who want to control their own endpoint.
- `meshmcp edge --beacon` — the zero-inbound path — is added alongside it.
- The trust core (`edge/mcp.go`, `edge/token.go`, capability + policy + audit) is
  **byte-identical** in both modes; only the listener seam differs
  (`edge.Server.Run` public listener vs. a tunnel `net.Listener`).
- Operators who run neither are **completely unaffected** — the beacon adds no
  default-on surface, consistent with the edge's off-by-default posture.

## Build sketch

**New components**
- `beacon/` (or a `meshmcp beacon` subcommand): the public relay — wildcard-cert
  TLS front (certmagic), a subdomain→tunnel registry, and the accept side of the
  reverse tunnel. Small; policy-blind by construction.
- A reverse-tunnel transport shared by gateway and beacon (mTLS/Noise + yamux),
  reusing the embedded WireGuard outbound-dial primitives.
- `edge --beacon`: dial the beacon, register the gateway's subdomain, expose each
  tunnelled stream to the **existing** `edge.Server.Handler()`.

**Reused unchanged:** the entire `edge/` trust core (`Handler`, `authenticate`,
`enforceToolCall`, `mintTokenSet`), the capability verifier, the policy engine, the
fail-closed audit ledger, and the WireGuard backend dial.

**Phasing**
1. **MVP:** `edge --tunnel` (loopback bind behind an existing tunnel provider) —
   proves the zero-inbound-port UX and the "`Handler()` over a non-public listener"
   seam with near-zero new code.
2. **Beacon v1 (Posture A):** self-hostable broker-terminating beacon + reverse
   tunnel; `edge --beacon <url>`; one-command onboarding.
3. **Hardened (Posture B):** TLS-passthrough so a passive beacon sees only
   ciphertext.
4. **Optional SaaS beacon:** a meshmcp-operated beacon with per-gateway subdomains
   and abuse/rate-limit/tenant-isolation — with the self-host binary as the escape
   hatch.

## Residual risks & unexplored alternatives

- **New trusted party.** Posture A adds one confidentiality-trusted party; both
  postures add a party that *controls the public name* and can therefore actively
  MITM within a token lifetime. This is a genuine reduction from today's
  "operator-owned listener, zero third parties" — accepted deliberately in exchange
  for the Apple-feel win, and bounded by the gateway-side double-gate + fail-closed
  audit (the beacon can never mint authority or hide what it relayed).
- **A meshmcp-operated beacon is a hosted dependency** and a new public namespace
  to run (abuse, rate-limiting, tenant isolation, availability). The self-host
  binary must land in the same release, not later, or the "just works" story has a
  hole.
- **Replay within a token lifetime** is the beacon's real capability in Posture A.
  Mitigations to design in: short token TTL (already ≤1h), per-request nonce/DPoP
  binding through the existing DPoP verifier seam (`docs/EDGE.md` §"Shared DPoP
  replay store"), and idempotency on mutating tool calls.
- **Verification gap.** Approaches 3–5 (adopt-tunnel, netbird-relay,
  token-exchange-BYO) were generated but **not** adversarially verified before the
  design run hit its session limit. The recommendation stands on the two verified
  designs, but the completeness check is: **re-run the verification and confirm the
  beacon still wins — especially against `adopt-tunnel` on effort as the MVP.**
- **Unexplored:** a pure client-side option (a claude.ai-side connector that speaks
  WireGuard) is out of scope — it would require Anthropic to change the connector,
  which the whole premise rules out.

## See also

- [EDGE.md](../EDGE.md) — the current public-listener ingress this proposal
  removes the burden of.
- [spec/OAUTH-STANDARDS.md](../spec/OAUTH-STANDARDS.md) — the recorded exposure-model
  decision and deviations D-A…D-D that any new ingress must respect.
- `edge/mcp.go` (`enforceToolCall`), `edge/token.go` (`mintTokenSet`),
  `edge/server.go` (`Handler`, `Run`) — the trust core a beacon must keep intact.
