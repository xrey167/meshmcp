# meshmcp — vision & roadmap

## What this actually is

Three off-the-shelf ideas, composed into something that doesn't exist yet:

- **Embedded userspace WireGuard** (from caddy-netbird's pattern) — an app becomes a
  mesh peer in-process, no TUN device, no open ports, no admin rights.
- **A Mars-STN-style resumable session** — a logical stream that survives the physical
  connection dropping, with exactly-once replay.
- **An MCP-aware policy enforcement point** — the gateway parses JSON-RPC and authorizes
  individual tool calls by cryptographic identity.

Put together, meshmcp is **a private, identity-native fabric for AI tool traffic**. Every
MCP server becomes a dark service reachable only by authorized mesh peers; every tool call
is attributable to a WireGuard public key; every session survives roaming. None of the
three source projects set out to build this, and no MCP gateway today has all three
properties at once.

## The layers we have (all proven)

| Layer | Property | Proof |
|---|---|---|
| Transport | Zero-exposure, NAT-proof, E2E-encrypted | Live: 2 peers on api.netbird.io, MCP round-trip |
| Identity | Every caller = a WireGuard pubkey (`IdentityForIP`) | Live: audit record carries `peer_key` |
| Continuity | Sessions survive reconnect, exactly-once, bounded buffer | `-race` tests: 300/300 across 7 drops; live MCP |
| HA / migration | Session survives a gateway crash (shared durable store + lease) | `-race` test: gw1 crash → gw2 rehydrates |
| Authorization | Per-tool + per-method ACLs by identity, denied inline | Live: `echo` denied for a peer, others pass |
| Accountability | Structured per-call audit + full both-directions trace | Live: JSONL deny record; trace with payloads |
| Aggregation | One endpoint = namespaced union; LB, failover, discovery, bidirectional MCP | `-race` tests + live router routing/failover |
| Payload + Steer (Air) | AirDrop files, push, fetch; **steer** a live agent/session/task; launch/workflow | `-race` tests: `tasks/steer`, line-safe session steer, agent inbox; see [AIR.md](AIR.md) |
| Discover + See (Air) | **browse** a backend's tools/resources/prompts; **stream** the ledger live; **bind** a governed reaction to it; **vision** — inventory & serve image drops | Shipped: `air browse / stream / bind / vision` (+ `serve --gallery`); the browse→stream→bind→vision arc, with computer-use/phone-use ahead, is in [AIR-VISION.md](AIR-VISION.md) |

## Where it goes — grounded

Phases 1–3 (gateway, resumable sessions, policy+audit) and much of the HA / tool-mesh
track (session migration, replica failover, discovery registry, bidirectional MCP — see
[HA-TOOLMESH.md](HA-TOOLMESH.md)) are **built and tested**. Wave 2 has since delivered most
of the phases below — **Phase 4 (F21), Phase 5 (F29), and Phase 7 (F15) shipped**; Phase 6
(federation) is the main remaining control-plane track. Each phase is annotated inline.

**Phase 4 — capability tokens.** Today authz is peer-identity → tool. Next: short-lived,
signed capability grants ("this agent may call `read_*` on `kg-memory` until 15:00"), issued
by a control plane and verified at the gateway. Turns the mesh into an agent-scoped
capability system, not just a network.
> **Shipped (Wave 2):** signed capability grants gained a revocation lifecycle — a
> mesh-distributed revocation store plus `capability issue / revoke / list` (**F21**).

**Phase 5 — rate & cost governance.** The gateway already sees every tool call. Add
per-identity quotas, token-bucket rate limits, and (for LLM-backed tools) cost accounting.
A denied-by-budget response is the same inline-error mechanism as a policy deny.
> **Shipped (Wave 2):** per-identity cost & budget governance — `meshmcp budget` (**F29**).

**Phase 6 — federation.** Multiple NetBird networks (orgs) peering selected backends across
a trust boundary, with policy at the seam. An agent in org A calls a vetted tool in org B,
every call audited on both sides, nothing else reachable. B2B tool-sharing with no public
surface.
> **Status:** partially shipped — the governed plugin marketplace (**F14**, `meshmcp market`)
> and the federation boundary (`federation/`, now with a wired DCR/token-exchange edge) ship;
> SSO-mapped federation (**F31**) has shipped its **first slice**: a verified OIDC token
> presented over an already-authenticated mesh connection attributes its `groups` claim to the
> caller's WireGuard key, feeding `group:<name>` policy — additive attribution over the
> transport root, never a replacement for it (see [SSO.md](SSO.md)). Static pinned issuer keys,
> no JWKS fetch; a forged/expired/wrong-audience token maps to nothing (deny).

**Phase 7 — observability plane.** `meshmcp status` → live sessions, peers, per-tool call
rates; the audit stream shipped to any sink (OTel, a SIEM). "Who called what, from where,
when" becomes queryable for an entire agent fleet.
> **Shipped (Wave 2):** `meshmcp status` (live sessions, peers, per-tool call rates) plus a
> webhook audit sink (**F15**); a Prometheus `/metrics` endpoint ships via `metrics_listen`
> (**S41** — metadata-only labels from the shared ledger); the OTel/OTLP exporter on the same
> `AuditSink` seam has also shipped — `audit_otlp` exports audit records to any OTLP/HTTP
> logs collector (dependency-free OTLP JSON; batched, non-blocking, metadata-only).

> These phases are developed, sized, and mapped to concrete seams in
> **[ROADMAP-HARDENING.md](ROADMAP-HARDENING.md)** (Wave 2), most of them now **shipped**:
> Phase 4 → **F21 ✓** (capability revocation lifecycle), Phase 5 → **F29 ✓** (cost & budget
> governance), Phase 7 → **F15 ✓** (observability plane — `status` + webhook sink); Phase 6 →
> **F14 ✓** (plugin marketplace — `meshmcp market`) shipped and **F31** (SSO-mapped
> federation) shipped its **first slice** — OIDC group attribution over the transport root
> (see [SSO.md](SSO.md)); cross-org SSO mapping at the federation seam is the remaining work.
> Wave 2 also
> shipped the compile-time **plugin platform** (F13), HTTP-backend policy parity (F16),
> group-based policy (F17), identity-bound sessions (F23), the mesh vault / scheduler / event
> bus (F26–F28), an attestation pack (F32), client-hook adapters (F33), and most of the
> hardening sweep — flagships F13–F33 (F30 still open; F25 and F31 first slices shipped) + minors S11–S60.
>
> **F25 (multi-tenant control plane) — first slice shipped.** The control plane
> partitions its own state (policy, registry, enrollment, audit) into tenants
> keyed on the transport-proven WireGuard key, resolved inside the one
> authorization chokepoint and never named by a request — cross-tenant access is
> absent by construction, with per-tenant RBAC (no cross-tenant super-role) and
> one tamper-evident audit chain per tenant. A single-tenant deployment is
> byte-identical to before. Honest v1 boundary: enrollment shares one NetBird
> PAT/account (per-tenant groups + audit attribution, not account isolation), and
> the anchor witness stays shared. See
> **[MULTI-TENANT.md](MULTI-TENANT.md)** and THREAT-MODEL adversary 14.
>
> **F31 (SSO/OIDC mapping) — first slice shipped.** A verified OIDC token maps to
> additive `group:<name>` attribution over the transport-authenticated mesh key
> (never a replacement), presented on the gateway control endpoint and verified
> against statically pinned issuer keys in fail-closed order. See
> **[SSO.md](SSO.md)** and THREAT-MODEL adversary 15.

## Where it goes — wilder (still grounded in the primitives)

- **Self-hosted push for agents.** The embedded peer holds a persistent E2E channel; a
  control plane can push a task to any agent/device by mesh identity — no Firebase, no
  polling, works through CGNAT. The resumable session already is this channel.
- **Edge/field agent fleets.** Kiosks, LTE routers, on-prem boxes behind CGNAT each become
  directly addressable, policy-governed peers. Firmware, telemetry, and tool calls ride one
  resilient channel that survives the network flapping.
- **A "tool exchange."** Because identity + authz + audit are built in, a marketplace of
  MCP tools where access is a capability grant and every invocation is metered and
  attributable — a substrate for paid, governed agent tools.
- **Compute mesh.** The same embedded-peer + resumable-session pattern generalizes past
  MCP: any custom protocol server (a model shard, a vector store, a render worker) can join
  as a dark, identity-native, roaming-resilient peer. MCP is the first payload, not the
  ceiling.

## Design invariants (don't break these)

1. **No open ports, ever.** Backends listen only on the mesh interface.
2. **Identity is cryptographic, never claimed.** Authz keys off the WireGuard pubkey the
   transport proves, not headers the caller sends. Gateway-stamped headers are stripped
   from input first.
3. **Deny is the safe default.** Policies are allowlists; the absence of a rule denies.
4. **Audit is a control, not best-effort.** A configured audit sink that can't open is a
   hard startup error.
5. **Pure transport where possible.** The gateway speaks MCP only to *authorize* — it never
   rewrites tool semantics. Any MCP server works unmodified.

## Honest limitations

- Policy applies to **stdio** backends (newline-delimited JSON-RPC) in full, and to
  Streamable-HTTP/remote backends for per-tool authorization + audit + rate/window/co-sign
  (F16, request-body parsing) **plus** taint labels (per `Mcp-Session-Id`, keyed with the
  transport-proven peer key; a label-bearing policy denies session-less `tools/call`
  rather than silently skipping), secret injection with per-peer response redaction
  (JSON and SSE — an unscannable compressed/oversized response is refused, never
  forwarded), and capability upgrades (the token is stripped before the backend).
  Honest residuals: labels attach at decision time (same as stdio); redaction is
  best-effort (same threat model as stdio); a fresh session id starts label-clean
  (≈ a stdio reconnect) and idle label state expires after 24h. DLP, shadow policies,
  and router delegation remain stdio-only and are refused in config for HTTP/remote.
- Policy matches FQDN, pubkey, and **`group:<name>`** rules (F17); groups are resolved from
  config (`groups:`, a static `GroupResolver`) **and**, when SSO is configured (F31 v1), from a
  verified OIDC token's `groups` claim attributed to the caller's WireGuard key — the two are
  OR-composed behind the engine's single resolver slot (see [SSO.md](SSO.md)). SSO groups are
  additive attribution over the transport root, bounded by the token's lifetime; a forged or
  expired token attributes nothing. Dynamic NetBird group membership still isn't available
  through the embed API — a management-API-backed resolver is a drop-in for the same interface
  but isn't wired yet.
- The gateway binary is heavy (~44 MB, NetBird's dep tree) — a daemon, not something to
  embed in a tiny CLI. Clients that only `connect` could use a thinner build later.
- One live roam (physically moving networks mid-session) is proven only by loopback drop +
  live round-trip separately, not yet as a single physical-roam test.
