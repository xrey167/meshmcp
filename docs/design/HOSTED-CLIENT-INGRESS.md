# Hosted-client ingress without the edge's public-listener burden

> **Status:** Design proposal (not yet built). Produced by a multi-agent design
> exploration — six independent approaches, each adversarially verified across
> three lenses (security/trust-core · Apple-feel/operator-burden ·
> feasibility/protocol/self-host), then synthesized. All 29 agents completed;
> verified average scores are cited inline. Where a claim is grounded in shipping
> code it cites the file; see the "Grounding check" at the end for what was
> verified against the tree.

meshmcp's promise is zero open inbound ports: every MCP server lives on a private WireGuard mesh, identity is proven by the transport, and nothing but the operator's own gateway holds a key. The `edge` breaks that promise in exactly one place. To let a hosted client that cannot join the mesh — most concretely a claude.ai custom connector running on Anthropic's servers — reach a mesh tool, today's edge forces the operator to stand up a second, deliberately public TLS listener: open an inbound port, own and point a public DNS name, obtain and rotate a publicly-trusted cert, and harden the listener. Those are precisely the four burdens meshmcp removes everywhere else, which is why the edge feels like a foreign appliance bolted onto an otherwise "it just works" system. This document picks the one ingress design that keeps the trust core whole while deleting all four operator burdens for the default path.

## The invariants any design must keep

A hosted-client ingress is acceptable only if it preserves meshmcp's trust core **byte-for-byte on the operator's own gateway**. Concretely:

1. **Gateway-minted, non-caller-asserted identity.** The synthetic identity `oauth:<client_id>` is derived on the gateway from a gateway-issued, revocable, unexpired bearer bound to a still-approved client (`edge/mcp.go` `authenticate` → `oauthIdentity`). No intermediary and no client-supplied header may assert identity.
2. **The capability double-gate, in order, on the gateway.** `enforceToolCall` (`edge/mcp.go:165`) re-verifies the Ed25519 `CapabilityClaims` (subject/audience/tool-glob/expiry, fail-closed) via `CapabilityVerifier.Verify` **before** the deny-by-default `policy.Engine.DecideToolCallBound`. The signing key (`mintTokenSet`, `edge/token.go`) never leaves the gateway.
3. **Fail-closed, hash-chained audit on the gateway.** The ledger runs `WithFailClosed(true).WithSync(true)`; an allow that cannot be recorded is denied (`edge/mcp.go:179`); the chain verifies across restart or refuses to append. No intermediary can read, write, reorder, or suppress it.
4. **Deny-by-default, operator-in-the-loop enrollment.** `default_allow:false`, `edge clients approve`, `edge authz approve`, and the revocation cascade stay exactly as today.
5. **Egress unchanged.** The tool is reached OUTBOUND over WireGuard (`client.Dial`, `BlockInbound=true`); the bearer never crosses the mesh.

Integrity of these five is non-negotiable. The axis that genuinely varies between designs is **confidentiality**: what a new in-path party can *see* and whether it can *actively MITM*. That is where the six designs separate.

## The six approaches, compared

| Approach | Who holds the public cert | What the intermediary sees | Operator burden (default path) | Self-host | Avg | Verdict |
|---|---|---|---|---|---|---|
| **Terminating broker** | meshmcp/self broker (wildcard) | **Full plaintext**: bearers, tool args, results; can actively MITM & replay | Zero ports / DNS / cert | Yes, but broker still terminates TLS | **7.0** | Highest score, but a strict confidentiality + active-MITM regression vs today's edge |
| **Passthrough beacon (SNI)** | **Operator's gateway** (per-subdomain LE, DNS-01) | Ciphertext + SNI + traffic metadata only | Zero ports / DNS / cert | Yes; relocates public triad onto the beacon box | **6.3** | Best trust/burden balance; residual = beacon-as-DNS-authority rogue-cert MITM, CT-detectable |
| **Funnel-style beacon** | **Operator's gateway** (per-subdomain LE) | Ciphertext + SNI + metadata only | Zero ports / DNS / cert | Yes; same relocation | **6.3** | Same architecture as above; surfaces the Let's Encrypt rate-limit / Public-Suffix-List engineering detail |
| **Adopt existing tunnel** | Provider (Tailscale = operator's **node**; CF/ngrok = provider edge) | Tailscale: ciphertext+SNI. CF/ngrok: **full plaintext** | Low, but a mandatory third-party account + console setup | No meshmcp dep, but SaaS account required | **6.0** | Magic for operators already on Tailscale; CF/ngrok leak plaintext |
| **BYO-front + RFC 8693** | **Operator's own** front / IdP | The operator's own front (plaintext, but it is the operator's box) | Zero *if* they already run a front; a box otherwise | Fully; no meshmcp dep | **6.0** | Adds no new trust party; Apple-feel only for those who already own public infra |
| **NetBird Expose** | NetBird hosted proxy | **Full plaintext** at NetBird's proxy node | Zero ports / DNS / cert | Relocates onto self-hosted NetBird proxy | **5.3** | Reuses the SaaS tier the mesh already trusts, but plaintext regression + ephemeral-domain disqualifier |

**Terminating broker (7.0).** Operationally flawless — one command, zero of all four burdens — and the integrity core is provably untouched (a keyless broker can neither forge a capability nor corrupt the ledger; a dropped request is never executed, so no unaudited allow occurs). Its killer, from the security lens: because the broker holds the name+cert claude.ai trusts, it terminates TLS, sees every bearer/arg/result in plaintext, and can replay the bearer or actively rewrite the conversation within the ≤1h TTL. That is a new plaintext-and-MITM trust root the current edge simply does not have.

**Passthrough beacon / Funnel-style beacon (6.3, tie).** These are the *same architecture*: an outbound rendezvous that owns the public name and port but does **pure L4 SNI passthrough** — the gateway obtains its **own** per-subdomain Let's Encrypt cert via a beacon-brokered DNS-01 challenge, and the cert private key is generated on and never leaves the gateway. A passive beacon therefore sees only ciphertext + the SNI label it assigned + metadata. The one residual power is that the beacon is DNS authority for a name the operator doesn't own, so a *malicious* beacon could issue a rogue cert and actively MITM — detectable by gateway-side Certificate-Transparency monitoring (tamper-evident, exactly meshmcp's audit philosophy) and escapable by self-hosting. Funnel-style adds the concrete operational note that all `gw-*.beacon` subdomains roll up to one registered domain under Let's Encrypt's rate limit, so the shared beacon domain must go on the Public Suffix List (as Tailscale did for `ts.net`).

**Adopt existing tunnel (6.0).** Rides infrastructure operators already run. Tailscale Funnel is the standout because TLS terminates on the operator's **own** node, so the provider sees only ciphertext — but Funnel is a best-effort/beta streaming path, and Cloudflare/ngrok forfeit confidentiality entirely (plaintext at the provider edge). Its ceiling is the mandatory third-party account and out-of-band console setup that no `meshmcp` command can absorb.

**BYO-front + RFC 8693 (6.0).** The only design that introduces **no new trust party**: the front is the operator's own nginx/CDN/IdP. Genuinely Apple-feel for operators who already run a public front, and fully self-hostable with zero meshmcp dependency. But for the solo operator with no existing front it degrades to "stand up an always-on serverless container that holds a persistent WireGuard tunnel," which is not zero-infra — and the confidentiality-preserving `meshmcp front` sidecar is net-new.

**NetBird Expose (5.3).** Elegant reuse of the exact hosted tier the mesh already trusts, and zero of all four burdens. But HTTPS-mode Expose terminates TLS at NetBird's proxy (full plaintext + replay), and hosted Expose mints **ephemeral, random-suffixed** domains that change on every restart — a direct violation of the connector's stable-URL constraint unless the operator brings a custom domain, which reintroduces the DNS burden.

## Recommendation

**Adopt the passthrough beacon (a merge of the "beacon-passthrough" and "funnel-saas" designs) as the primary hosted-client ingress, shipped as a new second mode of `meshmcp edge`.**

This is deliberately *not* the top raw score. The terminating broker scores 7.0 but its security lens flags a strict, unavoidable regression: it installs a party that sees plaintext and can actively MITM — a downgrade of confidentiality, which *is* part of meshmcp's trust core. The passthrough beacon scores 6.3 but is the highest-scoring design that does **not** regress confidentiality against a passive adversary, and it delivers the full Apple-feel for the default path. Given a choice between "frictionless but a new plaintext trust root" and "frictionless and only ciphertext is exposed," meshmcp's whole pitch demands the latter.

### How it beats the current edge on Apple-feel

The operator runs **one command** and the four burdens vanish:

- **Zero inbound ports.** The gateway makes only outbound dials: one persistent reverse tunnel to the beacon (over the NetBird mesh, `BlockInbound=true`) and one mesh dial to the tool. No public bind anywhere on the operator.
- **No operator-owned DNS.** The stable public name is the beacon's deterministically-derived subdomain, e.g. `gw-<hash(pubkey)>.beacon.meshmcp.net`. It is durable because it is derived from the gateway's key, so it survives restarts — satisfying the connector's stable-URL contract.
- **No operator cert management.** `certmagic` runs ACME **DNS-01** for that subdomain; the challenge TXT is published via the beacon's ACME-DNS-style control API over the tunnel. No inbound challenge port (DNS-01, not HTTP-01/TLS-ALPN), no operator DNS control, no cert files, silent auto-renew.
- **Config shrinks** from today's required `listen` + `public_url` + `tls`/ACME block to a single `beacon:` stanza; `public_url` is learned at runtime from the assigned subdomain and fed to `metadata.go`, so 401→discovery works unchanged.

### How it preserves the double-gate + fail-closed audit

The beacon sits **strictly below the gateway's TLS**. Each spliced byte stream surfaces on the gateway as a `net.Conn` from a tunnel-backed `net.Listener`; the **unchanged** `edge.Server` terminates TLS with the gateway's own cert and runs `Handler()` verbatim (already proven separable — every edge test drives `srv.Handler()` over `httptest`). Because nothing about the ingress touches `authenticate`, `enforceToolCall`, the signing key, the policy engine, or the ledger, all five invariants hold byte-for-byte. The single change inside the `edge/` package is an injected `Options.Listener` in place of the public `net.Listen`; everything downstream is untouched.

### Exactly what the beacon can and cannot see

**Can see:** the cleartext TLS **SNI** (the routing label it assigned), the source IP (Anthropic's egress), TCP timing/byte-counts, tunnel liveness, and — at enrollment — the gateway's beacon-identity pubkey plus opaque ACME challenge TXT tokens.

**Cannot see (passive):** the cert private key, any plaintext HTTP, OAuth bearers/refresh tokens, DCR bodies, authorization codes, PKCE verifiers, MCP JSON-RPC (tool names/arguments/results), WireGuard keys, the mesh backend identity, or the audit ledger. A mis-route fails the TLS handshake (wrong cert) — degrading to DoS, never disclosure.

**Cannot do, ever:** forge or widen a capability, assert an identity, alter a policy decision, or write/suppress the ledger. Even under a *full active rogue-cert MITM*, the beacon can wiretap and replay a live fronted session but **cannot fabricate a governed allow** — every injected call still hits the capability gate + deny-by-default policy + fail-closed audit under `oauth:<client_id>`. The integrity core is unbreakable from the beacon's position; only confidentiality of the fronted leg is at stake, and only against an *active* (CT-detectable) adversary.

The one honest regression vs the current edge: the beacon is DNS authority for a name the operator does not own, placing it in the CA issuance path. This is made **tamper-evident** (gateway-side CT monitoring of its own subdomain alarms on any cert whose key is not its own) and **escapable** (self-host, or CNAME delegation from an owned apex). That is a materially narrower and better-defended trust surface than the terminating broker's unconditional plaintext exposure.

## Grafts from the runners-up

Fold these into the primary rather than shipping them as rival designs:

- **BYO-front / RFC 8693 as a first-class alternate mode (from `token-exchange-byo`).** For operators who already run nginx/CDN/an enterprise IdP, this is *strictly better* than the beacon: no new trust party at all. Ship `meshmcp edge` "behind-front" mode (bind loopback/mesh, disable public TLS, `public_url` = the operator's own name) plus the `meshmcp front` mesh-joined reverse-proxy sidecar, and the `edge/assertion.go` JWKS-verify + RFC 8693 token-exchange for operators whose IdP can issue the initial assertion. Document it as: *"already have a public front? Use it — zero new trust."*
- **Tailscale Funnel as a recognized escape hatch (from `adopt-tunnel`).** For the large population already running Tailscale, `meshmcp edge --tunnel tailscale` binds loopback and supervises `tailscale funnel`; TLS terminates on the operator's **own node**, so confidentiality is preserved with no meshmcp infra and no beacon. Explicitly tier CF/ngrok as a "convenience, reduced-confidentiality" option gated behind a startup plaintext-exposure warning — never the default.
- **DPoP sender-constraining (from `broker-terminating`, `netbird-relay`, and others).** The `DPoPVerifier` seam already exists (`server.go:178`). If/when the claude.ai connector presents DPoP (RFC 9449), enforce it: a bearer captured by an active MITM becomes unreplayable, collapsing the residual beacon risk to read-only disclosure. Wire the plumbing now, enforce when the client supports it.
- **The three-points-on-one-curve framing (from `broker-terminating`).** Present ingress as a single trust curve: `meshmcp edge` (zero third party) → self-hosted beacon (trust-minimizing) → meshmcp-operated beacon (it-just-works default). Same binary, operator's choice.
- **CT-monitoring + CAA account-pinning + a signed subdomain→pubkey transparency log (from `beacon-passthrough`/`funnel-saas`).** Build the CT probe into the gateway (auto-alarm, optional fail-closed stop-serving) rather than shipping it as guidance; have the beacon publish CAA records account-pinned to the gateways' ACME accounts to raise the bar on third-party (non-beacon) rogue issuance.
- **PROXY-protocol-v2 source-IP passthrough (from `beacon-passthrough`).** The beacon prepends the real client IP ahead of the ClientHello so the edge's per-IP rate limiters (`edge/limits.go`, which key on `RemoteAddr`) see real clients, not the tunnel address. Strip it on the gateway before handing bytes to Go's TLS.

## Coexistence with today's edge

This is a **second mode of `meshmcp edge`, not a replacement and not a rewrite.** The `edge/` OAuth+MCP+double-gate+audit brain is already transport-portable — `Handler()` is cleanly separated from `Run()`/the public bind — so the beacon path is a *Run-over-listener* addition, not a fork.

- **Byte-for-byte identical for users who don't opt in:** anyone running `meshmcp edge` with a `listen` + `public_url` + `tls` block keeps the current public-TLS listener with zero behavior change. The `edge` remains the **zero-third-party** option for operators who accept owning a port/DNS/cert in exchange for no in-path party at all.
- **What changes** is entirely additive: a new `beacon:` (or `publish:`) config stanza mutually exclusive with `tls`; a runtime-derived `public_url`; and an injected `net.Listener`. `config.Validate` enforces exactly one of `{public TLS listener, beacon publish, behind-front}`.
- **Identical operator vocabulary:** `edge clients approve`, `edge authz approve`, revocation cascade, `default_allow:false`, the signing key, the audit ledger, and the single tool-scoped backend all carry over unchanged. An operator who understands the edge already understands the beacon.

## Build sketch

**Reused from the binary (no change):** the entire `edge/` package (DCR, PKCE, consent, `mintTokenSet`, the double-gate, the Streamable-HTTP bridge, lifecycle/revocation); `policy.Engine` + `CapabilityVerifier` + `signer`; the fail-closed hash-chained audit ledger; NetBird embedded WireGuard (`client.Dial`/`BlockInbound` for the backend leg **and** for the outbound rendezvous, `client.ListenTCP` on the netstack); NetBird signal+relay for NAT traversal; `certmagic` (`edge/acme.go`, switched from HTTP-01/TLS-ALPN to DNS-01); `pgstore` for the DPoP replay store.

**New components:**

- **`meshmcp beacon`** — a small public binary: (a) authoritative DNS for the beacon zone (`A/AAAA` for `gw-<id>` → self; `TXT` for `_acme-challenge.<id>` from an ACME-DNS-style table gateways populate over the tunnel); (b) a `:443` TCP acceptor that peeks the ClientHello SNI and splices raw bytes into the matching reverse tunnel, prepending PROXY-v2, **decrypting nothing**; (c) a mesh-joined reverse-tunnel rendezvous/mux server that authenticates gateways by WG pubkey / Ed25519 beacon-identity key and binds `subdomain = base32(sha256(pubkey))[:16]` (no land-grab); (d) a subdomain registry with lease/renew/reclaim. Holds **no** per-gateway private key.
- **Gateway-side beacon transport** — a persistent multiplexed reverse tunnel (auto-reconnect with backoff); a `certmagic` DNS-01 solver pointed at the beacon control API (ACME account + cert key stay on the gateway); a tunnel-backed `net.Listener` (with PROXY-v2 parse) feeding `srv.ServeTLS(ln,"","")` with the gateway's own cert. (Multiplexing can use **HTTP/2 over the single tunnel connection with no new dependency** — `golang.org/x/net` is already in the module graph — with `yamux`/`smux`/QUIC as alternatives if per-stream flow control or connection migration is wanted.)
- **`edge.Options.Listener` injection point** — the sole change inside `edge/`.
- **CT-monitoring probe** on the gateway; **config** `beacon:`/`publish:` stanza superseding `listen`/`public_url`/`tls`.

**Phased plan:**

- **Phase 0 — MVP (small; days-to-weeks on the gateway side, reuses everything).** Passthrough beacon with deterministic subdomain, gateway-held DNS-01 cert, single beacon (self-hosted or one meshmcp-run). Goal: a real claude.ai connector completes DCR→PKCE→token→`tools/call` end-to-end, and the SSE GET stream (25s keepalive, `http.Flusher`) survives the muxed tunnel. This proves conformance is *inherited* — `PublicURL` is one uniform origin, all six endpoints tunnel to it, no spec surface can drift. (An even faster first rung: `edge --behind-front` / `edge --tunnel tailscale`, which proves the "`Handler()` over a non-public listener" seam behind existing infra with near-zero new code — see the grafts.)
  - **Shipped so far** (this PR): (1) the `edge` **behind-front** loopback seam (`behind_front: true`); (2) the **`beacon/` package** — deterministic subdomain from the gateway key (`SubdomainLabel`), the crypto/tls-based SNI peek with byte-exact replay, the reverse-tunnel rendezvous (gateway dials out, registers, opens on-demand data conns), and the SNI-routed raw splice exposed to the gateway as a `net.Listener` (`beacon.Tunnel`); (3) the **`meshmcp beacon`** command; (4) **`edge --beacon`** — the `beacon:` config stanza, the derived public name, `Server.ServeOverListener`, and the cmd wiring that dials the beacon and serves the edge over the tunnel with the gateway's own cert. End-to-end tested: a **real `edge.Server` answers OAuth discovery through the beacon** (TLS terminates on the gateway, client pins the gateway cert), plus the raw-splice and SNI-peek proofs. (5) **ACME DNS-01 provisioning** (stacked follow-up PR): the beacon's **authoritative DNS server** (`miekg/dns`) answering A + `_acme-challenge` TXT, control-protocol **TXT publish/clear** frames (a gateway may only touch its OWN challenge name), a gateway-side **libdns provider** over the tunnel, and `edge` **`beacon.auto_cert`** wiring a certmagic DNS-01 solver so the gateway auto-obtains a publicly-trusted cert for its derived name — no inbound challenge port. Tested end-to-end minus the live Let's Encrypt call (the DNS-01 broker + authoritative DNS are proven with real DNS queries). (6) **Pre-merge security review + hardening**: an adversarial multi-lens review of the ingress code drove: **registration proof-of-possession** (a gateway now proves it holds the Ed25519 key its subdomain label is derived from — closing a critical subdomain/cert-hijack; nonce-signed challenge-response), a **data-conn leak race** fix, **per-tenant + global pending-splice caps**, **per-gateway TXT caps**, an **OPEN-frame write deadline**, and **TCP keepalive**. **Known follow-ups (deferred, documented):** source-client-IP passthrough (PROXY-protocol-v2 — until then the edge's per-IP limiters see the beacon address, not the real client); authoritative-DNS response-rate-limiting; the multi-tenant subdomain **lease/HA** layer (largely unnecessary for a single beacon: labels are deterministic and registration is now authenticated, so ownership can't be stolen and gateways self-heal on reconnect); and gateway-side **CT monitoring** (needs live CT-log access). None of these are exploitable to breach the trust core — that runs on the gateway.
- **Phase 1 — Hardened (weeks; the beacon is the real work — a new production public service, but a well-trodden Tailscale-Funnel/ngrok/frp shape).** CT auto-alarm + optional fail-closed; CAA pinning; signed subdomain→pubkey transparency log; PROXY-v2 source IP; per-tenant L4 DoS scrubbing/rate limits; durable subdomain lease across gateway reconnect **and** beacon restart/failover (shared state in `pgstore`); HA/anycast beacon fronts. Land DPoP enforcement behind a capability flag.
- **Phase 2 — Optional SaaS beacon + escape hatches (ongoing).** meshmcp-operated shared beacon with the Public-Suffix-List entry (to escape the Let's Encrypt per-registered-domain cert limit), abuse/enrollment controls, and funding/HA. Ship and document the two escape hatches in parallel: `behind-front`/RFC-8693 for operators with their own infra, and `--tunnel tailscale` for the Tailscale population. Same binary, one trust curve.

**Effort feel:** the gateway delta is genuinely small and reuse-heavy; the standing multi-tenant beacon service is the bulk of the work, and it is a known shape. The confidentiality-preserving default therefore ships cheaply for a self-hosted or single beacon, with the SaaS beacon as the polish pass.

## Residual risks & unexplored alternatives

**Open risks (be honest):**

- **Active rogue-cert MITM by a malicious/compromised/subpoenaed beacon.** Because the beacon is DNS authority for the subdomain, it can satisfy DNS-01 under its own key, obtain a valid publicly-trusted cert, and MITM the outer TLS — exposing bearers and tool traffic and enabling bearer replay. Mitigation is **detective** (CT monitoring), which races the ≤1h bearer window with real CT-indexing lag; the only fully **preventive** fix (operator CNAME from an owned apex) reintroduces the DNS burden. This is the load-bearing residual; it is narrower and better-defended than the terminating broker's unconditional exposure, but it is real and must be documented as a new deviation (D-E) and adversary in the threat model.
- **Bearer replay without DPoP.** claude.ai presents no DPoP today, so tokens are pure possession-equals-authority. The double-gate bounds *what* a replayed bearer can do (tool-scoped, audited) but cannot prevent it. Enforce DPoP the moment the connector supports it.
- **Stable-URL durability across failover.** Keeping `gw-<id>` pinned to the same gateway across redials and beacon restart, with no operator account, needs the shared lease state in Phase 1. If it regresses, the connector URL silently breaks after a reconnect.
- **SSE longevity** over the muxed tunnel + beacon failover; and **ECH** (Encrypted ClientHello) would hide the SNI and break routing — the beacon owns the zone and simply must not publish HTTPS/SVCB ECH configs, and this incompatibility must be documented.
- **Self-host relocates, does not eliminate, the public triad** onto the beacon box (amortized once across all a gateway's tools, and de-risked because that box holds no key and sees no plaintext).

**Alternatives the six did not cover:**

- **A native connector-side mesh join or mTLS client certificate.** The clean fix is for the hosted client to prove a key meshmcp already trusts (join the mesh, or present a client cert bound to the capability at the TLS layer). This is outside meshmcp's control today but is the only path that removes the in-path party entirely — worth raising with Anthropic.
- **Application-layer end-to-end encryption / payload signing beneath the transport.** None of the six proposed an MCP-level E2E envelope that would defeat even a *terminating* broker. It is impossible unilaterally (claude.ai speaks vanilla OAuth/MCP), but if the MCP spec ever admits a request-signing or payload-encryption extension, it would collapse the entire confidentiality question for every design here.
- **DANE/TLSA pinning in the beacon zone.** The beacon controls DNS, so it could publish a TLSA record pinning the gateway's cert — but a *malicious* beacon controls the TLSA record too, so it does not escape the DNS-authority trust problem. Noted and rejected.
- **Anycast/QUIC-only rendezvous with connection migration** to make beacon failover invisible to a live SSE stream — an optimization worth prototyping in Phase 1 but not required for MVP.

## Grounding check (verified against the tree)

The build sketch rests on primitives confirmed present in this repo:

- **`certmagic v0.21.3`** is already a direct dependency (`go.mod`) — the beacon's DNS-01 ACME path reuses `edge/acme.go`, not a new library.
- **`golang.org/x/net` (HTTP/2)** and **`google.golang.org/grpc`** are already in the module graph, so tunnel multiplexing needs **no new dependency** (`yamux`/`smux`/QUIC remain optional upgrades).
- **The outbound-dial pattern** (`client.Dial` + `BlockInbound=true`) is proven and reused today in `cmd/meshmcp/edge.go`, `air.go`, and `agent.go`; the beacon's reverse rendezvous uses the same primitive.
- **`edge.Server.Handler()`** (`edge/server.go:210`) is a plain `http.ServeMux` cleanly separated from `Run()` (`edge/server.go:292`), and the double-gate order (`edge/mcp.go:165` — capability `Verify` at `:170` before policy `DecideToolCallBound` at `:175`, fail-closed audit at `:179`) is exactly as the invariants require — so serving `Handler()` over a tunnel-backed listener changes the transport, not the trust core.

Secondary code references in this doc (`edge/limits.go` rate-limit keying, the `DPoPVerifier` seam, `metadata.go` discovery, `edge/assertion.go` for the BYO-front graft) name the surfaces a build would touch; confirm exact signatures at implementation time.

## See also

- [EDGE.md](../EDGE.md) — the current public-listener ingress whose operator burden this proposal removes.
- [spec/OAUTH-STANDARDS.md](../spec/OAUTH-STANDARDS.md) — the recorded exposure-model decision and deviations D-A…D-D; the beacon adds a proposed **D-E** (beacon as DNS/CA-path authority, CT-detected).
- [THREAT-MODEL.md](../THREAT-MODEL.md) — adversaries 12–13 (external OAuth registrant, stolen edge bearer); the beacon adds a proposed active-rogue-cert-MITM adversary.
- `edge/mcp.go` (`enforceToolCall`), `edge/token.go` (`mintTokenSet`), `edge/server.go` (`Handler`, `Run`) — the trust core a beacon must keep intact.
