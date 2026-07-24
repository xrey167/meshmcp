# The Edge — hosted MCP clients over a governed public door

`meshmcp edge` is the project's **one deliberate exception** to "no public
application ingress." It exists for a single case the mesh model cannot serve:
a **hosted MCP client that cannot join a WireGuard mesh** — most concretely a
[claude.ai](https://claude.ai) custom connector, which runs on Anthropic's
servers and reaches an MCP server over public HTTPS with OAuth.

Everything else in meshmcp keys identity off the WireGuard key the transport
proves. A hosted client holds no such key. The edge closes that gap without
weakening the core: it terminates OAuth at a hardened, off-by-default listener,
maps the caller to a synthetic identity, and puts it through the **same**
default-deny policy engine, capability verification, and fail-closed audit log
as any mesh peer. See the recorded exposure-model decision and its four
deviations (D-A…D-D) in [spec/OAUTH-STANDARDS.md](spec/OAUTH-STANDARDS.md), and
adversaries 12–13 in [THREAT-MODEL.md](THREAT-MODEL.md).

> **Maturity:** Experimental / Labs, off by default. See
> [CAPABILITY-MATRIX.md](CAPABILITY-MATRIX.md). It is the product's only public
> listener; run it only when you deliberately need a hosted client, and scope
> its backend policy tightly.

---

## What it is, in one paragraph

A second, explicitly-configured TLS listener — never the mesh interface, never
a default-on bind — that serves the OAuth 2.1 authorization-server endpoints
(discovery, Dynamic Client Registration, authorize, token) plus **exactly one
tool-scoped MCP endpoint** at `/mcp`. A hosted client discovers the auth server
from a `401` challenge, registers itself, is approved by an operator, runs the
authorization-code + PKCE flow (with operator-in-the-loop consent), and receives
a short-lived bearer token. That bearer is exchanged at issuance into an
Ed25519 `policy.CapabilityClaims` bound to `oauth:<client_id>`, audience- and
tool-limited, TTL ≤ 1h; it is re-verified on every tool call. The bearer never
crosses into the mesh.

---

## The trust boundary it draws

```
   claude.ai (Anthropic servers)                 your infrastructure
   ─────────────────────────────                 ───────────────────────────────
   OAuth 2.1 + PKCE  ─────────────►  ┌─────────────────────────────────────────┐
   Bearer access token  ──────────►  │  meshmcp edge  (public TLS, off by       │
                                     │  default, one configured backend)        │
                                     │    · DCR + operator approval             │
                                     │    · authorize + consent + token         │
                                     │    · /mcp: bearer → oauth:<client_id>     │
                                     │      → capability gate → policy engine    │
                                     │      → fail-closed audit → bridge         │
                                     └──────────────────┬──────────────────────┘
                                                        │ WireGuard mesh (the edge joins it)
                                                        ▼
                                        one configured MCP backend (unchanged)
```

The public listener reaches **only** the one backend named in its config. There
is no route from the edge to the rest of the mesh, the control plane, or any
other backend.

---

## The double gate

Every `tools/call` on `/mcp` passes two independent checks before it is relayed:

1. **Capability gate.** The bearer's stored Ed25519 capability must cover the
   tool for this identity and this backend. It is re-verified from the signed
   grant on every call, so a tampered on-disk token record cannot widen it, and
   a revoked capability id fails closed.
2. **Policy gate.** The unchanged `policy.Engine` decides the call under your
   `backend.policy` rules, keyed on `oauth:<client_id>` — deny-by-default,
   with the same rate limits, windows, and co-sign semantics a mesh peer gets.

A denial at either gate returns a JSON-RPC error and is audited. An allow is
relayed only if the decision was recorded (fail-closed audit).

---

## Identity model

A hosted client is one synthetic identity: `oauth:<client_id>`, used as both the
policy FQDN and key (the engine compares it as an opaque string — no engine
change was needed). Write rules against it exactly like a mesh peer:

```yaml
rules:
  - peers: ["pubkey:oauth:edge-ab12…"]   # one specific connector
    tools: ["search_*"]
    allow: true
  - peers: ["oauth:*"]                    # any approved hosted client
    tools: ["read_wiki"]
    allow: true
```

Group membership works too. The authorizing operator is recorded in the audit
trail, not folded into the identity, so one connector keeps one stable identity
across re-authorizations.

---

## Registration gating

- **`open-approval` (default, claude.ai-compatible).** Anyone may register
  (claude.ai registers with no initial access token), but the client lands
  **pending** and can complete no authorization and obtain no token until an
  operator approves it. Compensating controls replace the RFC 7591
  initial-access-token gate: per-IP rate limits, a `max_pending` cap plus
  pending-TTL GC, and audited transitions.
- **`token` (spec-literal).** Registration requires a pre-issued initial access
  token; a successful registration is approved directly. Unusable by claude.ai
  (it has nowhere to present the token), offered for closed deployments.

---

## Operating it

```bash
# Start the public ingress (see examples/edge.yaml for a full annotated config).
meshmcp edge --config edge.yaml

# Review and decide registrations and authorization requests.
meshmcp edge clients list   --state /var/lib/meshmcp/edge
meshmcp edge clients approve --state /var/lib/meshmcp/edge <client_id>
meshmcp edge authz   list   --state /var/lib/meshmcp/edge
meshmcp edge authz   approve --state /var/lib/meshmcp/edge <request_id>

# Inspect and revoke issued tokens; revoke a client entirely (cascade).
meshmcp edge tokens  list   --state /var/lib/meshmcp/edge
meshmcp edge tokens  revoke --state /var/lib/meshmcp/edge --family <id>
meshmcp edge clients revoke --state /var/lib/meshmcp/edge <client_id>

# The edge keeps its own tamper-evident ledger — verify it like any other.
meshmcp audit verify /var/lib/meshmcp/edge/audit.jsonl
```

Consent is **operator-in-the-loop**: no password is collected on the public
page (there is nothing there to phish); the browser page only polls, and the
operator approves out of band with `edge authz approve`. Revoking a client
tears down its tokens, the capabilities those tokens carried, and its live
sessions.

---

## TLS

Exactly one of two modes, sharing one hardened server (ReadHeaderTimeout and
IdleTimeout set; no global write/read timeout so SSE survives):

- **Operator cert files** — `tls.cert_file` / `tls.key_file` (use a full chain).
- **Opt-in ACME** — `tls.acme` via [certmagic](https://github.com/caddyserver/certmagic)
  (already in the module graph). `tls-alpn-01` by default (no extra port), or
  `http-01` with its own listener. Certificates are obtained synchronously at
  startup — a certificate problem is a fatal startup error, never a silent
  first-handshake failure.

claude.ai requires a publicly-trusted certificate; ACME is the practical
default. A self-signed cert will be rejected by the connector.

---

## Behind a front — zero inbound ports (`behind_front`)

The TLS modes above make the edge itself the public listener: an inbound port, a
public DNS name, and a cert to obtain and rotate. `behind_front: true` removes all
three for the common case where a **trusted TLS-terminating front already exists**
— [Tailscale Funnel](https://tailscale.com/kb/1223/funnel), a reverse proxy, or an
API gateway that dials out and needs no inbound port on this host:

```yaml
behind_front: true
listen: 127.0.0.1:8080          # loopback ONLY — enforced
public_url: https://mcp.example.com   # the FRONT's public https URL (still the OAuth issuer)
# no tls: block — the front terminates TLS
```

In this mode the edge serves **plain HTTP on loopback**; the front terminates the
public TLS and forwards. Everything that matters is byte-for-byte identical to the
public-TLS path: the OAuth endpoints, the capability + policy double gate, and the
fail-closed audit ledger all run on this gateway. Only the listener and where TLS
terminates change.

Two guarantees keep it safe:

- **Loopback is enforced.** `listen` must bind `127.0.0.0/8` or `::1`; any
  routable address is a config error, so OAuth bearers can never cross a network
  in cleartext. The front must reach the edge over loopback (or a host-local
  socket), never across an untrusted segment.
- **The front owns TLS.** A `tls:` block alongside `behind_front` is a config
  error — exactly one party terminates TLS.

Example with Tailscale Funnel (no meshmcp infra, no inbound port, TLS terminates
on *your own* node so the tunnel provider sees only ciphertext):

```bash
meshmcp edge --config edge.yaml        # serves http://127.0.0.1:8080
tailscale funnel 8080                  # publishes https://<node>.ts.net → 127.0.0.1:8080
# set public_url to the funnel URL; claude.ai connects to it
```

This is the first, near-zero-code rung of the broader
[hosted-client ingress design](design/HOSTED-CLIENT-INGRESS.md), whose recommended
end-state (the passthrough **beacon**) removes the "must already run a front"
caveat while keeping the same loopback-listener seam.

---

## Behind a beacon — zero inbound ports, no front to run (`beacon`)

`behind_front` still needs a front you operate. A **beacon** (`meshmcp beacon`)
removes even that: the gateway dials OUT to a shared beacon, is assigned a stable
public name derived from its key, and the beacon routes inbound TLS to it by the
cleartext **SNI**, splicing raw bytes. TLS terminates on the **gateway** with the
gateway's OWN certificate — the beacon holds no key and sees only ciphertext.

```yaml
beacon:
  control: beacon.example.com:7443   # the beacon address the gateway dials out to
  zone: beacon.example.com           # the beacon's public DNS zone
  auto_cert:                         # automatic cert via ACME DNS-01 (recommended)
    email: ops@example.com           #   ACME account contact
# listen / public_url are unused: public_url is derived as https://<label>.<zone>
```

The public name is `<label>.<zone>` where `label = base32(sha256(signing-key
pubkey))[:16]` — deterministic, so it survives restarts (the connector needs a
stable URL). Two ways to get the gateway's certificate:

- **`beacon.auto_cert` (recommended)** — the gateway obtains a publicly-trusted
  cert for its derived name via **ACME DNS-01**, brokered through the beacon: the
  gateway publishes the challenge TXT over the tunnel and the beacon's
  authoritative DNS serves it. No inbound challenge port, no manual cert.
- **`tls.cert_file` / `tls.key_file`** — an operator-provided cert whose SAN is the
  derived name (printed on startup). Use `auto_cert` OR files, not both.

Run the relay with its authoritative DNS enabled (required for `auto_cert`):

```bash
meshmcp beacon --zone beacon.example.com --public :443 --control :7443 \
               --dns :53 --public-ip 203.0.113.10
```

Delegate the beacon zone (`beacon.example.com`) to that DNS server at your
registrar so Let's Encrypt (and hosted clients) resolve it.

**Confidentiality vs. `behind_front`:** the beacon is a shared party that owns the
public name, so it is DNS authority for the subdomain and *could* actively MITM by
issuing its own cert — a narrower, CT-detectable risk than a TLS-terminating
proxy, and escapable by self-hosting the beacon. Against a *passive* beacon, only
ciphertext and the SNI are exposed. The full trade, and the CT-monitoring /
DPoP mitigations, are in the
[design doc](design/HOSTED-CLIENT-INGRESS.md).

### Hardening a public beacon

For a beacon exposed to the internet, three defenses harden the control path and
the authoritative DNS. All are backward compatible — an unpinned gateway and a
beacon without these flags behave exactly as before.

- **Pin the control channel (`--control-tls-auto`, `beacon.pin`).** Start the
  beacon with a control-channel certificate and it prints an SPKI pin:

  ```bash
  meshmcp beacon --zone beacon.example.com --control :7443 --control-tls-auto
  # → control channel TLS enabled — configure gateways with beacon.pin: "sha256/…"
  ```

  Set that pin in the gateway's `beacon.pin`. Every control **and** data dial to the
  beacon is then TLS with the beacon's public key pinned (no PKI, so the beacon can
  rotate its leaf), so the routing protocol — connIDs, the connID-binding key, ACME
  TXT publishes — cannot be observed or MITM'd. The beacon serves pinned (TLS) and
  legacy (plaintext) gateways on the same port, so enabling it is not a flag day. BYO
  cert with `--control-cert`/`--control-key` instead of `--control-tls-auto`.

- **connID HMAC binding (automatic over a pinned channel).** Once the control
  channel is TLS, the beacon hands each gateway a per-session key and requires every
  inbound data connection to carry `HMAC(key, connID)`. A third party that learns a
  connID still cannot claim a pending splice — the data path is authenticated to the
  session, not just the (already unguessable) connID.

- **DNS response-rate-limiting + TCP.** The authoritative server (`--dns`) answers
  over **TCP as well as UDP**, applies EDNS0-aware truncation, and rate-limits UDP
  responses per client prefix (/24, /64): over the budget it slips to a small `TC=1`
  answer (forcing a rate-limit-exempt TCP retry) or drops — so the beacon cannot be
  used as a reflection/amplification vector. Loopback and TCP are exempt; Let's
  Encrypt validation (a few queries per resolver prefix) is well under the budget.

> The PROXY-header source IP the gateway records is exactly as trustworthy as the
> beacon that asserts it — pin the control channel in production. See the design doc.

> **Status:** experimental. The rendezvous, SNI-routed splice, gateway listener,
> authoritative DNS server (RRL + TCP), ACME DNS-01 challenge brokering, PROXY v2
> source-IP passthrough, connID HMAC binding, and control-channel TLS pinning are
> implemented and tested end-to-end (the live Let's Encrypt issuance itself is
> exercised only in real deployments). Multi-tenant subdomain leasing/HA,
> per-IP rate limiting on the control listener, and CT-monitoring are the next
> increments.

---

## Transport

Full MCP Streamable HTTP:

- **POST** relays one JSON-RPC request, preserving the client's id.
- **GET** opens the Server-Sent Events stream (25 s keepalives, one stream per
  session, a bounded per-session buffer that closes the session on overflow, and
  a cut when the access token expires — no authorization outlives its token).
- **DELETE** ends a session.
- `Mcp-Session-Id` is issued on `initialize` and bound to `{client_id, grant
  family}` — a request presenting another client's or family's session is a
  `404`. Sessions are in-memory; a restart makes clients re-initialize (which
  the spec requires them to handle). Set `oauth.sessions: false` for spec-legal
  stateless POST-only mode.

The backend leg is a transparent proxy: the edge dials the one configured mesh
backend and relays JSON-RPC, routing backend notifications onto the session's
SSE stream. Only newline-framed JSON-RPC mesh backends (meshmcp's stdio/
resumable gateway surface) are supported in v1; HTTP-kind backends are a
documented non-goal for now.

---

## Shared DPoP replay store

The edge constructs an RFC 9449 DPoP verifier whose replay store (spent `jti`
values and server-issued nonces) is in-process by default — correct for a
single instance, but two edge instances behind one public URL would each track
replays alone, so a proof spent on one could be replayed against the other.
`oauth.dpop_replay_store` (a `postgres://` DSN, backed by the `pgstore`
package) makes the store shared and restart-surviving. It is fail-closed: a
non-postgres value is a config error, and an unreachable database at startup
refuses to start the listener rather than silently degrading to per-process
tracking. Note the public surface is bearer-only today (the recorded
exposure-model decision — hosted clients such as claude.ai present no DPoP);
the verifier is the seam DPoP-bound flows will enforce through.

---

## What it is not

- **Not** a general-purpose OAuth authorization server for arbitrary bearer
  clients on the mesh's own tool-call path (that would duplicate and weaken the
  capability/delegation model — the explicit non-goal in
  [spec/OAUTH-STANDARDS.md](spec/OAUTH-STANDARDS.md)).
- **Not** a change to the mesh. `serve`, `federate`, the policy engine, and the
  `federation/` package are untouched; not running `meshmcp edge` leaves the
  product byte-for-byte identical.
- **Not** the partner-org federation path. The issuer-pinned DCR/token-exchange
  handlers in `federation/` remain a separate, still-unwired story for
  organizations that run their own IdP.

---

## See also

- [examples/edge.yaml](../examples/edge.yaml) — a full annotated config.
- [COOKBOOK.md](COOKBOOK.md) recipe 13 — "Connect claude.ai to a mesh tool."
- [spec/OAUTH-STANDARDS.md](spec/OAUTH-STANDARDS.md) — the design, the recorded
  exposure-model decision, and deviations D-A…D-D.
- [THREAT-MODEL.md](THREAT-MODEL.md) — adversaries 12 (external OAuth
  registrant / hosted client) and 13 (stolen edge bearer token).
