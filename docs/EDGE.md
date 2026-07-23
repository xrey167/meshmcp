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
