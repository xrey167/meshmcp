# SSO-mapped group attribution (F31, v1)

Map an external OIDC identity's **groups** onto an already-authenticated mesh
peer, so an organization's SSO directory role can drive `group:<name>` policy —
**without** ever replacing the WireGuard transport identity as the root of trust.

This is the first slice of F31 ("federated identity — SSO mapping at the seam").
It is deliberately narrow and honest: an OIDC claim is **additive attribution**
bound to a transport-proven mesh key, never a new authentication path.

## The one-paragraph model

A mesh peer, already connected and WireGuard-authenticated, presents an OIDC
token to `POST /v1/sso/attest` on the gateway's mesh control endpoint. The
gateway resolves the caller's **transport** public key from the connection
(never from the token), verifies the token against **statically pinned** issuer
keys (signature, `iss`/`aud`/`exp`/`nbf`, pinned algorithm), and — on success —
records the token's `groups` as an attribution **bound to that transport key**
for a bounded lifetime. A shared group resolver then reports those groups so an
existing `group:<name>` rule matches. Any verification failure binds **nothing**.

```
mesh peer ──(WireGuard, authenticated)──▶ gateway control endpoint
   │                                          │
   │  POST /v1/sso/attest {token}             │ 1. peerKey := transport identity (ROOT)
   └─────────────────────────────────────────▶ 2. OIDCVerifier.Verify(token)   (pinned key,
                                              │      iss/aud/exp/nbf, pinned alg)
                                              │ 3. SSOGroups.Bind(peerKey, groups, exp)
                                              ▼
   later: tools/call ──▶ policy Engine ──▶ group:<name> rule
                                        └─▶ CombinedGroups = StaticGroups OR SSOGroups
                                                                     (keyed on peerKey)
```

## Exactly what it DOES grant

- A **verified** OIDC token (correct signature against a pinned issuer key,
  `aud` contains meshmcp's identity, unexpired, not-before satisfied, header
  `alg` equal to the issuer's pinned algorithm) attributes its `groups` claim to
  the caller's WireGuard transport key.
- Existing `group:<name>` policy rules then match that caller — on **stdio and
  HTTP/remote** backends alike, through the same shared group resolver F17
  already uses.
- The attribution is **bounded**: it lives for `min(token exp, now + bind_ttl_max)`
  and stops matching once it expires (TTL eviction).

## Exactly what it does NOT grant (and does not do)

- **It never replaces or bypasses the WireGuard identity.** The transport
  `peerKey` is resolved from the connection first and remains the *only* thing
  enforcement keys on. The token alone authenticates nothing — the mesh
  connection must already be WireGuard-authenticated.
- **Every forgery/expiry/audience failure maps to nothing → deny.** A tampered
  or wrong-key signature, `alg:none`, an HS256 alg-confusion attempt, a missing
  or past `exp`, a future `nbf`, an `aud` that omits meshmcp, an unpinned issuer,
  or an algorithm that is not the issuer's pinned one — all fail verification, so
  **nothing is bound**, `InGroup` stays false, and the caller falls to today's
  deny behavior.
- **It grants no capability, tool ACL, or control-plane role by itself.** It only
  contributes group *membership* feeding `group:<name>` matching. If no policy
  rule references an attributed group, nothing changes for that caller.
- **Attribution is strictly per-transport-key.** A binding is keyed on the
  presenter's own transport key; one key's binding is never visible under
  another key's `InGroup`. A peer can only ever attribute groups to itself, and
  only groups an IdP actually issued it in a token this gateway verified.
- **No OIDC configured ⇒ byte-identical to today.** With no `oidc:` stanza there
  is no verifier, no store, no `/v1/sso/attest` route, and the group resolver is
  exactly the config-driven `StaticGroups` (or none) it is today.
- **The IdP is trusted for group membership, not audited by meshmcp.** meshmcp
  verifies the token is authentic and current; it does not second-guess whether
  the IdP's assignment of a user to a group is "correct."

## Configuration

```yaml
control:
  port: 9600          # required — the attest surface mounts on the mesh control listener
  allow: ["pubkey:..."]

groups:               # F17 groups; a group:<name> rule can be fed by config OR SSO
  finance: []         # (an empty static group is fine; SSO supplies the members)

oidc:
  audience: "https://meshmcp.example.org"   # a token's aud MUST contain this
  groups_claim: "groups"                    # optional (default "groups")
  email_claim:  "email"                     # optional (default "email")
  bind_ttl_max: 3600                        # optional cap in seconds (default 3600)
  issuers:
    - issuer: "https://idp.acme.example"    # exact iss string (no glob, no "*")
      alg:    "RS256"                        # PINNED per issuer: "ES256" | "RS256"
      jwks_file: "/etc/meshmcp/acme-jwks.json"   # the IdP's published JWKS, saved locally
    - issuer: "https://idp.other.example"
      alg:    "ES256"
      key_file: "/etc/meshmcp/other-es256.pem"   # OR a single PEM public key
```

Then a rule authorizes by SSO group exactly as it would by a config group:

```yaml
backends:
  - name: payments
    port: 9110
    stdio: ["./payments-mcp"]
    policy:
      default_allow: false
      rules:
        - peers: ["group:finance"]   # matched by StaticGroups OR an SSO binding
          tools: ["pay", "refund"]
          allow: true
```

### Static keys only in v1 (the honesty boundary)

Keys are **pinned statically** — a JWKS document on disk (`jwks_file`, the IdP's
published key set, supporting multiple keys and `kid` rotation) or a single PEM
public key (`key_file`). There is **no outbound network call on the verify
path**: a forged token never triggers a fetch, and verification is deterministic
and offline. This mirrors `federation/exchange.go`'s `PinnedIssuers`.

An automatic cached fetch of an IdP's `jwks_uri` (feeding the same pinned-key
map) is the documented **v2** extension. v1 **rejects** a `jwks_uri` field at
config load so the boundary is explicit — pin the JWKS document itself. The
pinned algorithm is set per issuer in config and is **never** read from a token's
header to select a verification path (alg-confusion / `alg:none` defense).

## Presenting a token

`POST /v1/sso/attest` on the control endpoint, over the mesh, with the token in
the body:

```
POST /v1/sso/attest
{ "token": "<compact-JWS OIDC token>" }

200 { "status": "bound", "subject": "...", "email": "...",
      "groups": ["finance"], "expires_at": 1893456000, "you": "agent-a.netbird.cloud" }
```

The endpoint is self-service (any authenticated mesh peer may attest) because a
peer can only bind groups to **its own** transport key, and only groups the IdP
issued it in a token this gateway verified. An unattributable transport (no
WireGuard key) is denied. Every attempt — success or failure — is recorded in the
shared audit ledger (`backend: sso-attest`, method `sso/attest`), with `peer_key`
holding the transport-verified key the attribution binds to.

## Where it lives in the code

- `policy/oidc.go` — `OIDCVerifier`, `OIDCClaims`, pinned ES256/RS256 verify,
  `ParseJWKS` (RFC 7517). Mirrors `federation/exchange.go`'s ordered,
  pinned-alg, fail-closed `validateSubjectToken`.
- `policy/ssogroups.go` — `SSOGroups` attribution store (`Bind`/`InGroup`, TTL,
  per-key isolation) + `CombinedGroups` (ORs `StaticGroups` with `SSOGroups`
  behind the Engine's single resolver slot).
- `cmd/meshmcp/sso.go` — the `POST /v1/sso/attest` handler (transport root →
  verify → bind), mounted on the mesh control listener.
- Wiring: `cmd/meshmcp/config.go` (`oidc:` config + load-time key resolution),
  `cmd/meshmcp/serve.go` and `cmd/meshmcp/httppolicy.go` (shared verifier + store
  threaded into the group resolver on both transports).

Bindings are in-memory and per-gateway-process; they survive a SIGHUP policy
reload (a config reload must not drop live attributions) but not a restart. A
multi-gateway HA deployment gets per-gateway binding stores — a shared store is a
follow-up, matching the capability/delegation replay-store precedent.
