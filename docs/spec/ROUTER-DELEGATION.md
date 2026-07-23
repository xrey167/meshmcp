# Router / Federation Delegation Design (Phase 4)

## Problem

The aggregating router (and, symmetrically, a federation boundary) forwards a
downstream caller's request to an upstream backend. Today it dials the upstream
using the **router's own** WireGuard identity and conveys the original caller
only as unsigned `_meta`. An upstream that trusted `_meta` would be trusting
attacker-influenced data; an upstream that ignores it sees only the router. Either
way the router is an **unrestricted confused deputy**: any caller who reaches the
router can drive any upstream tool with the router's authority.

Engineering invariant to satisfy: **router forwarding cannot widen a downstream
caller's authority.**

## Design: signed delegation tokens + scope intersection

The router is an enforcement point for the original caller. For each hop it
presents a **signed, short-lived `DelegationToken`** (issued by a configured
trusted router authority) instead of relying on `_meta`. The token binds:

- original caller public key (`caller`)
- router public key (`router`)
- upstream audience (`aud`)
- backend (`backend`)
- tool/method (`tool`)
- canonical request hash (`req_hash`)
- expiry (`exp`, capped at 5 min) and a unique `nonce`
- the trusted authority signer (`pubkey`) + `sig` over all fields

The upstream verifies the token (`VerifyDelegation`) against a **pinned**
authority key and this exact hop, then computes the decision as the
**intersection**:

```
allow ⇔ delegation verifies
        AND upstream-policy(original caller)  = allow
        AND upstream-policy(router service)   = allow
```

implemented by `AuthorizeDelegated(callerDec, routerDec, delegationErr)`. Because
both the caller and the router must independently be allowed:

- a **router cannot widen** a caller's authority (caller denied ⇒ deny), and
- a **caller cannot exceed** what the router itself may do (router denied ⇒ deny).

Raw `_meta` remains informational only and is never trusted as identity.

## What the token verification rejects

`VerifyDelegation` fails closed on: a token version other than 1; a signer that
is not the pinned authority (and an empty pin never verifies); a token minted
for a different audience/backend/tool; a token presented by a different router
than it names; changed arguments (`req_hash` mismatch); an expired token; a
lifetime beyond the 5-minute ceiling (re-enforced at verify time, not just at
mint time — same belt-and-suspenders as the capability verifier); and a
replayed nonce (`NonceStore`). A second (nested) hop needs its own token bound
to the second audience — a first-hop token does not carry over.

## Status

- **Implemented & tested (`policy/delegation.go`, `policy/delegation_test.go`):**
  the `DelegationToken`, `IssueDelegation`, `VerifyDelegation`, `NonceStore`
  (replay protection), and `AuthorizeDelegated` intersection primitive, with
  tests for forged origin, wrong backend/audience/router, changed args, expiry
  (+ lifetime cap), replay, nested hops, compromised-router-widening, and the
  intersection in both directions.
- **Interim router hardening — WIRED:** the router is default-deny on a caller
  ACL (`routerCallerAllowed`), and — when a `policy:` block is configured — it now
  **applies full tool policy at the router before forwarding**. Every proxied
  `tools/call` is authorized against the ORIGINAL caller's transport identity and
  the namespaced tool name; a denied call is refused at the router and never
  dispatched upstream (`router.go`, `TestRouterEnforcesToolPolicy`,
  `examples/router-policy.yaml`). This reduces the confused-deputy blast radius
  from "any upstream tool" to exactly what the router policy permits — enforcement
  the router owns locally, with no wire-protocol change.
- **Signed-delegation upstream verification — WIRED (v1):** the router mints a
  per-call `DelegationToken` for every forwarded `tools/call` to an
  audience-pinned upstream, and a pinned gateway backend strips + verifies it
  (`VerifyDelegation`) and authorizes `AuthorizeDelegated(caller ∩ router)`.
  The three open decisions are settled:
  - **(a) Audience:** operator pin. Each static router upstream carries
    `audience: <upstream gateway mesh public key>`; the token's `aud` claim is
    that pin, and the gateway verifies against its own mesh key. With
    `delegation_key` set, a static upstream WITHOUT a pin is a startup error
    (it would otherwise be called unsigned); registry-discovered upstreams have
    no pin and take the legacy unsigned path (logged at startup).
  - **(b) Authority key:** lives at the router — `delegation_key:` names a
    `policy.Signer` key file created by `meshmcp router keygen`. A configured
    but missing/unreadable key is FATAL at startup (S13 pattern), never a
    silent downgrade. Gateways pin the authority's public key per backend:
    `router_delegation: {trusted_public_keys: [<hex>...], required: bool}`.
  - **(c) Wire transport:** `tools/call` `params._meta["com.meshmcp/delegation"]`
    = base64url(JSON(token)), minted once per logical call (one nonce; every
    replica dispatch attempt of that call presents the same token). The filter
    strips it from every governed line before the backend, trace, audit, or
    secret injection — and never trusts it (or `meshmcpOriginPeer/Key`, which
    stays informational) as identity: the token is verified against the pinned
    authority, and the presenting router is the transport-proven peer.

  Enforcement semantics: `required: true` denies any `tools/call` without a
  valid token; `required: false` verifies and
  intersects a call WITH a token and lets a token-less call fall through to the
  ordinary single-hop policy (mixed direct+routed backends). A mint failure at
  the router DENIES the call — it is never forwarded unsigned. A co-sign
  outcome on either leg of the intersection is not-allow and therefore denies
  (a delegated hop is not a co-sign enforcement point in v1). The caller leg is
  evaluated only after the router leg allows: a router-denied call has no side
  effects on the original caller's budgets (its single-use co-sign approvals
  and rate tokens are consumed only on the path that can allow), so a denial
  cannot be used to drain a caller's pending approvals.

  **Honest v1 limits:** `tools/call` only (other methods have no per-method
  verify hook upstream — `required: true` does NOT gate `resources/read`,
  `prompts/get`, or `tools/list`; restrict those surfaces with the backend
  policy's `methods` rules); stdio backends only (the HTTP enforcer has no
  body-rewrite strip yet — `router_delegation` on an HTTP backend is a config
  error, not a silent no-op); the replay `NonceStore` is **per-gateway-process
  in-memory** — a multi-gateway HA deployment has per-gateway replay windows,
  and a future shared (pg) store would fail closed on a cross-gateway replica
  failover re-presenting one token.

## Audit

Wired as specified: every call where a token was presented or required —
allow, verify-fail deny, and missing-token deny alike — records BOTH
identities and the nonce (`delegated_caller`, `delegation_router`,
`delegation_nonce`; see AUDIT-RECORD.md), so a forwarded call is attributable
end to end. `reason` carries the precise cause (`delegation invalid: ...`,
`denied by caller policy: ...`, `denied by router policy: ...`).
