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

`VerifyDelegation` fails closed on: a signer that is not the pinned authority
(and an empty pin never verifies); a token minted for a different
audience/backend/tool; a token presented by a different router than it names;
changed arguments (`req_hash` mismatch); an expired token; and a replayed nonce
(`NonceStore`). A second (nested) hop needs its own token bound to the second
audience — a first-hop token does not carry over.

## Status

- **Implemented & tested (`policy/delegation.go`, `policy/delegation_test.go`):**
  the `DelegationToken`, `IssueDelegation`, `VerifyDelegation`, `NonceStore`
  (replay protection), and `AuthorizeDelegated` intersection primitive, with
  tests for forged origin, wrong backend/audience/router, changed args, expiry
  (+ lifetime cap), replay, nested hops, compromised-router-widening, and the
  intersection in both directions.
- **Not yet wired (follow-up):** the router does not yet mint tokens per hop, and
  upstreams do not yet call `VerifyDelegation` + `AuthorizeDelegated` in the
  proxy path. Until that lands, router aggregation and federation remain
  **experimental / Labs** (see the capability matrix). The minimum interim
  hardening — a **default-deny caller ACL** on the router and applying full tool
  policy at the router before forwarding — is tracked with the wiring.

## Audit

When wired, both identities must be preserved in the audit record: the original
caller AND the router (delegate), plus the delegation nonce, so a forwarded call
is attributable end to end.
