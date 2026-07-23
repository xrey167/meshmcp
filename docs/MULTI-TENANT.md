# Multi-tenant control plane (F25 v1)

The control plane can partition its own state — policy, service registry,
enrollment, and audit — into **tenants**, so several teams share one control
node without being able to read or write each other's control storage.

The wedge is a single invariant, inherited from the confused-deputy lesson that
governs the whole product:

> A caller's tenant is a **pure function of the transport-proven WireGuard key**,
> resolved at the same instant as identity, inside the one authorization
> chokepoint. It is never named by a request — not in the body, a header, a query
> param, or the URL. A handler receives only the `tenantID` the chokepoint
> derived, and every store is addressed through it. **Cross-tenant access is
> absent by construction, not blocked by a check.**

A single-tenant deployment (no `tenants:` in the ACL) behaves **exactly** as
before this feature existed — the entire tenant layer is additive and default
off.

## How a tenant is defined

A tenant is a **named group of grants** in the operator ACL. The control ACL
(`--acl`) gains a `tenants:` form alongside today's flat `grants:` form; the two
are mutually exclusive and auto-detected at load.

```yaml
# Multi-tenant: each tenant is defined ONLY by the keys it grants.
tenants:
  acme:
    grants:
      <KA-wireguard-pubkey-hex>: [control.admin]
    enroll_groups: [nb-group-acme]      # optional, per-tenant NetBird auto_groups
  globex:
    grants:
      <KB-wireguard-pubkey-hex>: [policy.read, registry.read]
```

```yaml
# Single-tenant (UNCHANGED — loads and behaves exactly as today):
grants:
  <key>: [control.admin]
```

**Load-time invariants** (a misconfigured ACL fails startup, never silently
mis-partitions — operator input is validated at load, never in the request
path):

- A key is granted under **exactly one** tenant. A key in two tenants is a
  config error (its tenant would be ambiguous).
- Each tenant id passes the same path-safety rules as a policy name
  (`[A-Za-z0-9._-]`, no `..`, no separators, ≤128) because it becomes a
  **directory segment** under each store root.
- `tenants:` and top-level `grants:` are mutually exclusive.
- A tenant with no grants, and an ACL with neither `grants:` nor `tenants:`, are
  errors (a default-deny control plane with no admitted key admits no one).

Tenant and roles resolve **atomically from one datum** (the ACL), so they can
never drift the way two separate config files (an ACL plus a pubkey→tenant map)
could.

## How a tenant is resolved (per request)

Inside `Server.authorize` — the sole chokepoint every privileged route funnels
through — immediately after the transport identity is derived and before the
role check:

```
id, ok := Identify(remoteAddr)          // transport only (WireGuard key); unchanged
if !ok || id.PubKey == "" -> 403         // unattributable caller
tid, ok := TenantFor(id.PubKey)          // tenant is a pure function of the key
if !ok -> 403 (deny, tenant="")          // caller belongs to no tenant
if !Authorized(tid, id.PubKey, role) -> 403 (deny, tenant=tid)
-> allow (tenant=tid); return (id, tid)
```

`authorize` returns `(identity, tenantID)`; the `tenantID` is the only handle a
handler has on a tenant. Every store selection (`policyStore(tid)`,
`regStore(tid)`, `enrollWith(tid)`) takes it, so a request is role-checked
against a tenant's authorizer **and** addressed into that same tenant's stores —
the two can never point at different tenants.

## RBAC: no cross-tenant super-role

A grant is `(tenantID, pubKey) → roles`. Each tenant has its **own**
authorizer; `control.admin` implies every role **within that tenant only**.
Isolation is structural: an admin-of-A's key literally does not exist in B's
authorizer, so `Authorized("B", KA, …)` consults a map with no entry for `KA` and
returns false. This is not a "caller tenant == target tenant" comparison a logic
slip could bypass — the datum for KA-in-B is absent.

## Storage layout

| Capability | Flag (now a **root**) | Per-tenant path |
|---|---|---|
| Policy | `--policies <root>` | `<root>/<tenant>/<name>.yaml` |
| Registry | `--registry <root>` | `<root>/<tenant>/*.json` |
| Control + enrollment audit | `--control-audit <dir>` | `<dir>/<tenant>.jsonl` (one hash chain per tenant) |

A tenant's directories and audit chain are created **lazily** on first use, so a
tenant that never acts leaves no files. In single-tenant mode the same flags name
a single directory/file (the sentinel tenant `""` collapses `join(root, "")` to
`root`), so on-disk layout is byte-identical to today.

## Audit isolation — one hash chain per tenant

Multi-tenant control-plane actions are routed through a **per-tenant
`policy.AuditLog`** (a real tamper-evident hash chain), not the plain
control-audit sink. Control actions **and** enrollment for a tenant interleave
into the **same** `<control-audit-dir>/<tenant>.jsonl`, sharing one `Seq`/
`PrevHash` cursor, so:

- `meshmcp audit verify` (or `policy.VerifyChain`) over one tenant's file proves
  its integrity **without needing any other tenant's records**.
- One tenant's sequence numbers advance independently of another's (distinct
  `AuditLog` instances, distinct cursors).
- A **no-tenant denial** (a caller in no tenant) carries `tenant=""` and is
  logged to the un-tenanted fallback (stderr) — it can never enter a tenant's
  chain, keeping every chain free of foreign records.

Set `--control-audit <dir>` to get per-tenant chains; without it, control
decisions log to stderr (no per-tenant chain). Per-tenant chains are seeded from
their existing tail on restart (continue the same chain) but are not re-verified
at open in v1 — see non-goals.

## Enrollment — the honest boundary

`NetBirdIssuer` holds **one PAT for one NetBird account**. True per-tenant
*management-plane* isolation (a separate account/PAT per tenant) is **out of v1**
— do not read the shared PAT as cryptographically isolated. What v1 does isolate:

1. **Per-tenant `auto_groups`**: an enrolled node lands in its tenant's NetBird
   groups (`enroll_groups` in the ACL; falls back to `--enroll-groups`).
2. **Tenant-stamped, chain-isolated enrollment audit**: enrollment is attributed
   in the tenant's own hash chain.
3. The enroll response advertises the tenant's **own** registry subdir, so an
   enrolled node registers into its partition.

## What is and isn't isolated in v1

**Isolated (defended, tested):**

- **Policy read/write** — a tenant cannot read or list another tenant's policies
  (separate directories).
- **Registry** — a tenant's listing excludes other tenants' services.
- **RBAC** — admin-of-A holds nothing in B; no cross-tenant super-role.
- **Namespace collisions** — same policy/service name in two tenants are
  independent files; a write in one never mutates the other.
- **Audit chains** — one tamper-evident hash chain per tenant; verifiable in
  isolation; independent sequence cursors.
- **Enrollment attribution + group-scoping** — attributed to the tenant's chain,
  scoped to the tenant's groups.
- **Deny-by-default** — a caller in no tenant is refused on every privileged
  route, deny-audited with an empty tenant.
- **Confused-deputy** — a caller-named tenant in the body/params is rejected
  (`DisallowUnknownFields`) and could not redirect the operation regardless; the
  tenant derives only from the transport key.
- **Single-tenant back-compat** — no `tenants:` ⇒ byte-identical to today.

**NOT isolated in v1 (explicit non-goals — named, not faked):**

- **NetBird management-plane account** — one shared PAT for all tenants.
  Enrollment isolates groups and audit attribution, not the account.
- **The anchor witness file** (`--anchor-witness`) — this host's own
  external-anchoring log, not per-tenant control storage; shared in v1.
  Authorization still funnels through the tenant chokepoint (a caller must belong
  to a tenant and hold `anchor.submit`).
- **Fail-closed per-tenant control audit** — control audit stays best-effort
  (observability layered on the 403), and per-tenant chains are tail-seeded on
  restart but not re-verified at open. Both are possible hardenings, deferred.

See [THREAT-MODEL.md](THREAT-MODEL.md) adversary 14 for the defended property and
its boundary, and [CAPABILITY-MATRIX.md](CAPABILITY-MATRIX.md) for maturity.
