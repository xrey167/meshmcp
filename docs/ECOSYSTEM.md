# The meshmcp agent ecosystem

meshmcp is becoming one coherent environment for agents, tools, workflows,
stores, and people—not a collection of unrelated commands. The experience is
designed around a short loop:

> **discover → understand → use → continue**

The inspiration is the coherence of well-integrated consumer platforms: one
identity, a small shared vocabulary, predictable hand-offs between surfaces,
and privacy by default. meshmcp uses its own names, protocols, and interaction
model. It is independent and is not affiliated with or endorsed by Apple Inc.

## The experience spine

| Step | What the user experiences | What meshmcp provides |
|---|---|---|
| **Discover** | “Show me what I can reach.” | A per-caller Air catalog, already filtered by backend ACL. |
| **Understand** | “What is it, who runs it, and what can it do?” | One Component Card vocabulary shared by catalog, map, home, change, CLI, and MCP-app views. |
| **Use** | “Open or invoke it by a durable reference.” | Stable IDs and names resolve to an address; the live transport proves identity and policy decides every action. |
| **Continue** | “Resume or steer work without losing its security context.” | Today, identity-bound session resume and steer; later, explicitly accepted Continuity Capsules for starting related work elsewhere. |

The important boundary is between **description** and **authority**. Discovery
can describe a component, but it cannot grant access to it.

## Component Card v1

Every new Air catalog is tagged with schema
`com.meshmcp.air.catalog/v1`. Each endpoint remains backward-compatible with
the previous catalog fields while adding a portable Component Card:

```json
{
  "id": "demo-main",
  "kind": "backend",
  "name": "demo",
  "version": "0.1.0",
  "owner": {
    "pubkey": "<gateway-wireguard-public-key>",
    "fqdn": "gateway.example.mesh"
  },
  "address": "100.64.0.2:9101",
  "transport": "stdio",
  "features": [
    { "name": "air.browse.v1" },
    { "name": "mcp.2025-06-18" }
  ],
  "lifecycle": {
    "state": "serving"
  }
}
```

The card fields are deliberately small:

| Field | Meaning |
|---|---|
| `id` | Stable logical reference. Configure it explicitly to preserve identity across renames; otherwise meshmcp derives a deterministic ID from owner, kind, and configured name. |
| `kind` | Portable role: `gateway`, `backend`, `agent`, `workflow`, `bus`, or `store`. |
| `name` | Human-readable name; it may change without becoming the component's identity. |
| `version` | Operator-declared component version, when known. |
| `owner` | Advertised WireGuard public key and display FQDN, with an optional SPIFFE ID. These are descriptive until a live transport proves identity. |
| `address` / `transport` | Current route and how to dial it. Address changes do not change an explicit stable ID. |
| `features` | Deterministic, versioned support claims. They are capabilities in the product sense, not authorization tokens. |
| `lifecycle` | Current advertised state (`starting`, `serving`, `busy`, `draining`, `offline`, or `unknown`), optional timestamp, and producer generation. |

Legacy `resumable` and `steerable` booleans stay on the wire during the
transition and are mirrored to their standard feature identifiers. Old catalogs
without card fields remain readable.

### Standard feature IDs

| Feature | Advertised when applicable |
|---|---|
| `mcp.2025-06-18` | The component speaks the repository's MCP protocol baseline. |
| `air.browse.v1` | Its MCP tools, resources, and prompts can be browsed. |
| `air.resume.v1` | Its configured session transport supports resume. |
| `air.steer.v1` | A live steer surface is currently available. |
| `authz.capability.v1` | The backend is configured to verify meshmcp signed capability grants. |

Feature order is canonicalized so catalogs, diffs, and interfaces see the same
representation. Absence means “not advertised here,” not “denied.”

### Cards advertise; policy authorizes

A Component Card is untrusted discovery metadata. In particular:

- `owner` never replaces the identity proved by the WireGuard transport;
- a feature never bypasses ACL, policy, co-sign, taint, secret, or capability
  verification;
- the gateway filters catalog entries for the connecting caller before they are
  returned;
- every real operation is authorized and audited again at its enforcement
  point.

The experimental MCP Server Card model under `protocol/servercard` and an Air
Component Card have different jobs: a Server Card describes an MCP server
protocol surface, while a Component Card describes a component's current place
inside this private mesh. They can converge later without weakening either
trust boundary.

## Ecosystem roadmap

Component Cards are the first shared contract. The following phases build on
that contract; they are not claims of shipped functionality.

| Phase | Outcome | Non-negotiable acceptance boundary |
|---|---|---|
| **1 · Component Cards** | One identity, feature, lifecycle, and resolution vocabulary across Air surfaces. | Cards stay advisory; live transport identity and policy remain authoritative. |
| **2 · Trust Card + Library** | Signed provenance, review status, publisher, content hash, and installed/available lifecycle connect the governed marketplace to a personal component library. | Installing verifies pinned publisher trust and content; it never activates code merely because it was discovered. |
| **3 · Universal Resolver** | Resolve a stable ID, friendly name, intent, or resource reference to the best caller-visible component. | Resolution returns candidates; it never widens the caller's authority or silently chooses an ambiguous name. |
| **4 · Continuity Capsules** | Move a bounded work summary and artifact references to another agent or device so it can start related work. | The target explicitly accepts. A capsule never swaps session ownership, transfers identity/capability/secret tokens, replays hidden model context, or auto-executes. New work runs as the target identity and is authorized anew. |
| **5 · Automations** | Turn schedules, audit events, and component lifecycle changes into governed actions. | Each trigger resolves a concrete actor and each effect passes normal policy, approval, and audit. |
| **6 · Native companion** | Approvals, inbox, browse, and continuity on a phone using the existing mobile bindings. | Hardware-backed device identity and explicit human confirmation protect privileged actions; shipping an app remains external to this repository. |

This sequence closes the loop: every surface reads the same card, every action
returns through the same identity and policy spine, and every result can become
discoverable, resumable, or explicitly handed forward without creating a second
security model.
