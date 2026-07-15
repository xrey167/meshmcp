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

## Where it goes — grounded

Phases 1–3 (gateway, resumable sessions, policy+audit) and much of the HA / tool-mesh
track (session migration, replica failover, discovery registry, bidirectional MCP — see
[HA-TOOLMESH.md](HA-TOOLMESH.md)) are **built and tested**. The phases below remain open;
they are control-plane / governance work on top of the proven substrate.

**Phase 4 — capability tokens.** Today authz is peer-identity → tool. Next: short-lived,
signed capability grants ("this agent may call `read_*` on `kg-memory` until 15:00"), issued
by a control plane and verified at the gateway. Turns the mesh into an agent-scoped
capability system, not just a network.

**Phase 5 — rate & cost governance.** The gateway already sees every tool call. Add
per-identity quotas, token-bucket rate limits, and (for LLM-backed tools) cost accounting.
A denied-by-budget response is the same inline-error mechanism as a policy deny.

**Phase 6 — federation.** Multiple NetBird networks (orgs) peering selected backends across
a trust boundary, with policy at the seam. An agent in org A calls a vetted tool in org B,
every call audited on both sides, nothing else reachable. B2B tool-sharing with no public
surface.

**Phase 7 — observability plane.** `meshmcp status` → live sessions, peers, per-tool call
rates; the audit stream shipped to any sink (OTel, a SIEM). "Who called what, from where,
when" becomes queryable for an entire agent fleet.

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

- Policy applies to **stdio** backends (newline-delimited JSON-RPC). Streamable-HTTP
  backends get network ACL + identity headers, not per-tool parsing, yet.
- NetBird **group** membership isn't available through the embed API; policy matches FQDN
  and pubkey today. Group-based rules need the management API.
- The gateway binary is heavy (~44 MB, NetBird's dep tree) — a daemon, not something to
  embed in a tiny CLI. Clients that only `connect` could use a thinner build later.
- One live roam (physically moving networks mid-session) is proven only by loopback drop +
  live round-trip separately, not yet as a single physical-roam test.
