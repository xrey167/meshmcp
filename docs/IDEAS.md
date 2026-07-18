# meshmcp — Revolutionary Enhancement Ideas

> A grounded ideation map for turning meshmcp from a control plane that *governs*
> other people's tools into a fabric that *carries valuable payloads itself* —
> knowledge, memory, and files — where **provenance and governance are
> cryptographic and built‑in, not bolted on**.

---

## The thesis

meshmcp today is plumbing: an identity‑native control plane for MCP traffic over an
embedded NetBird/WireGuard mesh. Its proven, composable primitives are unusually strong:

| Primitive | What it gives us | Where |
|---|---|---|
| **Cryptographic identity** | Every caller resolves to a WireGuard pubkey — proven, not claimed | `IdentityForIP`, `acl.go` |
| **Zero‑exposure transport** | Backends listen only on the mesh; no open ports | `mesh.go`, `serve.go` |
| **Resumable + migratable sessions** | Exactly‑once streams that survive roaming *and* gateway crash | `session/` |
| **The agent firewall** | Allow / deny / co‑sign, rate & time limits, **data‑flow taint + labels** | `policy/` |
| **Non‑repudiable audit** | Ed25519‑signed, SHA‑256 hash‑chained Merkle ledger | `policy/`, `audit.go` |
| **Credential broker · signed capabilities** | Secrets by identity; short‑lived subject‑bound grants | `secrets/`, `capabilitycmd.go` |
| **Router · federation · insight** | Aggregation, cross‑org bridging, policy‑from‑behavior | `router.go`, `federation/`, `insight/` |

**The move that makes everything below revolutionary:** the same WireGuard key that
authorizes a *tool call* can stamp a *knowledge triple*, a *retrieved document*, or a
*shared file*. No competitor has a knowledge graph whose every fact is signed, a RAG
whose corpus never leaves its trust boundary, or an AirDrop that is resumable **and**
audited by construction. meshmcp can — because identity, policy, audit, and taint already
exist. This extends the moat from *traffic* to *payload*.

> **Status today (both codebase explorations confirm):** KG, RAG, vector/embedding, and
> peer‑to‑peer file sharing are **all greenfield**. The `vectors` backend appears only in
> docs and the landing page; no such server exists. The MCP framework emits **text‑only**
> content. Persistence is entirely file/JSONL‑based (no DB). Clean slate, strong foundation.

---

## Flagship tier

Twelve deeply‑developed features, each novel *because of* meshmcp's primitives.

### F1 · AirDrop across instances — `meshmcp drop`  ⭐ *first to build*
Stream a file or directory to any mesh peer **by identity**. E2E‑encrypted by WireGuard,
**resumable over the session layer** (survives a network change mid‑transfer),
**policy‑gated** (the receiver's firewall must allow the drop by sender identity), and
**audited** (a content hash of every file lands in the ledger). Discovery like AirDrop:
`meshmcp peers` lists reachable identities; `meshmcp drop 100.x.y.z ./report.pdf`.
Zero‑config, no cloud, no open ports, no accounts.

> **Why it's revolutionary:** the only file transfer where *who sent what to whom* is
> cryptographically provable, and the transfer resumes across a roam.

### F2 · Provenance‑native Mesh Knowledge Graph
A KG MCP backend where every node and edge is stamped with the asserting identity and
hash‑chained into the audit ledger. Every triple is non‑repudiable ("prove who asserted
what, and when"); queries are policy‑filtered so an agent sees only the subgraph its
labels permit (reuses `emit_labels` / `block_labels`).

> **Why it's revolutionary:** a knowledge graph where trust is cryptographic and each fact
> carries a signature.

### F3 · Zero‑exposure, federated RAG
A `vectors` MCP backend (`embed` / `search`) reachable only over the mesh. A query fans out
across peers' vector stores via the **router**; each peer enforces its own policy on what's
retrievable; results merge.

> **Why it's revolutionary:** RAG where the corpus never leaves its owner's trust boundary —
> retrieval‑as‑a‑capability, private by construction.

### F4 · Mesh Spotlight — semantic search across every peer you can reach
Combine F1's discovery with F3's retrieval: one query, semantically searched across *all*
files and corpora on peers your identity is authorized to see, ranked and provenance‑tagged.
Each peer answers only within its own policy.

> **Why it's revolutionary:** private, permissioned, federated "search my entire mesh" —
> Spotlight for a distributed org, with no central index and nothing exposed.

### F5 · Continuity — agent & session handoff
Reuse the **migratable session** layer (proven: gw1 crash → gw2 rehydrates) to hand a *live*
agent session — with its context and in‑flight state — from one device / agent / gateway to
another by identity. Start a task on your laptop, hand it to a server or a teammate's agent
mid‑run.

> **Why it's revolutionary:** Apple‑Continuity‑style handoff for AI agents, over a
> zero‑exposure mesh.

### F6 · Verifiable AI answers — signed provenance receipts
Every RAG/KG answer ships with a signed receipt: which triples / documents were retrieved,
under which identity, at which ledger sequence — replayable via `replay.go`.

> **Why it's revolutionary:** "prove what context produced this answer" becomes a
> cryptographic guarantee, not a log you have to trust. Compliance‑grade explainability.

### F7 · Taint‑contained RAG — network‑layer prompt‑injection defense
Reuse `taint_source` / `taint_guard`: a retrieval that pulls untrusted documents marks the
session tainted, blocking downstream egress / write tools *at the network layer, where no
jailbreak reaches*.

> **Why it's revolutionary:** the first RAG stack whose prompt‑injection containment is
> enforced below the model.

### F8 · Time‑travel — bitemporal, tamper‑evident knowledge
Because the ledger already hash‑chains every record with a sequence number, the KG / memory
is inherently versioned: query "as of" any checkpoint, diff knowledge over time, prove no
retroactive edits.

> **Why it's revolutionary:** a knowledge base you can rewind and *prove* was never silently
> altered.

### F9 · Shared agent‑memory fabric
A mesh‑wide, identity‑scoped long‑term memory MCP server: agents write / read memories
stamped with identity + labels; policy governs cross‑agent sharing; sync rides resumable
sessions.

> **Why it's revolutionary:** a fleet‑wide brain agents can hand off to each other —
> governed and auditable.

### F10 · Universal clipboard + push‑to‑agent
The persistent E2E channel carries small payloads instantly between your own identities: a
universal clipboard across your devices, and a way to *push* a task, a KG delta, or a file
to any agent / device by identity — through CGNAT, no Firebase, no polling.

> **Why it's revolutionary:** Apple‑Universal‑Clipboard reach for an entire self‑hosted
> agent fleet.

### F11 · Content‑addressed artifact mesh — a private distributed CDN
Extend F1 into a BitTorrent‑like content‑addressed store: request a blob by hash, any peer
holding it serves it, integrity verified by hash, dedup automatic.

> **Why it's revolutionary:** a private, identity‑gated distributed CDN for datasets, model
> weights, and build artifacts — no S3, no exposed endpoint.

### F12 · Cross‑org knowledge & tool exchange — a governed marketplace
Extend `federation/` so orgs share vetted KG subgraphs / RAG corpora / tools across the trust
seam, identity‑mapped, capability‑gated, metered, and audited on both sides.

> **Why it's revolutionary:** a B2B knowledge/tool marketplace where access is a mintable
> grant and every use is attributable — with no public surface.

---

## Supporting tier — high value, lower lift (mostly primitive reuse)

| # | Idea | Reuses |
|---|------|--------|
| **S1** | **First‑class binary/blob MCP content** — `mcp/` emits text only; add blob/image/audio + resource streaming. *Foundational enabler for F1–F4, F11.* | `mcp/server.go`, `protocol/content/` |
| **S2** | **Personal knowledge vault** synced across *your* devices (AirDrop "My Devices"), E2E, no third party. | `session/`, `mesh.go` |
| **S3** | **GraphRAG bridge** — entity‑centric retrieval walks the KG (F2), then pulls documents (F3). | F2 + F3 |
| **S4** | **Signed knowledge capabilities** — short‑lived grants to a KG subgraph or corpus ("agent X may query `legal` until 17:00"). | `capabilitycmd.go` |
| **S5** | **Semantic policy from embeddings** — cluster tool calls by similarity, propose *semantic* least‑privilege rules over glob patterns. | `insight/` |
| **S6** | **Cost & quota governance** for RAG/LLM tools — token‑bucket + cost accounting, denied‑by‑budget inline. | `policy/` (VISION phase 5) |
| **S7** | **Embedding / vector‑shard compute mesh** — run an index shard as a dark peer; queries route to the nearest via the router. | `router.go` (VISION compute mesh) |
| **S8** | **Offline‑first CRDT knowledge sync** — peers edit the KG offline; CRDT reconcile on reconnect, reconciliation audited. | `session/`, `policy/` |
| **S9** | **Multiplayer Control‑Room knowledge canvas** — humans + agents co‑edit a live graph and drag‑drop files to AirDrop them. | `room.go` |
| **S10** | **Natural‑language mesh ops** — "share these files with Alice's laptop" / "give the analyst read access to the legal corpus until 5pm", attributed and audited. | `mcpapp.go` |

*Flagship F1–F12 + supporting S1–S10 = 22 grounded ideas.*

---

## Recommended build order

AirDrop leads, then the knowledge features, each riding primitives that already exist:

1. **S1 — blob/binary content** in `mcp/` — foundational; small, well‑tested surface.
2. **F1 — `meshmcp drop` + `meshmcp peers`** — new `drop.go` / `peers.go`, reusing
   `session/{frame,store,endpoint}.go`, `mesh.go` (`client.Dial` / `ListenTCP`), `policy/`
   (gate the drop by sender identity), `audit.go` (hash each file into the ledger). Ships with
   `examples/drop.yaml` and docs.
3. **F3 RAG + F2 KG** — new `cmd/vectors/` and `cmd/kg/` MCP backends on `mcp/`, governed by
   the existing firewall **unmodified** (the natural insertion point both explorations found).
4. **F7 taint‑aware RAG + F6 verifiable answers** — pure reuse of `policy/` taint + `replay.go`;
   cheap to build, outsized story.

## Design invariants these must honor

1. **No open ports, ever** — payloads ride the mesh interface only.
2. **Identity is cryptographic, never claimed** — a triple, a file, a retrieval is stamped with
   the WireGuard key the transport proves.
3. **Deny is the safe default** — knowledge and files are allowlisted, like tools.
4. **Audit is a control, not best‑effort** — every drop, assertion, and retrieval is a ledger
   record; an unopenable sink is a hard error.

---

<sub>Ideation map for meshmcp · © Rey Darius · see <a href="VISION.md">VISION.md</a> for the grounded roadmap.</sub>
