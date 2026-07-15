# The agent firewall, tamper-evident audit, dashboard, replay & control plane

This document covers the control-layer meshmcp adds on top of connectivity and
identity: **policy-as-code for what an agent may do, a provable record of what
it did, a way to see and re-run it, and a control plane to roll it out.** Each
piece is built and tested (`go test ./... -race`, 7 packages green).

The one idea underneath all of it: because the WireGuard key *is* the caller's
identity, every decision and every audit record keys off something the caller
cryptographically proved — not a header it can forge.

---

## 1. The policy engine (`policy/`)

The gateway already authorized `tools/call` by identity (allow/deny). The
engine turns that into a real capability language. A rule is still matched by
peer + tool (or method), but an **allow** rule can now carry constraints:

| Field | Meaning |
|---|---|
| `rate: {max, per}` | Token-bucket rate limit, **per identity** (e.g. `max: 30, per: "1m"`). |
| `when: {days, hours, tz}` | The rule only applies inside a day/hour window; outside it, evaluation falls through to the next rule. |
| `require_cosign: true` | The call is held as `cosign` until a human identity approves it (see §4). |
| `taint_source: true` | Making this call marks the session **tainted** (it brought in untrusted data). |
| `taint_guard: true` | This call is **blocked whenever the session is tainted**. |

Verdicts are three-valued — `allow`, `deny`, `cosign` — carried on
`policy.Decision.Outcome`, with a human-readable `Reason` that flows into both
the denial message and the audit record.

### Taint tracking = prompt-injection defense at the network layer

The classic agent attack: a tool pulls in web content, the content contains
injected instructions, and the agent is steered into calling a privileged tool.
No LLM-side guardrail can be *guaranteed* to catch this — a good jailbreak talks
past it.

meshmcp puts the boundary in the network. Mark data-fetching tools
`taint_source` and privileged tools `taint_guard`. Once an untrusted-source
call is made, the session is tainted and **the mesh simply will not route** any
guarded tool. The decision is made from connection state the model cannot see
or influence, so there is nothing to jailbreak.

Taint is per **session** (it lives on the `Filter`, one per connection). Rate
limits and co-sign are per **identity** and shared across a backend's
connections (they live on the shared `Engine`).

```
fetch()      → allow  (taint_source) ──► session now tainted
write_file() → DENY   "blocked: session tainted by untrusted data"
```

### 1a. Data-flow labels (generalized taint)

Taint is one bit; real data governance needs a lattice. A rule may
`emit_labels` (e.g. `["pii"]`, `["secret"]`) that attach to the session, and
`block_labels` that deny a call when the session carries them. `taint_source` /
`taint_guard` are sugar for the `"tainted"` label. This expresses controls no
LLM guardrail or ordinary firewall can — the canonical one being "PII may not
leave the mesh":

```yaml
- { peers: ["*"], tools: ["read_customer"], allow: true, emit_labels: ["pii"] }
- { peers: ["*"], tools: ["post_external"], allow: true, block_labels: ["pii"] }
```

Once `read_customer` runs, the session carries `pii` and `post_external` is
refused — enforced from data-flow state the model cannot influence. Full
grammar: [docs/spec/POLICY-DSL.md](spec/POLICY-DSL.md).

---

## 2. Tamper-evident audit (`policy/audit.go`, `policy/chain.go`)

Every audit record now carries `seq`, `prev_hash`, and `hash`, where
`hash = sha256(json(record with hash cleared))` and `prev_hash` links to the
record before it. The records form a hash chain: **edit, reorder, delete, or
insert anything and every hash after it breaks** — detectable without the
original.

```bash
meshmcp audit verify ./audit.jsonl
# OK  1240 records, chain intact
#     head 9f9d4849599df811…
# …or…
# TAMPERED  837 records read; chain breaks at seq 838
#           record seq 838 was edited: stored hash "e8f0…" != recomputed "26b2…"
```

`VerifyChain` returns the first offending `seq` and why. `LastLink` +
`SeedFrom` let a restarted process continue the same chain, so the guarantee
spans restarts. This is the "show me every tool call agent X made against
customer data last quarter, and prove the log wasn't edited" capability that
regulated buyers are *required* to have and that a plain log cannot provide.

### 2a. Signed + anchored checkpoints (non-repudiable)

A hash chain is tamper-*evident* but an insider who controls the whole file can
rewrite and re-link it. To close that, the gateway periodically emits an
**Ed25519-signed Merkle checkpoint** over a batch of records
(`policy/merkle.go`, `sign.go`, `checkpoint.go`):

```bash
meshmcp audit keygen --out audit-signing-key.json   # gateway signing key
# config: audit_checkpoints + audit_signing_key + audit_checkpoint_every
meshmcp audit verify audit.jsonl --checkpoints cps.jsonl --pubkey <key>
# OK  1240 records, 10 signed checkpoint(s), 1240 records committed
#     non-repudiable: the log is complete and unedited, provable with the public key alone
```

Because the Merkle root is *signed*, editing any covered record fails
verification (`Merkle root mismatch`) and the attacker cannot re-sign without
the private key — even with full write access to the file. Checkpoints
optionally **anchor** to an external witness (`audit_anchor`), defending even
against an insider who also holds the signing key. Full format:
[docs/spec/AUDIT-RECORD.md](spec/AUDIT-RECORD.md).

---

## 3. The dashboard (`meshmcp dash`, `policy/analyze.go`)

The trace is invisible until someone can see it. `meshmcp dash --audit <file>`
serves a self-contained (no external assets) HTML dashboard plus a
`/api/summary` JSON endpoint that reports, live:

- policy decision counts (allow / deny / co-sign),
- per-identity and per-tool rollups,
- the **identity → tool call graph**,
- recent activity with reasons,
- and the **chain-verification verdict**, so the view says at a glance whether
  the data it is showing can be trusted.

---

## 4. Human co-sign (`policy/cosign.go`, `meshmcp approve`)

A `require_cosign` call is held (`cosign` outcome, denied to the caller with an
explanation) until a human identity approves it out of band:

```bash
meshmcp approve --store ./cosign <peer-fqdn> transfer_funds
# co-signed: <peer-fqdn> may call "transfer_funds" (approver: alice)
```

Approvals are small identity-attributed JSON files in a shared directory
(`FileCosign`), optionally expiring (`cosign_ttl_seconds`) so a co-sign
authorizes a bounded window rather than forever. `--revoke` withdraws one.

---

## 5. Session replay / fork (`meshmcp replay`, `policy/replay.go`)

Because a trace (captured with `payloads: true`) holds every request's params
and every response's result, a past session can be deterministically re-issued
against a backend and **every response diffed** against what was originally
recorded:

```bash
meshmcp replay ./trace.jsonl 100.x.y.z:9110
#   #1   initialize            OK
#   #2   tools/call:add        DIFF   was {"text":"42"}  now {"text":"43"}
# replay complete: 4 requests, 1 divergence(s)
```

`--fork N` replays only the first N messages, then stops — fork the session at
message N and diverge against a different tool version. This is time-travel
debugging for agent runs.

---

## 6. Managed control plane (`meshmcp control`, `control/`)

So a team adopts the mesh without hand-wiring NetBird, registries, and policy
files on every node. The control plane runs as an ordinary mesh peer (no public
port, identity-checked callers) and serves:

| Route | Purpose |
|---|---|
| `POST /v1/enroll` | Hand a new node its management URL + setup key (+ shared registry). |
| `GET/POST/DELETE /v1/registry` | The service registry — who is on the mesh. |
| `GET/PUT /v1/policy/<name>`, `GET /v1/policies` | Publish and distribute named policies (validated before storing). |

```bash
meshmcp control --registry ./registry --policies ./policies \
                --enroll-key <netbird-setup-key>
```

The enroller is pluggable (`control.EnrollFunc`). `StaticEnroll` hands out a
fixed key; `NetBirdIssuer` (`control/netbird.go`) is the production backend — it
calls the NetBird management API to mint a **one-off, ephemeral, group-scoped**
setup key per node (auto-expiring, revocable) and writes every issuance to a
tamper-evident enrollment audit trail. Turn it on with `--netbird-token`.

---

## 7. Cross-org federation (`meshmcp federate`, `federation/`)

The network-effects layer: a **boundary** bridges named tools between two
independent meshes/orgs. Neither side exposes a public port. The boundary
(`federation/boundary.go`) maps a remote caller's cryptographic mesh identity to
a known **org**, admits only the tools that org is **granted**, stamps each
relayed call with the org's local **principal**, and **audits every crossing**
into a hash-chained log:

```yaml
mappings:
  - { match: "pubkey:<acme-gw-key>", org: acme, principal: "partner:acme" }
grants:
  - { org: acme, tools: ["read_*", "search"] }
```

An unrecognized caller maps to no org and sees nothing; an org may call only its
granted tools; every crossing is identity-attributed and recorded. This is
agent-to-agent B2B where each org you connect raises the switching cost for all
the others — worth starting small because it compounds.

---

## Design invariants (unchanged, extended)

1. **No open ports, ever** — the control plane and dashboard included (dashboard
   binds localhost by default; the control plane binds the mesh).
2. **Identity is cryptographic, never claimed** — policy, audit, and co-sign all
   key off the WireGuard identity the transport proves.
3. **Deny is the safe default** — policies are allowlists; a tainted session
   denies guarded tools; an unverifiable audit chain is a hard signal.
4. **Pure transport where possible** — the engine parses MCP only to authorize;
   any MCP server works unmodified.
