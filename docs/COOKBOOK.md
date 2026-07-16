# meshmcp cookbook — what's possible, by example

Worked, copy-paste scenarios. Each shows the goal, the config or commands, and a
diagram of what happens. Every scenario runs on one `meshmcp` binary; mesh
credentials come from `$NB_SETUP_KEY` or `--setup-key`.

> A visual tour of the same material: the [capabilities showcase](https://claude.ai/code/artifact/063e5ce2-bc4d-42b4-bc8e-a777a803ce75).

**Contents**
1. [Share a local tool with your team — expose nothing](#1-share-a-local-tool-with-your-team--expose-nothing)
2. [Stop prompt injection at the network layer](#2-stop-prompt-injection-at-the-network-layer)
3. [Never let PII leave the mesh](#3-never-let-pii-leave-the-mesh)
4. [Give an agent a credential it never holds](#4-give-an-agent-a-credential-it-never-holds)
5. [Prove to an auditor what every agent did](#5-prove-to-an-auditor-what-every-agent-did)
6. [Generate a least-privilege policy from real traffic](#6-generate-a-least-privilege-policy-from-real-traffic)
7. [Require a human co-sign for money movement](#7-require-a-human-co-sign-for-money-movement)
8. [Survive a gateway crash mid-session](#8-survive-a-gateway-crash-mid-session)
9. [Aggregate many servers into one endpoint](#9-aggregate-many-servers-into-one-endpoint)
10. [Bridge two organizations](#10-bridge-two-organizations)

---

## 1. Share a local tool with your team — expose nothing

**Goal:** run an MCP server that teammates can reach, with no public port.

```yaml
# backends.yaml
mesh: { device_name: home-gw, setup_key_env: NB_SETUP_KEY }
backends:
  - name: fs
    port: 9101
    stdio: ["./mcpserver", "--root", "."]
```

```bash
meshmcp serve --config backends.yaml        # prints a mesh IP, e.g. 100.81.5.9
# from any other machine on the mesh:
meshmcp ls   100.81.5.9:9101
meshmcp call 100.81.5.9:9101 add --arg a=2 --arg b=40   # → 42
```

```mermaid
flowchart LR
  A["teammate<br/>meshmcp call"] -- WireGuard mesh --> G["meshmcp gateway<br/>:9101 (mesh-only)"]
  G --> B["fs MCP server<br/>stdio, unmodified"]
  I(("internet<br/>nmap")) -. "nothing to find" .- G
```

To use it from Claude Code, add a stdio bridge:

```jsonc
{ "mcpServers": { "home": {
  "command": "meshmcp",
  "args": ["connect", "--resumable", "100.81.5.9:9101"],
  "env": { "NB_SETUP_KEY": "<key>" } } } }
```

---

## 2. Stop prompt injection at the network layer

**Goal:** an agent that reads untrusted web content must not be able to perform a
privileged write, even if the content jailbreaks it.

```yaml
policy:
  default_allow: false
  rules:
    - peers: ["*"]              # fetch brings untrusted data in
      tools: ["fetch", "http_*"]
      allow: true
      taint_source: true
    - peers: ["*"]              # writes are blocked once the session is tainted
      tools: ["write_file", "run_command"]
      allow: true
      taint_guard: true
```

The decision is made from connection state the model can't see or influence, so
there is nothing to jailbreak.

```mermaid
sequenceDiagram
  participant A as agent
  participant G as meshmcp gateway
  participant B as backend
  A->>G: tools/call fetch(...)
  G->>B: allowed (taint_source) — session now TAINTED
  B-->>A: untrusted content (may contain injected instructions)
  A->>G: tools/call write_file(...)
  G--xA: BLOCKED — "session tainted by untrusted data"
  Note over G,B: the write never reaches the backend
```

---

## 3. Never let PII leave the mesh

**Goal:** data read from an internal tool may not flow to an external egress tool.

```yaml
policy:
  default_allow: false
  rules:
    - peers: ["*"]                      # reading customer data tags the session
      tools: ["read_customer"]
      allow: true
      emit_labels: ["pii"]
    - peers: ["*"]                      # egress refuses once pii is present
      tools: ["post_external", "email_*"]
      allow: true
      block_labels: ["pii"]
```

```mermaid
flowchart LR
  R["read_customer()"] -->|allow · emit pii| S["session labels: {pii}"]
  S --> P["post_external()"]
  P -->|block_labels pii| X["DENIED"]
  style X fill:#5a1a1a,stroke:#ff5c5c,color:#fff
```

No LLM guardrail or ordinary firewall can express a *flow* constraint like this.

---

## 4. Give an agent a credential it never holds

**Goal:** an agent calls a paid API without ever seeing the API key.

```yaml
# secrets.yaml (excerpt) — store values out of band, never in the config
backends:
  - name: payments
    port: 9120
    stdio: ["./mcpserver"]
    policy: { default_allow: false, rules: [ { peers: ["*"], tools: ["charge"], allow: true } ] }
    secrets:
      file: ./secrets.json          # {"stripe_key":"sk_live_..."}  (chmod 600)
      grants:
        - peers: ["pubkey:<billing-agent-key>"]
          secrets: ["stripe_key"]
          tools: ["charge"]
          block_labels: ["tainted"]  # no credential for a tainted session
```

The agent writes `{{secret:stripe_key}}` in the tool arguments; the gateway
resolves it by identity.

```mermaid
sequenceDiagram
  participant A as agent
  participant G as gateway (broker)
  participant B as backend
  A->>G: charge { auth: "Bearer {{secret:stripe_key}}" }
  Note over G: authorize by identity · refuse if tainted · audit "stripe_key: injected"
  G->>B: charge { auth: "Bearer sk_live_…" }
  Note over A,G: trace & audit record only the reference — never the value
```

Validate without revealing anything: `meshmcp secrets check --config secrets.yaml`.

---

## 5. Prove to an auditor what every agent did

**Goal:** a tamper-evident, non-repudiable record of every tool call.

```yaml
backends:
  - name: guarded
    port: 9104
    stdio: ["./mcpserver"]
    audit_log: ./audit.jsonl
    audit_checkpoints: ./cps.jsonl       # Ed25519-signed Merkle checkpoints
    audit_signing_key: ./signing-key.json
    policy: { default_allow: false, rules: [ { peers: ["*"], tools: ["read_*"], allow: true } ] }
```

```bash
meshmcp audit keygen --out signing-key.json     # once; publish the public key
# ... run traffic ...
meshmcp audit verify audit.jsonl --checkpoints cps.jsonl --pubkey <key>
# OK  1240 records, 10 signed checkpoint(s), 1240 records committed
```

```mermaid
flowchart LR
  r1["seq 1<br/>hash 9f9d…"] --> r2["seq 2<br/>prev 9f9d…"] --> r3["seq 3<br/>prev e8f0…"]
  cp{{"signed checkpoint<br/>Merkle root · Ed25519 sig"}}
  r1 -.-> cp
  r2 -.-> cp
  r3 -.-> cp
```

Edit any record — even re-linking the whole chain — and the recomputed Merkle
root no longer matches the **signed** root. It can't be forged without the key.

---

## 6. Generate a least-privilege policy from real traffic

**Goal:** don't hand-write a deny-by-default allowlist — learn one, then prove
it's safe before enforcing.

```bash
meshmcp insight profile   audit.jsonl                       # what agents actually do
meshmcp insight recommend audit.jsonl > policy.yaml          # least-privilege policy
meshmcp insight simulate  audit.jsonl --policy policy.yaml   # CI gate: exit ≠ 0 on regressions
meshmcp insight detect    today.jsonl --baseline last-week.jsonl   # drift → open a co-sign
```

```mermaid
flowchart LR
  O["observe<br/>profile"] --> R["recommend<br/>policy.yaml"] --> S["simulate<br/>CI gate"] --> E["enforce"]
  E --> D["detect<br/>drift → co-sign"]
  D -. new behavior .-> O
```

The recommended policy is guaranteed not to deny the traffic it was learned from
(a tested invariant); `simulate` catches any regression a *change* would cause.

---

## 7. Require a human co-sign for money movement

**Goal:** a privileged call is held until a human identity on the mesh approves it.

```yaml
policy:
  rules:
    - peers: ["*"]
      tools: ["transfer_funds"]
      allow: true
      require_cosign: true
# backend also sets: cosign_store: ./cosign
```

```bash
# the agent's call is held (denied with "requires a human co-sign") until:
meshmcp approve --store ./cosign <agent-fqdn> transfer_funds
# co-signed: <agent-fqdn> may call "transfer_funds" (approver: alice)
```

Approvals are identity-attributed, optionally expiring (`cosign_ttl_seconds`),
and revocable (`--revoke`). Silence is not permission.

---

## 8. Survive a gateway crash mid-session

**Goal:** a logical MCP session survives a gateway failover, without the client noticing.

```yaml
backends:
  - name: kg
    port: 9101
    stdio: ["./mcpserver"]
    resumable: true
    session_store: ./sessions      # shared between gateway replicas
```

```mermaid
sequenceDiagram
  participant C as client (--resumable)
  participant G1 as gateway A
  participant G2 as gateway B
  participant S as shared store
  C->>G1: session, acked to seq N
  G1->>S: checkpoint on every ack
  Note over G1: 💥 crash
  C->>G2: reattach
  G2->>S: rehydrate (owner lease)
  G2-->>C: replay missed messages — exactly-once, in order
```

Checkpoints are ack-consistent and guarded by a cross-process ownership lease, so
failover is race-free.

---

## 9. Aggregate many servers into one endpoint

**Goal:** present N backends as one namespaced MCP endpoint with load-balancing and failover.

```yaml
# router.yaml
mesh: { device_name: router }
registry: ./registry            # discover backends dynamically
upstreams:
  fs:    ["100.81.5.9:9101"]
  tools: ["100.81.5.9:9102", "100.81.6.2:9102"]   # replica set
```

```bash
meshmcp router --config router.yaml
meshmcp ls   100.81.7.1:9100          # union: fs.read_file, tools.add, …
meshmcp call 100.81.7.1:9100 tools.add --arg a=2 --arg b=40
```

```mermaid
flowchart LR
  C["client"] --> R["router :9100<br/>namespaced union"]
  R --> F["fs :9101"]
  R --> T1["tools :9102 (A)"]
  R --> T2["tools :9102 (B)"]
  R -. health-check + failover .- T1
```

Round-robins replicas, fails over on transport error, re-dials down replicas in
the background, and relays full bidirectional MCP (sampling/elicitation).

---

## 10. Bridge two organizations

**Goal:** let another org's agents call *specific* tools of yours — no public endpoint on either side.

```yaml
# federate.yaml
port: 9300
upstream: 100.64.0.10:9101          # your local MCP server
audit: ./federation-audit.jsonl
mappings:
  - { match: "pubkey:<acme-gw-key>", org: acme, principal: "partner:acme" }
grants:
  - { org: acme, tools: ["read_*", "search"] }   # only these cross
```

```mermaid
flowchart LR
  RA["acme agent<br/>(their mesh)"] -->|federation link| BD["boundary :9300<br/>map identity · grant · audit"]
  BD --> UP["your MCP server<br/>read_* only"]
  BD -. every crossing audited .-> L[("hash-chained log")]
```

An unrecognized caller maps to no org and sees nothing; each org may call only
its granted tools; every crossing is identity-stamped and recorded.

---

## Where to go next

- **[AGENT-FIREWALL.md](AGENT-FIREWALL.md)** — the policy engine, signed audit, dashboard, replay, control plane, federation.
- **[INSIGHT.md](INSIGHT.md)** — observe → recommend → simulate → detect.
- **[SECRETS.md](SECRETS.md)** — the credential broker and its threat model.
- **[spec/](spec/)** — the open audit-record and policy-DSL specs, with JSON Schemas.
- **[../examples/](../examples/)** — the full annotated config files these snippets are drawn from.
