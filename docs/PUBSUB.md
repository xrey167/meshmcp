# Pub/Sub — the identity-native event fabric

meshmcp governs *tool traffic*. The same primitives — a cryptographic identity
for every caller, deny-by-default policy, data-flow taint, and a hash-chained
audit — also make it a governed **event bus**. `meshmcp pubsub` runs a broker on
the mesh; peers `publish` events to topics and `subscribe` to them by identity.
No open ports, no broker account, no central index.

It is a bus that no ordinary message queue can be:

- **Every event is attributable.** An event is stamped with the WireGuard key
  the transport proved — not a claimed `producer_id`. "Who published what, when"
  is cryptographic.
- **Delivery is authorized per topic, deny by default.** A publish or a
  subscribe to a topic the caller's identity is not granted is refused, inline,
  the same way the firewall refuses an ungranted tool call.
- **Taint is contained at the bus, below the model.** An event marked tainted
  (e.g. anything a crawler publishes to `web.*`) is delivered only to
  subscribers explicitly cleared for it. A prompt-injection payload cannot ride
  the bus into an uncleared agent, because the network layer never hands it over.
- **The stream is tamper-evident.** Events are hash-chained exactly like the
  audit ledger: each carries a monotonic sequence, the previous event's hash,
  and its own. Editing, reordering, or dropping any event is detectable.
- **It survives roaming.** Delivery rides the resumable session layer, so a
  subscriber that changes networks resumes its stream; `--since` replays events
  it missed from the broker's retention window.

---

## Commands

```
meshmcp pubsub    --config broker.yaml                run a broker on the mesh
meshmcp publish   [flags] <peer-ip:port> <topic>      publish one event
meshmcp subscribe [flags] <peer-ip:port> <topic...>   stream events to stdout
```

Publish reads its payload from stdin (or `--data`), wraps it as a JSON string
unless `--json` is set, and attaches any `--label`s:

```sh
echo '{"level":"warn","msg":"disk 90%"}' | meshmcp publish --json 100.x.y.z:9120 alerts.prod
meshmcp publish --data "deploy started" --label pii 100.x.y.z:9120 ops.deploys
```

`--stream` turns publish into a producer feed: one event per stdin line over a
single session (one mesh join for the whole feed), instead of one event per run:

```sh
tail -F app.log | meshmcp publish --stream 100.x.y.z:9120 logs.app
```

Subscribe streams matching events as newline-delimited JSON and blocks until
Ctrl-C. Topics are globs; `--since` replays retained events first:

```sh
meshmcp subscribe 100.x.y.z:9120 'alerts.*' 'ops.*'
meshmcp subscribe --since 41 100.x.y.z:9120 'alerts.prod'
```

## Durability

By default the bus is a live tap: events live in a bounded in-memory ring.
Set `event_log:` in the broker config to make it an **event log** instead:

```yaml
event_log: ./pubsub-events.jsonl
```

Each sealed event is appended to that file in sequence order. On restart the
broker resumes the **sequence and hash chain** from the log and preloads the
replay window, so `--since` works across restarts and the chain is continuous.
Because the events are hash-chained like the audit ledger, the persisted stream
is externally verifiable — a tampered, reordered, or truncated log is detected:

```sh
meshmcp pubsub verify ./pubsub-events.jsonl
# OK: 12043 event(s), hash chain verified (through seq 12043)
```

Persistence is best-effort per event (direct appends, no fsync — durable across
a process restart, like the audit ledger), and a torn trailing write from a
crash mid-append is tolerated on load; any interior break is a hard error.

---

## The broker config

See [`examples/pubsub.yaml`](../examples/pubsub.yaml) for a complete, commented
file. Two layers of authorization, mirroring the gateway:

- **`allow`** — a connection ACL: which mesh peers may open a pub/sub session at
  all (FQDN globs or `pubkey:<key>`; empty = any mesh peer).
- **`policy`** — per-topic authorization, deny by default. First matching rule
  wins. A rule grants a set of `peers` a set of `topics` for publish and/or
  subscribe, and carries the label semantics:

  | Field | Applies to | Meaning |
  |-------|-----------|---------|
  | `allow` | both | grant (or, `false`, explicit deny) |
  | `taint` / `emit_labels` | publish | labels stamped onto events this rule allows |
  | `clear_labels` / `clear_taint` | subscribe | labels this subscriber may receive |
  | `clear_all` | subscribe | receive events regardless of label (fully trusted) |

  A subscription that spans several topics gets the **intersection** of their
  clearances — never more cleared than its least-cleared topic.

```yaml
policy:
  default_allow: false
  rules:
    - peers: ["crawler.netbird.cloud"]     # crawler publishes tainted web events
      topics: ["web.*"]
      allow: true
      taint: true
    - peers: ["analyst-*.netbird.cloud"]   # analysts see everything, incl. tainted
      topics: ["*"]
      allow: true
      clear_all: true
    - peers: ["pubkey:AbCdEf..."]          # services: own namespace, NOT cleared for taint
      topics: ["alerts.*"]
      allow: true
```

---

## Hardening — the invariants the broker enforces

The bus is security-critical, so most of its surface is guarantees, not
features. The core (`pubsub/`) is transport-agnostic and every invariant below
is covered by `go test -race`:

| Invariant | How |
|---|---|
| **Deny by default** | Publish and subscribe both refused unless a rule grants the identity+topic; a nil authorizer denies everything. |
| **Identity never claimed** | A caller whose WireGuard key the transport could not prove (empty identity) is refused before authorization — at the broker connection boundary and again in the core — so it can never match a rule with no explicit `peers:` restriction. |
| **Attributable & ordered** | Each event sealed under lock with a monotonic sequence and the publisher's proven key. |
| **Tamper-evident** | Hash chain over every event; `VerifyChain` (and `meshmcp audit`) detect edits/reorders/drops. |
| **Taint containment** | An event is delivered to a subscription only if it is cleared for *every* label the event carries. |
| **Bounded memory** | Fixed per-subscriber buffers; a per-event payload cap (`max_payload_bytes`) bounds retention at `retain × cap`; `Backpressure` is `drop_oldest` (evict + count) or `disconnect` (close, resume via `--since`). |
| **Fan-out isolation** | Delivery is non-blocking, so one slow subscriber never stalls the publisher or other subscribers. |
| **Rate limiting** | Per-peer token bucket over **publish *and* subscribe**, charged *before* authorization and audit, so a connected-but-unauthorized peer cannot amplify CPU/disk/lock load by flooding rejected requests. Bounded by default (`publish_rate: 0` → 200/s; `-1` → unlimited). |
| **Resource caps** | Hard bounds on subscriptions (global **and per-peer**, so one identity can't pin every slot), topics/subscription, topic length, labels/event, payload size, and per-frame size — checked before allocation. |
| **No silent caps** | Replay past the retention window sets `truncated`; dropped events are counted and surfaced. |
| **Audited** | Every allow/deny decision is a record in the shared hash-chained ledger (`audit_log`). |

## Gateway hooks — the firewall as a stream

Beyond hand-published events, the gateway itself can emit **its own policy
decisions** onto the bus (and/or a webhook), turning the firewall into an
observable event stream. Add a `hooks:` block to a `meshmcp serve` config
([`examples/hooks.yaml`](../examples/hooks.yaml)):

```yaml
hooks:
  events: ["deny", "cosign"]     # decisions to emit (topic "gateway.<outcome>")
  bus:                            # embedded broker on the mesh; peers subscribe
    listen_port: 9130
    allow: ["*.netbird.cloud"]
    policy: { default_allow: false, rules: [ ... ] }
  webhook:                        # and/or POST each event as JSON
    url: https://siem.example.com/ingest/meshmcp
    auth_header: "Bearer ${SIEM_TOKEN}"
```

Every policy decision then flows to `gateway.deny` / `gateway.cosign` /
`gateway.allow`. Watch it live from any authorized peer:

```sh
meshmcp subscribe <gateway-mesh-ip>:9130 'gateway.*'
```

Hooks are **strictly observability, decoupled from enforcement**: the emit path
never blocks or fails a decision — it drops onto a bounded queue and a worker
fans out, so a slow or dead sink can never delay the request path. Only decision
metadata is emitted (backend, peer, method, tool, reason, rule, audit sequence)
— never tool arguments, payloads, or injected secrets. Internal emission is
sealed into the same hash chain and audited, but bypasses per-topic publish
authorization (the gateway is the broker operator). A webhook to a public URL
sends that metadata off the mesh, so it is explicit and opt-in.

## Wire protocol

The wire protocol is newline-delimited JSON over the resumable session
transport; a client sends one `{"role":"pub"|"sub", ...}` hello frame, then
either publishes (one frame in, one ack out) or streams events.
