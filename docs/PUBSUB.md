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
meshmcp request   [flags] <peer-ip:port> <topic>      publish a request, wait for the reply (RPC)
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

`--retain` stores the event as the topic's **last-value**, so a subscriber that
connects later immediately receives the current state (MQTT-style retain).
`--file` publishes a file's bytes as a **base64 binary payload** (the event
carries `"enc":"base64"` so consumers know to decode):

```sh
meshmcp publish --retain 100.x.y.z:9120 state.thermostat --data '{"c":21}'
meshmcp publish --file model.bin 100.x.y.z:9120 artifacts.model
```

A retained value can **expire** (`--retain-ttl`, so stale state like presence
isn't served to a late subscriber) or be **cleared** (`--unretain`, an MQTT-style
tombstone — the clear still reaches current subscribers, but future ones get no
retained value):

```sh
meshmcp publish --retain --retain-ttl 5m 100.x.y.z:9120 state.presence --data '"online"'
meshmcp publish --unretain 100.x.y.z:9120 state.presence   # clear it
```

Subscribe streams matching events as newline-delimited JSON and blocks until
Ctrl-C. Topics are globs; `--since` replays retained events first:

```sh
meshmcp subscribe 100.x.y.z:9120 'alerts.*' 'ops.*'
meshmcp subscribe --since 41 100.x.y.z:9120 'alerts.prod'
```

`--group <name>` joins a **consumer group**: each event is delivered to exactly
one member of the group instead of to every subscriber, so a pool of workers
shares the load (competing consumers). Ungrouped subscribers still each get their
own copy:

```sh
# three workers share the jobs.* stream; each event goes to one of them
meshmcp subscribe --group workers 100.x.y.z:9120 'jobs.*'   # run on each worker
```

Delivery is **capacity-aware**: an event goes to the next member with buffer
room, so a busy/slow member is skipped in favor of an idle one rather than
dropped on. Taint containment still holds — an event is only ever routed to a
member cleared for its labels (containment is applied *before* group selection).

**At-least-once** groups add `--ack`: an event delivered to a member is held
in-flight until the member acks it, and **redelivered to another member** if that
one disconnects first — so a crashed or rolling worker loses no work. The
`respond` RPC worker acks a request only after its handler succeeds, so a pool of
`respond --group <g> --ack` workers is a reliable job queue (a failed/crashed
handler's job is retried on a sibling). When every member is at its in-flight cap,
further events are held in a **bounded per-group backlog** (`max_group_pending`;
oldest dropped and counted if it overflows) and drain as members ack. Duplicates
are possible if a member dies mid-processing — at-least-once, by design.

A group is live-only and scoped to **one broker**: `--since` replay is not
combined with `--group` (replaying a window to every competing consumer would
duplicate it), and a group spanning two *federated* brokers gets one delivery
**per broker** (federation mirrors independently — it does not coordinate a global
group). At-least-once holds across worker churn while the group keeps ≥1 member;
if the **last** member leaves holding un-acked work, that work can't be
redelivered live (it is counted, not silently lost) — recover it with the durable
`event_log:` plus a `--durable` non-group consumer.

`--durable <file>` makes a subscriber **at-least-once**: it persists the
last-seen sequence to the file and resumes from it, so with a broker `event_log:`
no events are missed across a disconnect or a broker restart (a duplicate is
possible if a crash lands between delivery and the cursor write — at-least-once,
not exactly-once):

```sh
meshmcp subscribe --durable ./alerts.cursor 100.x.y.z:9120 'alerts.prod'
```

## Request/reply (RPC over the bus)

`meshmcp request` turns the bus into an **identity-native RPC transport**: it
publishes a request and blocks for the correlated reply. Because the request and
the reply are both ordinary events, every RPC is attributable (stamped with the
caller's proven key), authorized per topic (deny by default), taint-contained,
and hash-chained — guarantees no ordinary RPC has:

```sh
echo '[2,3]' | meshmcp request --json 100.x.y.z:9120 rpc.add    # prints the reply
```

A **responder** turns a program into a governed RPC service. `meshmcp respond`
runs a handler command per request — the request payload on its stdin — and
publishes the handler's output back to the event's `reply_to` with the same
`corr`:

```sh
# answer rpc.add by summing the JSON array in each request
meshmcp respond --json 100.x.y.z:9120 rpc.add -- jq 'add'
```

Run several with `--group` and they become a **pool of competing RPC workers**
(the request load is shared, one request per worker) — parallelism is "run more
of me". Add `--ack` for a **reliable job queue**: a request is acked only after
the handler succeeds, so a crash redelivers it to a sibling worker (at-least-once)
instead of losing it. Without `--ack`, a failed handler still returns a reply
(its error text), so an RPC caller gets a reply or a timeout, never silence. (A
responder is just a subscribe + publish, so the shell `while read` equivalent
works too, using `publish --corr`.)

`request` allocates a private per-request reply topic by default
(`_rpc.reply.<id>`) and matches the reply by `corr`, so concurrent requests never
cross-talk; `--reply-topic` overrides it, `--timeout` bounds the wait, and
`--from <wg-key>` pins the reply to a specific responder's proven key (rejects a
reply from anyone else). RPC is still deny-by-default: **both parties must be
granted the reply namespace** — the requester to *subscribe* `_rpc.reply.*`, the
responder to *publish* it — so an RPC channel is an explicit policy grant, not
ambient. `request` returns the **first** matching reply (single-reply RPC;
scatter-gather across many responders is not built in).

## Durability

By default the bus is a live tap: events live in a bounded in-memory ring.
Set `event_log:` in the broker config to make it an **event log** instead:

```yaml
event_log: ./pubsub-events.jsonl
```

Each sealed event is appended to that file in sequence order. On restart the
broker resumes the **sequence and hash chain** from the log, preloads the replay
window, and **rebuilds retained last-values** (with their TTLs and tombstones)
from the stream, so `--since` and retained state both work across restarts and
the chain is continuous. Because the events are hash-chained like the audit
ledger, the persisted stream is externally verifiable — a tampered, reordered,
or truncated log is detected:

```sh
meshmcp pubsub verify ./pubsub-events.jsonl
# OK: 12043 event(s), hash chain verified (through seq 12043)
```

Persistence is best-effort per event (direct appends, no fsync — durable across
a process restart, like the audit ledger), and a torn trailing write from a
crash mid-append is tolerated on load; any interior break is a hard error.

For **non-repudiation**, add `event_signing_key:` + `event_checkpoints:` to emit
Ed25519-signed Merkle checkpoints over the stream (`meshmcp audit keygen` mints
the key). Then an insider who controls the log file can't rewrite history
without the signature disagreeing:

```sh
meshmcp pubsub verify --checkpoints pubsub-checkpoints.jsonl --pubkey <hex> pubsub-events.jsonl
# OK: 12043 event(s), hash chain + 94 signed checkpoint(s) verified (through seq 12043)
```

## Signed capability grants

Beyond the static `policy:` rules, a caller can present a **short-lived signed
capability** that grants a topic beyond the default-deny — access minted
out-of-band without editing the broker config. Set `name:` (the audience) and
`trusted_public_keys:` (pinned authorities) on the broker, then:

```sh
meshmcp capability keygen --out authority.json                     # once
meshmcp capability issue --key authority.json --subject <wg-key> \
  --audience alerts-bus --tool 'metrics.*' --ttl 8h > grant.tok
meshmcp subscribe --capability @grant.tok 100.x.y.z:9120 'metrics.*'
```

Like tool capabilities, a grant is bound to the caller's WireGuard key
(subject), one broker (audience), a set of topic globs, and a ≤24h window, and
it can **only upgrade a default-deny — never an explicit `allow: false`**. A
capability-granted topic carries no data-flow label clearance (it receives only
unlabeled events): the grant conveys access, not taint clearance.

## Federation

A single broker is a single point of failure. Run several and **federate** them:
a broker mirrors remote brokers' topics into its own, so a subscriber on one
broker also sees events published to another.

```yaml
federate:
  - peer: "100.64.0.6:9120"
    topics: ["alerts.*", "ops.*"]
```

Each mirrored event preserves its original publisher and is tagged with the
source broker (`origin`), so a bidirectional federation **cannot loop** — a
mirror is never re-mirrored. Taint labels are preserved across the hop, so
containment holds mesh-wide. **Retained** last-values (and their TTLs and
tombstones) also cross the hop — the retain intent rides the event — so a
subscriber on the downstream broker sees the current state a peer retained.
The remote broker must authorize this broker's identity to subscribe to the
mirrored topics (federation is a granted relation, not ambient). Mirroring is
best-effort live; pair it with `event_log:` + `--durable` subscribers for
at-least-once across a broker outage.

## Introspection

Query a running broker for a live snapshot:

```sh
meshmcp pubsub stats 100.x.y.z:9120
# subscriptions=7  groups=2  sequence=12043  retained=4096  dropped=12
```

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
