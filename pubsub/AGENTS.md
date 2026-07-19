<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-18 | Updated: 2026-07-18 -->

# pubsub

## Purpose
meshmcp's identity-native event fabric: a publish/subscribe bus where every event is stamped with the publisher's cryptographic mesh identity, delivery is authorized per topic by that identity (deny by default), data-flow labels contain tainted events at the bus (not just at the model), and the whole event stream is hash-chained so it is tamper-evident like the audit ledger. The package is the **pure, transport-agnostic core** — it knows nothing about the mesh, the session layer, or the wire protocol, so every hardening invariant is exercised deterministically under `go test -race`. The mesh wiring (the broker daemon and the `meshmcp publish` / `subscribe` clients) lives in the root package (`pubsub.go`, `pubsubwire.go`) and drives this core.

## Key Files
| File | Description |
|------|-------------|
| `pubsub.go` | Package doc, `Identity`, `Event` + the tamper-evident hash chain (`VerifyChain`), `Backpressure` policy, sentinel errors. |
| `broker.go` | `Broker`: authorize → rate-limit → seal (seq + hash) → retain → fan out. Resource `Limits`, `Publish`/`Subscribe`/`Close`, non-blocking `deliverLocked`, `fanoutLocked` (ungrouped copy-to-all + consumer-group round-robin), audit integration. |
| `subscription.go` | `Subscription`: the per-subscriber delivery stream (`C()`), label-clearance `accepts`, `group` membership, drop/truncation counters. |
| `authorizer.go` | `Authorizer` interface; `RuleAuthorizer` (deny-by-default topic ACL with emit/clear labels, YAML-configured); `AllowAll`. Decisions carry `Explicit` so a signed capability upgrades only a *default* deny. |
| `ratelimit.go` | Per-publisher token-bucket limiter with an injected clock. |
| `ring.go` | Bounded retention ring for `--since` replay; surfaces `truncated` rather than silently short-serving. |
| `eventlog.go` | Durable append-only event log: `EventLog` (append sink + optional signed Merkle `Checkpointer`) + `LoadEvents` (chain-verified, torn-tail-tolerant) + `VerifyCheckpoints`. Seeds `seq`/`prev`/ring on restart via `Options.Seed`; the chain is externally verifiable and, with a signing key, non-repudiable. |

## For AI Agents

### Working In This Directory
- **Fail closed.** A nil `Authorizer` denies everything; an unknown backpressure string is an error; a publish/subscribe to an ungranted topic is refused. Preserve these — do not add an ambient allow.
- **Rate-limit before work.** `Publish` charges the per-publisher token bucket *before* authorization, validation, or audit, so rejected floods cannot amplify CPU/disk/lock load; rate-limited attempts are dropped without an audit record. Keep this ordering. Rate is bounded by default (`PublishRate: 0` → default; negative → unlimited).
- **Reject unproven identity.** Both `Publish` and `Subscribe` fail closed on an empty `Identity.Key` (the transport could not prove a WireGuard key), so an unproven caller can never match a rule with no `peers:` restriction. The daemon also rejects such connections up front. One audit record per subscribe (not per topic) keeps the ledger unfloodable.
- **The hash chain is a control.** `Publish` seals each event under `b.mu` (monotonic `Seq`, `PrevHash`, `Hash`); never reorder or mutate a sealed event. `VerifyChain` must stay able to detect edits, reorders, and drops.
- **Fan-out never blocks.** `deliverLocked` is non-blocking: on a full buffer it applies the subscription's `Backpressure` (DropOldest increments `Dropped`; Disconnect closes it). One slow reader must never stall the others or the publisher. Delivery is under `b.mu`, so ordering is deterministic.
- **Consumer groups route below containment.** `fanoutLocked` delivers each event to every accepting *ungrouped* subscription and to exactly one round-robin member of each *group* — but only among members that `accepts` the event, so taint clearance is enforced *before* group selection (an uncleared member is never a candidate). Groups are live-only (no `--since`/retained, which would duplicate across competing consumers); per-group cursor state (`groupRR`/`groupN`) is reclaimed when the last member leaves. Keep group state bounded to live groups.
- **Taint is contained below the model.** An event is delivered to a subscription only if the subscription is cleared for every label the event carries (`Subscription.accepts`). A multi-topic subscription's clearance is the **intersection** across its topics (least privilege).
- **No silent caps.** Replay that can't reach the requested sequence sets `Truncated`; dropped events increment `Dropped`. Surface both to the caller.
- **Bounded memory.** Retention holds full event payloads, so `Publish` caps payload size (`Limits.MaxPayloadBytes`); `Retain × MaxPayloadBytes` is the broker's memory bound. Keep any new buffering bounded the same way.

### Testing Requirements
- `CGO_ENABLED=1 go test ./pubsub/ -race`. The suite covers deny-by-default, ordering, hash-chain tamper detection, both backpressure policies, rate limiting (fake clock), resource caps, label/taint containment, replay + truncation, fan-out isolation, consumer-group load balancing (+ containment/leave/replay-rejection), and a concurrent fuzz.
- Time-dependent tests inject a clock via `Options.Now`; keep new time-sensitive logic clock-injectable.

## Dependencies

### Internal
- `meshmcp/policy` — `AuditLog` for the optional hash-chained decision record (nil-safe). Consumed by the root package's `pubsub`/`publish`/`subscribe` commands.

### External
- Standard library only.
