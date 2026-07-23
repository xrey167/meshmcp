# Performance

What each hot path costs, measured — so "calm under change" is a number, not a
vibe, and a regression is visible before it ships. These are **baselines from
one reference run**, not SLOs; absolute numbers vary with hardware, but the
*ratios* and the *shape* of the costs are the durable story.

Re-measure on your hardware:

```console
$ go test ./policy/  -bench . -benchmem -run '^$'
$ go test ./session/ -bench . -benchmem -run '^$'
```

## The per-call tax

Reference run (Intel Xeon @ 2.80GHz, linux/amd64, go1.26):

| Path | Cost | Allocations | What pays it |
|---|---:|---:|---|
| Policy decision (allow, 4-rule policy) | ~0.6 µs | 0 allocs | every governed `tools/call` |
| Policy decision (deny, default-deny miss) | ~0.5 µs | 0 allocs | every denied call |
| Audit append (hash + marshal, no I/O wait) | ~7 µs | 6 allocs | every audited decision |
| Audit append **with fsync** (the default) | ~770 µs | 6 allocs | every audited decision, durably |
| Chain verify, 1 000 records | ~7 ms | — | once per boot (`seedAuditFromExisting`) |
| Session checkpoint (FileStore save+load) | ~1.7 ms | 41 allocs | each ack-driven checkpoint of a resumable session |

## How to read it

- **The firewall itself is effectively free.** A policy decision is
  sub-microsecond and allocation-free — three orders of magnitude below any
  network hop. Adding rules costs nanoseconds each; you will never feel the
  policy engine.
- **Durability is the one real per-call cost, and it is a knob.** The default
  `audit_fsync: true` makes each audited decision survive power loss and caps
  audited throughput at roughly one fsync per decision (~1.3k decisions/sec on
  the reference disk). That is the *measured* price referenced by the
  `audit_fsync` config docs: opt out (`audit_fsync: false`) and the append
  drops to ~7 µs, keeping crash-survival (page cache) but not power-loss
  durability. Decide per deployment; the trade is now quantified.
- **Boot verification scales linearly with ledger length.** ~7 ms per 1 000
  records means even a million-record ledger re-verifies in single-digit
  seconds at startup. If that ever matters, sealed checkpoints already exist
  as the shortcut seam (verify only the unsealed tail) — wire it when a real
  deployment hits the wall, not before.
- **Session checkpoints are I/O-bound** (temp + fsync + rename per save).
  ~1.7 ms per checkpoint bounds how fast an ack-heavy resumable session can
  persist its cursor; the PostgreSQL store (`pgstore`) moves this off the local
  disk for HA deployments.

## Keeping it honest

- The benchmarks live in `policy/bench_test.go` and `session/bench_test.go`;
  they fail if behavior breaks (they assert results), so they double as tests.
- When touching a hot path (policy decision, audit append, chain verify,
  checkpointing), run the relevant `-bench` before and after; call out any
  order-of-magnitude change in the PR (see the PR template's verification
  section).
- CI thresholds are deliberately NOT wired yet: benchmark variance on shared
  runners produces false alarms, and GitHub-hosted CI is currently not
  executing jobs at all (see CHANGELOG known issues). Local before/after
  comparison is the gate that works today.
