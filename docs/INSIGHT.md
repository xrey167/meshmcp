# insight — the read side of the firewall

The `policy/` firewall *enforces* rules. `insight/` *produces and evolves* them.
It closes the loop that otherwise makes a deny-by-default firewall unusable:
someone has to author the allowlist, and today that is hand-written from
imagination. `insight` turns the audit stream into policy — it is the function
**AUDIT-RECORD\* → POLICY-DSL**, the missing morphism between the two formats
meshmcp standardizes.

```
        ┌─────────────── policy/ (enforce) ───────────────┐
audit ─▶ │  policy → allow / deny / cosign, inline          │
records  └───────────────────────▲──────────────────────────┘
   │                              │ policy.yaml
   ▼                              │
┌──────────────── insight/ (understand) ───────────────────┐
│ observe   → per-identity behavioral profile               │
│ recommend → least-privilege policy   (Profile → DSL)      │
│ simulate  → dry-run a policy vs recorded traffic (CI gate)│
│ detect    → deviation from baseline → open a co-sign       │
└────────────────────────────────────────────────────────────┘
```

All four stages are pure functions over `policy.AuditRecord` / `policy.Engine`
/ `policy.Policy` — no new infrastructure, fully unit-tested.

## observe — `insight profile`

Builds a per-identity behavioral profile keyed by the caller's cryptographic
key: tool set + call counts, methods, the per-active-minute call-rate
distribution (p50/p99), the hour/day activity footprint, decision breakdown,
and — when the policy in effect is supplied — the data-flow labels each identity
produced (reconstructed from the rule index the record already stores).

**The corpus is verified before it is trusted.** `Profile` runs `VerifyChain`
and reports `chain_ok`; you must not learn a baseline or synthesize a policy
from a tampered log, and the signed-audit module makes that check meaningful.

```bash
meshmcp insight profile audit.jsonl [--policy in-effect.yaml]
```

## recommend — `insight recommend`

Synthesizes a **least-privilege** `policy.Policy` from a profile: one allow rule
per identity granting exactly the tools it *successfully used* (tools that were
only ever denied stay denied), a rate cap at observed p99 × a safety factor, and
an activity window when behavior is cleanly weekday-bounded. `--generalize`
collapses `read_a, read_b → read_*` and **flags every widening** in the notes.
Data-flow guard suggestions are emitted as notes, never silent rules.

The output is valid POLICY-DSL on stdout (notes on stderr), so "write a policy
from scratch" becomes "review a generated one":

```bash
meshmcp insight recommend audit.jsonl [--generalize] > policy.yaml
```

**Invariant (tested):** a recommended policy, simulated against the corpus it was
learned from, produces **zero regressions**. A policy learned from behavior does
not deny that behavior.

## simulate — `insight simulate`

Replays the recorded corpus through the **real** `policy.Engine` under a
candidate policy and diffs each verdict against what actually happened:
regressions (was allowed, now blocked), new co-sign gates, loosenings, and rule
coverage. Records replay in time order with the engine clock driven from each
record's timestamp, so stateful constraints (rate buckets refill by elapsed
time; labels accumulate per identity) reproduce faithfully. Exit is non-zero on
any regression — the **policy CI gate**:

```bash
meshmcp insight simulate audit.jsonl --policy candidate.yaml   # exit 1 on regressions
```

No firewall change ships without first seeing what it would have done to last
week's traffic.

## detect — `insight detect`

Scores new records against a learned baseline: a tool never seen for an
identity, a rate spike past baseline p99 × k, off-hours activity against a
bounded window, a deny-rate spike (an agent hammering blocked tools reads as
compromised), an unknown identity, or a label-emitter reaching an egress tool.

Anomalies on otherwise-allowed calls are routed to **open a co-sign, not a hard
block** — detection is fail-to-human, not fail-closed, so a false positive slows
an agent rather than breaking it. Normal traffic produces nothing.

```bash
meshmcp insight detect new.jsonl --baseline history.jsonl
```

## The onboarding loop it unlocks

1. Deploy `default_allow` with full audit; let an agent run for a burn-in week.
2. `insight recommend` → a least-privilege policy for exactly what it did.
3. `insight simulate` the policy against the same week → confirm zero regressions.
4. Enforce. From then on, `insight detect` watches for drift and opens co-signs.
5. A detected deviation becomes new observed behavior → re-recommend. The loop
   closes: the firewall is the muscle, `insight` is the nervous system.

## Subtleties handled (and the ones left to the operator)

- **Over-fitting.** Least privilege grants exactly what was seen, so a
  legitimate first-time call is denied. Every recommendation ends with a REVIEW
  note; nothing auto-enforces; `--generalize` and a monitor-mode burn-in are the
  release valves.
- **Baseline poisoning.** If the observation window already contains misuse, the
  baseline learns it as normal. Recommend from a clean window; the chain check
  guards integrity but not intent.
- **Corpus sensitivity.** The record is payload-free by default; `insight`
  operates on metadata only.
- **Alert fatigue.** Anomalies are scored and ranked, not binary; detection
  prefers co-sign over deny.

## Reference implementation

`meshmcp/insight` (`profile.go`, `recommend.go`, `simulate.go`, `detect.go`) and
the `meshmcp insight` commands. Input format: [spec/AUDIT-RECORD.md](spec/AUDIT-RECORD.md).
Output format: [spec/POLICY-DSL.md](spec/POLICY-DSL.md).
