<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# insight

## Purpose
The **read side** of the firewall: it turns the audit stream into policy. A four-stage pipeline — observe → recommend → simulate → detect — that profiles what agents actually do, generates a least-privilege policy, simulates a candidate policy against real recorded traffic (a CI gate), and detects behavioral drift/anomalies. Backs `meshmcp insight <subcommand>`.

## Key Files
| File | Description |
|------|-------------|
| `profile.go` | Package doc + `observe`: aggregate a hash-chained audit log into per-identity behavior profiles. |
| `recommend.go` | `RecommendOptions` + policy synthesis. Round-trip invariant: a policy learned from behavior must not deny that same behavior. |
| `simulate.go` | `Change` — diff a candidate policy's verdicts against the recorded corpus (what would newly allow/deny). |
| `detect.go` | `DetectOptions` — anomaly scoring against a learned baseline (off-hours, new tools, volume spikes). |

## For AI Agents

### Working In This Directory
- Input is the tamper-evident `policy.AuditLog`; tests build one with `buildAudit`. Preserve the round-trip invariant in `recommend_test.go` when changing synthesis.
- This package is read-only over audit data — it recommends/simulates policy, it does not enforce.

### Testing Requirements
- `CGO_ENABLED=1 go test ./insight/ -race`. Each stage has a corpus-driven test.

## Dependencies

### Internal
- Reads `policy` audit records / `analyze.go` aggregates. Invoked from root `insight.go`.

### External
- Standard library only.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
