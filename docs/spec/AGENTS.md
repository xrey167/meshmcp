<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# spec

## Purpose
Open, machine-readable specifications for meshmcp's externally-verifiable formats: the audit-record format and the policy DSL, each paired with a JSON Schema so third parties can validate logs and policies independently of this implementation.

## Key Files
| File | Description |
|------|-------------|
| `AUDIT-RECORD.md` | Prose spec of the tamper-evident audit record (hash-chain fields, decision fields). |
| `audit-record.schema.json` | JSON Schema for one audit record. |
| `POLICY-DSL.md` | Prose spec of the policy DSL (rules, rate limits, time windows, labels, co-sign). |
| `policy.schema.json` | JSON Schema for a policy document. |

## For AI Agents

### Working In This Directory
- These schemas are a contract. If you change `policy.Policy` or `policy.AuditRecord` in code, update the corresponding `.md` **and** `.schema.json` together, or the external-verification promise breaks.

## Dependencies

### Internal
- Mirrors types in `policy/` (`policy.go`, `audit.go`).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
