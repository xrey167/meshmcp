<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# docs

## Purpose
Design documentation and open specifications for meshmcp. Human-facing narrative for each subsystem, plus the machine-readable specs under `spec/`. These are the authoritative "why/how" references the README links to.

## Key Files
| File | Description |
|------|-------------|
| `AGENT-FIREWALL.md` | The policy engine, signed audit, dashboard, replay, control plane, federation. |
| `INSIGHT.md` | The firewall's read side: observe → recommend → simulate → detect. |
| `SECRETS.md` | The credential broker: identity-gated secret injection. |
| `EXTENSIONS.md` | Signed capabilities, server middleware, typed function/task client (and why the external "fabric" pack was not merged). |
| `MCP-APP.md` | Adding meshmcp to Claude Code / Codex as an MCP app. |
| `MOBILE.md` | How the stack reaches phones (a phone as a human identity / co-sign approver). |
| `DEMO.md` · `COOKBOOK.md` | The live mesh demo, and 10 worked "what's possible" scenarios with configs + diagrams. |
| `HA-TOOLMESH.md` · `NETWORK-PLAN.md` · `VISION.md` · `reference.md` | HA design, network design, roadmap, full reference. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `spec/` | Open specs with JSON Schemas: audit-record format and the policy DSL (see `spec/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Keep docs consistent with the code they describe. When changing a subsystem, update its doc in the same pass (e.g. capability changes → `EXTENSIONS.md`).
- The protocol baseline is MCP **2025-06-18**; don't introduce claims about other versions.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
