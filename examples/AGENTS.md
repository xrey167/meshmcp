<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# examples

## Purpose
Ready-to-adapt gateway configurations, one per feature, plus the human-in-the-loop bridge. These YAML files are loaded by `meshmcp serve`/`router`/`orchestrate`/`federate` and validated by `loadConfig`; they double as executable documentation of the config surface.

## Key Files
| File | Description |
|------|-------------|
| `meshmcp.example.yaml` | Baseline annotated config. |
| `agent-firewall.yaml` · `live-policy.yaml` | Policy enforcement (allow/deny, rate limits, taint, co-sign). |
| `capabilities.yaml` | Signed-capability admission (required surface + policy-upgrade surface). |
| `secrets.yaml` | Credential broker (`{{secret:NAME}}` grants, taint-refusal). |
| `live-task.yaml` | Async tool tasks. |
| `demo-backends.yaml` · `demo-mesh.yaml` · `demo-trace.yaml` | The multi-backend live showcase and gateway-wide tracing. |
| `router.yaml` · `router-failover.yaml` | Aggregating router: discovery, load-balance, failover. |
| `orchestrate.yaml` · `federate.yaml` · `http-backend.yaml` | Server-to-server orchestration, cross-org federation, HTTP backend proxy. |
| `README.md` | Index of the examples. |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `hitl/` | Human-in-the-loop bridge to the OpenAI Agents SDK (see `hitl/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Configs reference the demo backend as `./cmd/mcpserver/mcpserver.exe` and use tool names from `prompt_mcp` (`read_file`, `run_command`, `charge`, `fetch`, …). If a tool is renamed, fix it here too.
- Cross-field rules enforced by `loadConfig`: capabilities are stdio-only, need ≥1 trusted key, and with `required:false` need a deny-by-default policy; secrets need a policy. Keep examples valid — `meshmcp secrets check --config <f>` parses the whole file.
- Placeholder keys use valid-format hex (e.g. all-zero 32-byte) so the file still loads; replace with real `capability keygen` output.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
