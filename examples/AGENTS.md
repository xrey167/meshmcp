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
| `orchestrate.yaml` · `federate.yaml` · `http-backend.yaml` | Server-to-server orchestration, cross-org federation, HTTP backend proxy (now with a per-tool policy — F16). |
| `dlp-firewall.yaml` · `cost-governance.yaml` | Content DLP as a decision hook (F18); cost-weighted budgets (F29). |
| `vault.yaml` · `scheduler.yaml` · `bus.yaml` | The Wave-2 dark backends: secrets vault (F26), scheduler (F27), event bus (F28). |
| `hook-policy.yaml` | Policy for the client-hook firewall (`meshmcp hook`, F33) — governs an LLM client's local tools. |
| `knowledge.yaml` | Provenance-native knowledge graph (F2) + zero-exposure RAG/vector store (F3) as governed stdio backends. |
| `graphrag.yaml` | GraphRAG bridge (S3): a `graph_search` tool combining the vector store (F3) and knowledge graph (F2) over the mesh. |
| `vectors-shards.yaml` | Embedding/vector-shard compute mesh (S7): several `vectors` backends behind a router for load-balance + failover. |
| `rag-firewall.yaml` | Taint-contained RAG (F7): retrieval marked a taint source so egress/write is blocked at the gateway after a search. |
| `group-policy.yaml` | Group/role-based policy (F17): rules match `group:<name>` instead of individual keys. |
| `continuity.yaml` | Session handoff (F5): a resumable backend + shared durable store so a second gateway rehydrates a live session on failover. |
| `drop.yaml` | `meshmcp drop` receiver: AirDrop files across mesh instances — ACL-gated, content-hash-verified, audited. |
| `pubsub.yaml` | `meshmcp pubsub` broker: identity-native event fabric with per-topic publish/subscribe authorization (F28). |
| `hooks.yaml` | Gateway hooks: publish firewall decisions (deny/cosign/allow) to the event bus and/or a webhook — observability only, never blocks. |
| `air-workflow.yaml` | Declarative Air launch/steer/call workflow run over one mesh membership, governed and audited (P4). |
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
