<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# hitl

## Purpose
A human-in-the-loop bridge showing how meshmcp's co-sign gate integrates with an external agent runtime — the OpenAI Agents SDK. When a tool requires a human co-sign, the agent's approval callback is wired to the mesh approver, so a person (e.g. a phone on the mesh) authorizes the call.

## Key Files
| File | Description |
|------|-------------|
| `meshmcp_hitl.py` | Python bridge: `mesh_on_approval` (route an SDK approval to the mesh co-sign) and `mesh_executor` (run the approved tool over the mesh). |
| `README.md` | How to run the bridge against a gateway. |

## For AI Agents

### Working In This Directory
- Python, not Go. Compile-check with `python3` (the system default `python` may be an ancient 3.3 that fails on modern syntax).
- The bridge is a demo of the boundary between an external agent framework and meshmcp's policy/co-sign — keep the approval semantics (needs_approval → mesh approver → execute) intact.

## Dependencies

### External
- OpenAI Agents SDK (Python). Talks to a running `meshmcp` gateway + `approvals` service.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
