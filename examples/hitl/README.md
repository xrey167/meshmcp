# Human-in-the-loop approvals over the mesh

Any agent framework with an approval hook can route human approvals through
meshmcp's mesh **approver** — so a command the agent wants to run is held until a
human on the mesh (a phone in your pocket) taps **Approve** or **Deny**, the
decision is attributed to that person's WireGuard identity, and it lands in the
tamper-evident audit. This generalizes meshmcp's `require_cosign` from
gateway-mediated calls to *any* tool, in any framework.

## How it works

```
 agent tool wants to run  ─▶  on_approval hook
                                 │  POST /v1/request {peer, tool}
                                 ▼
                        meshmcp approvals  (dark mesh service, no public port)
                                 │  a human opens it on their phone → Approve / Deny
                                 ▼
       on_approval polls  ◀──  GET /v1/status → approved | denied | pending
```

The approver exposes:

| Endpoint | Purpose |
|---|---|
| `POST /v1/request {peer, tool, backend}` | Register a request (from any agent framework). |
| `GET /v1/status?peer=&tool=` | Poll the decision: `pending` \| `approved` \| `denied`. |
| `GET /v1/pending`, `POST /v1/approve`, `POST /v1/deny` | The human's inbox + actions (the phone UI). |

Served over the mesh, the human's approval is their **WireGuard identity** — an
approve writes an identity-attributed grant into the shared co-sign store.

## Run it

```bash
meshmcp approvals --store ./cosign          # on the mesh; open http://<mesh-ip>:9700 on your phone
# for local testing:
meshmcp approvals --store ./cosign --addr 127.0.0.1:9700
```

## Use it — OpenAI Agents SDK `ShellTool`

```python
from agents import Agent, ShellTool
from meshmcp_hitl import mesh_on_approval, mesh_executor   # this folder

shell = ShellTool(
    # Execution ALSO on the mesh: runs on a governed backend via run_command
    # (allow-listed, rate-limited, taint-checked, audited) — not on this host.
    executor=mesh_executor("100.64.0.2:9105", nb_config="./agent-nb.json"),
    needs_approval=lambda *_: True,                     # hold every shell call
    on_approval=mesh_on_approval("agent:build-bot"),    # → approve from your phone
)

agent = Agent(name="build-bot", tools=[shell])
# The agent proposes a command → held → you approve on your phone → it runs on the
# governed mesh backend → the result comes back. Deny → the SDK returns a rejection.
```

- `mesh_on_approval(agent_id)` — holds the call for a human on the mesh.
- `mesh_executor(target)` — runs the approved command through meshmcp's governed
  `run_command` over the mesh (shells out to `meshmcp call`), so both the
  **approval** and the **execution** are governed and audited. Drop it, and the
  agent never touches the local host at all. Omit it (use your own `executor`) if
  you only want the approval half.

`MESHMCP_APPROVER` overrides the approver URL (default `http://127.0.0.1:9700`);
`meshmcp` must be on `PATH` (or pass `meshmcp_bin=`).

## Why route it through meshmcp instead of the SDK's local approval?

- **The approver is a real person, cryptographically.** The grant records *who*
  approved (their mesh identity), not a local boolean.
- **It's remote and mobile.** Approve from your phone anywhere on the mesh; no
  need to be at the terminal running the agent.
- **It's audited.** Every approve/deny is in the same tamper-evident ledger as
  the rest of the mesh — provable after the fact.
- **It's framework-agnostic.** The same approver serves the OpenAI Agents SDK,
  LangGraph, or your own tool — one inbox for all agent approvals.
