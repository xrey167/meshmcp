"""meshmcp human-in-the-loop bridge for agent frameworks.

Wire an agent tool's approval hook (e.g. the OpenAI Agents SDK
`ShellTool(on_approval=...)`) to meshmcp's mesh approver: the action is held
until a human on the mesh — typically a phone — taps Approve or Deny. The
decision is attributed to the approver's WireGuard identity and lands in
meshmcp's tamper-evident audit. No public port anywhere; the approver is a dark
mesh service.

Run the approver next to your gateway (shares the cosign store):
    meshmcp approvals --store ./cosign               # on the mesh (open it from your phone)
    meshmcp approvals --store ./cosign --addr 127.0.0.1:9700   # or local, for testing

Then, in your agent:
    from meshmcp_hitl import mesh_on_approval
    from agents import ShellTool

    ShellTool(
        executor=my_executor,
        needs_approval=lambda *_: True,
        on_approval=mesh_on_approval("agent:build-bot"),
    )

Config:
    MESHMCP_APPROVER   base URL of the approver (default http://127.0.0.1:9700)
"""

from __future__ import annotations

import asyncio
import os

import httpx

DEFAULT_APPROVER = os.getenv("MESHMCP_APPROVER", "http://127.0.0.1:9700")


def _command_of(item) -> str:
    """Best-effort human-readable label for the held action."""
    try:
        cmds = item.raw_item.get("action", {}).get("commands", [])
        if cmds:
            return " && ".join(cmds)
    except Exception:
        pass
    return getattr(item, "name", "tool")


def mesh_on_approval(
    agent_id: str,
    *,
    backend: str = "agent-shell",
    timeout_s: int = 120,
    approver_url: str | None = None,
):
    """Return an async on_approval callback that holds the call for a human on the mesh.

    agent_id     the identity recorded as the requester (e.g. "agent:build-bot")
    backend      a label shown to the approver
    timeout_s    how long to wait before auto-denying
    approver_url override the approver base URL (else $MESHMCP_APPROVER)
    """
    base = (approver_url or DEFAULT_APPROVER).rstrip("/")

    async def on_approval(_context, item):
        cmd = _command_of(item)[:200]
        key = {"peer": agent_id, "tool": f"shell:{cmd}"}
        async with httpx.AsyncClient(timeout=10) as client:
            # Register the request; the human sees it in the approver (phone).
            await client.post(f"{base}/v1/request", json={**key, "backend": backend})
            for _ in range(timeout_s):
                try:
                    state = (await client.get(f"{base}/v1/status", params=key)).json().get("state")
                except Exception:
                    state = "pending"
                if state == "approved":
                    return {"approve": True}
                if state == "denied":
                    return {"approve": False, "reason": "denied on the mesh"}
                await asyncio.sleep(1)
        return {"approve": False, "reason": "approval timed out on the mesh"}

    return on_approval
