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
import json
import os
import shlex
import subprocess

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


def _commands_of(request) -> list[str]:
    """Best-effort extraction of the shell command list from a ShellTool request."""
    for path in ("data.commands", "action.commands", "commands"):
        obj = request
        try:
            for part in path.split("."):
                obj = getattr(obj, part)
            if obj:
                return list(obj)
        except Exception:
            continue
    try:
        return list(request["action"]["commands"])  # dict-shaped request
    except Exception:
        return []


def _mesh_run(argv_base: list[str], target: str, line: str, timeout_s: int) -> str:
    """Run one command on the mesh backend via `meshmcp call ... run_command` and
    return its text output. Governed by the backend's policy and audited."""
    command, *args = shlex.split(line)
    payload = json.dumps({"command": command, "args": args})
    argv = argv_base + [target, "run_command", "--json", payload]
    try:
        res = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s)
    except Exception as e:  # noqa: BLE001
        return f"$ {line}\n(error invoking meshmcp: {e})"
    text = (res.stdout or "").strip()
    try:  # `meshmcp call` prints the tool result as JSON; pull out the text content.
        result = json.loads(text)
        content = result.get("content") or []
        joined = "\n".join(c.get("text", "") for c in content if isinstance(c, dict))
        if joined:
            text = joined
    except Exception:
        pass
    if not text and res.stderr:
        text = res.stderr.strip()
    return f"$ {line}\n{text}"


def mesh_executor(
    target: str,
    *,
    meshmcp_bin: str = "meshmcp",
    nb_config: str | None = None,
    timeout_s: int = 90,
):
    """Return a ShellTool executor that runs commands on a GOVERNED meshmcp backend
    (via run_command over the mesh) instead of locally — so execution is
    allow-listed, rate-limited, taint-checked, and audited just like the approval.

    target       backend mesh address, e.g. "100.64.0.2:9105"
    meshmcp_bin  path to the meshmcp binary (default: on PATH)
    nb_config    persist a stable mesh identity across calls (recommended)
    """
    argv_base = [meshmcp_bin, "call"]
    if nb_config:
        argv_base += ["--nb-config", nb_config]

    def executor(request) -> str:
        cmds = _commands_of(request)
        if not cmds:
            return "(no commands)"
        return "\n\n".join(_mesh_run(argv_base, target, line, timeout_s) for line in cmds)

    return executor
