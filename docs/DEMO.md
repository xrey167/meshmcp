# Live mesh demo — see the fabric work

This demo stands up a real meshmcp fabric on your NetBird mesh and drives it with
autonomous agent apps, so you can watch governance happen live in the **Control
Room**. One gateway fronts **four different MCP servers**; **four agent apps**,
each with its own mesh identity, generate recognizable traffic; a single
tamper-evident ledger feeds the live view.

```
 agent-reader ─▶ fs :9101         read allowed · write denied
 agent-fetcher ─▶ web :9102       fetch taints → write blocked
 agent-billing ─▶ payments :9103  {{secret}} injected · transfer held for co-sign
 agent-analyst ─▶ customer-db :9104   read tags pii → egress blocked
                     │
              one gateway · one shared audit ledger
                     │
              Control Room  ·  http://127.0.0.1:9900   (live)
```

## Run it

You need Go and a **reusable** NetBird setup key (app.netbird.io → Setup Keys).

**Windows (PowerShell):**
```powershell
$env:NB_SETUP_KEY = "<your-reusable-setup-key>"
./demo/run-mesh.ps1
```

**macOS / Linux:**
```bash
export NB_SETUP_KEY=<your-reusable-setup-key>
./demo/run-mesh.sh
```

The script builds the binaries, starts the gateway, waits for its mesh IP, opens
the Control Room, and launches the four agents (each as its own mesh peer, with a
random WireGuard port so they don't collide). **Ctrl+C** stops everything.

## What you'll see in the Control Room

- **Server tiles** — `fs`, `web`, `payments`, `customer-db`, each pulsing as it's
  hit, with an allow/deny/co-sign bar and inferred governance tags (🔑 secret,
  co-sign, taint, labels).
- **Identities** — the four agent apps, each resolved to its WireGuard identity,
  with live call counts and the last tool it touched.
- **Live decision feed** — every call streaming in, colour-coded:
  - `agent-reader → read_file @fs` **allow**, then `write_file` **deny**
  - `agent-fetcher → fetch @web` **allow** (taints), then `write_file` **deny** *(session tainted)*
  - `agent-billing → charge @payments` **allow** *(secret injected)*, then `transfer_funds` **cosign**
  - `agent-analyst → read_customer @customer-db` **allow** *(tags pii)*, then `post_message` **deny** *(pii may not egress)*
- **Chain badge** — `✓ chain intact` over the shared ledger.

## Try it live

While it runs:

```bash
# Approve a held payment — the billing agent's transfer_funds starts succeeding:
meshmcp approve --store demo/cosign <agent-billing-fqdn> transfer_funds

# Prove the ledger wasn't edited:
meshmcp audit verify demo/audit.jsonl

# Point your own agent at a backend and watch it appear as a new identity:
meshmcp call <gateway-ip>:9101 read_file --arg path=README.md
```

## Notes

- The four backends run the same demo server (`cmd/mcpserver`) with different
  policies — the diversity is in the **governance**, not the binary. The
  interesting behavior happens at the gateway; the tool handlers are stubs.
- `demo/secrets.json` holds a placeholder Stripe key — replace it with a real one
  only if you want `charge` to authenticate against a real API (not needed for
  the demo). It is gitignored.
- Everything under `demo/` (identities, logs, the ledger) is runtime state and
  gitignored.
- No public ports are opened anywhere — the whole demo lives on the mesh; only
  the Control Room binds localhost for you to watch.
