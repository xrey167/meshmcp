# The meshmcp Guide

Task-oriented recipes for people using meshmcp — not specs. Each one is: what
you want → what to run → what you should see. The deep documentation is linked
from every recipe when you want the why.

Everything below assumes the one-time setup in the first recipe. Commands that
take a `<control-ip:port>` can omit it once you save a default:
`meshmcp profile set --control <ip:port>` (or set `$MESHMCP_CONTROL`).

---

## Set up your first gateway

**You want:** your tools reachable from your other devices, privately, with
nothing exposed to the internet.

```console
$ export NB_SETUP_KEY=<key from app.netbird.io>
$ meshmcp air up
```

`air up` scaffolds a safe-by-default config on first run (deny-by-default
policy, audit on, pairing enabled), joins the mesh, and prints your mesh IP
and pair address. Your identity and state live in a stable per-user directory
(`~/.config/meshmcp` on Linux), so `air up` works from any folder.

Replace the placeholder backend in the generated `meshmcp.yaml` with your real
MCP server command, then `air up` again. Deny-by-default means nothing is
callable until you grant it — that is the point.

## Add your second device

**You want:** your laptop to see the gateway. Like accepting an AirDrop.

On the new device:

```console
$ meshmcp air join <gateway-pair-address> --label "work laptop"
requesting access as work-laptop.netbird.cloud
waiting for approval… (Ctrl-C to stop)
```

On the gateway (or any operator device):

```console
$ meshmcp air pair list
$ meshmcp air pair approve <control-ip:port> <peer-key>
```

The joining side flips to `approved — you're recognized on the mesh`.
Recognition is identity, not access: the new device still can't call any tool
until you grant one (next recipe). If you decline instead
(`air pair deny --reason "don't recognize this"`), the requester is told why.

## Let a device or agent actually use a tool

**You want:** the recognized laptop to query the knowledge graph — and nothing
else.

Grant-on-request: when a recognized peer's call is denied, it becomes a
pending "ask" an operator resolves with one command — Allow once, Always, or
Deny:

```console
$ meshmcp air grant list
$ meshmcp air grant allow <control-ip:port> <peer-key> "corpus/*" --always
```

The peer's retry succeeds. Revoke a single grant any time with
`air grant revoke` — deny-by-default takes back over immediately.

## Share a file with your other laptop

```console
$ meshmcp air send <control-ip:port> --to "work laptop" --file report.pdf
```

`--to` takes the device's friendly name, FQDN, or full public key — resolved
against live, transport-verified presence, never a spoofable string. Delivery
is receiver-confirmed: the command succeeds only after the receiving inbox
confirms exact payload totals.

## Approve a dangerous call from your phone

**You want:** `transfer_funds` to require a human tap, and the tap to happen
on your phone.

1. Mark the tool in the backend's policy:

```yaml
policy:
  rules:
    - tools: ["transfer_funds"]
      allow: true
      require_cosign: true
cosign_store: ./cosign
approval_signing_key: ./approval.key
```

2. Run the approver on the mesh and open it from your phone (any mesh device):

```console
$ meshmcp approvals --store ./cosign --approver 'pubkey:<your-phone-key>' --approval-key ./approval.key
```

A matching call is HELD; your phone shows it (peer, tool, exact arguments);
one tap mints a signed, single-use approval bound to those exact arguments.
Change the arguments and the approval no longer matches. See
`docs/spec/SECURITY-CLOSURE.md` for the guarantees.

## Connect claude.ai to a tool

**You want:** a hosted client that can't join your mesh (claude.ai custom
connectors) to reach ONE tool, without opening your gateway to the world.

```console
$ meshmcp edge --config examples/edge.yaml
```

The edge is a separate, off-by-default public ingress: OAuth 2.1 with consent,
scoped to exactly the tools you enumerate, with every call audited on the same
ledger. Follow `docs/COOKBOOK.md` recipe 13 end-to-end; `docs/EDGE.md`
explains the trade you're making (it is the project's only public listener).

## Add a second operator

**You want:** a teammate who can approve pairings and steer sessions — without
hand-editing YAML or sharing your key.

```console
$ meshmcp air operator add --pubkey <their-wireguard-key> --fqdn teammate.netbird.cloud
```

They can now `air pair approve`, `air grant allow`, and `air steer`. Remove
them with `air operator remove`. Operators are recognized by their unforgeable
WireGuard key on the same surface as `control.allow`.

## Steer a live agent

```console
$ meshmcp air sessions                      # what's running
$ meshmcp air steer --to analyst --param text="focus on the Q3 numbers"
```

`--to` binds to the one live session carrying that node's transport-verified
key; an ambiguous name fails closed rather than steering the wrong agent.

## Change policy without a restart

Edit `meshmcp.yaml`, then:

```console
$ kill -HUP $(pidof meshmcp)
```

Policy rules and allow lists hot-swap in place; live sessions keep running. A
config with a typo changes nothing — the gateway keeps its last good policy
and logs why.

## When something breaks

```console
$ meshmcp doctor                            # pre-flight: config, commands, permissions
$ meshmcp diag --bundle diag.tar.gz         # everything support needs, secrets redacted
```

Common failures print their own next step (missing setup key, unreachable
gateway, declined pairing). For operational emergencies — stolen device,
suspected audit tamper, key rotation — follow `docs/RUNBOOK.md` step by step.

## A device was lost or stolen

```console
$ meshmcp revoke-device <its-public-key> --netbird-token $NB_API_TOKEN --device <its-name>
```

One audited command: recognition revoked, grants purged, every outstanding
capability token killed, operator surface cleaned, peer deregistered from the
account. The checklist output names anything it couldn't reach from this host.

## Leave the mesh

```console
$ meshmcp uninstall            # dry run — shows what would be removed
$ meshmcp uninstall --yes      # remove identity, ledgers, stores, config
```

Removing the identity is irreversible (a fresh install means re-pairing);
that's why the default is a dry run.

---

*Deeper reading:* [README](../README.md) · [RUNBOOK](RUNBOOK.md) ·
[COOKBOOK](COOKBOOK.md) · [THREAT-MODEL](THREAT-MODEL.md) ·
[CAPABILITY-MATRIX](CAPABILITY-MATRIX.md) · [EDGE](EDGE.md)
