# Operator Runbook

Task-oriented recovery procedures for the situations that page you. Each entry
is: what happened → what to run → how to verify. The commands are the shipped
surface; nothing here requires editing YAML under pressure.

---

## My laptop / device was stolen

A device on your mesh is in unknown hands. Its WireGuard private key, any
capability tokens it held, and (if it was an operator device) its
control/approval authority are all compromised until revoked.

**One command severs every local trust surface:**

```console
$ meshmcp revoke-device --config meshmcp.yaml \
    --grant-store ./grants.json \
    --device <netbird-peer-name> --netbird-token $NB_API_TOKEN \
    <the-device's-wireguard-public-key>
```

What it does, in one audited pass (each action lands on the gateway's
tamper-evident ledger):

| Surface | Effect |
|---|---|
| Pairing | The identity stops being recognized (`paired.json` revoke); a still-pending request is cleared so it cannot be mistakenly approved later. |
| Grants | Every written `(identity, verb, scope)` grant in each `--grant-store` is removed, along with pending grant opportunities. |
| Capabilities | The identity is **subject-revoked** in every backend's `revocation_store` — every outstanding signed capability token it holds fails verification immediately, before expiry. |
| Operator surface | The identity is dropped from `operators` and `control.allow` (surgical config edit, re-validated before write). Revoking the *last* allowed identity is refused — one stolen device must not lock every operator out. |
| Management plane | With `--device` + `--netbird-token` (control node only), the peer is deregistered from the NetBird account (`DELETE /api/peers/{id}`), cutting its mesh membership. |

The command prints a checklist: `✓` done, `–` skipped (not configured / not
reachable from this host — finish those where noted), `✗` failed (exit is
non-zero; the identity may retain access on that surface until you re-run).

**Verify:**

```console
$ meshmcp air pair list <control-ip:port>      # identity absent
$ meshmcp audit verify --log audit.jsonl        # chain intact, revocation records present
```

The revoked device cannot re-join silently: re-pairing requires a fresh
`air join` request **and** an operator's explicit approval.

## A peer should lose one tool, not everything

Don't revoke the device — revoke the grant:

```console
$ meshmcp air grant revoke <control-ip:port> <peer-key> <scope>
```

Deny-by-default does the rest: no matching grant, no access.

## An operator left the team

```console
$ meshmcp air operator remove --pubkey <key>    # control/steer + pairing-approver surface
$ meshmcp revoke-device --config meshmcp.yaml <key>   # if their device should also lose peer trust
```

## Key rotation

meshmcp's own trust anchors, and how to rotate each:

- **Mesh identity (WireGuard key).** Held in the NetBird state file
  (`config_path`, default `<data-dir>/meshmcp-nb.json`). To rotate: `meshmcp
  uninstall --keep-config` on the device, then re-enroll with a fresh setup key
  — the device gets a new key pair and mesh IP; re-pair and re-grant it.
  Deregister the old peer from the NetBird account.
- **Capability authority keys** (`capabilities.trusted_public_keys`). Mint with
  the new key, add it to the pinned set, drain, then remove the old key. The
  verifier only ever trusts pinned keys, so removal is immediate revocation of
  everything the old key signed.
- **Approval signing key** (`approval_signing_key`). Generate a new key file,
  update both the backend config and the approver's `--approval-key`, restart
  (or SIGHUP for policy-rule changes). Outstanding minted approvals die with
  the old key — they are single-use and short-TTL by design.
- **Audit checkpoint signing key.** Keep the old PUBLIC key: sealed checkpoints
  signed by it must remain verifiable. Add the new key for future checkpoints;
  never delete the old ledger or its key.

## Backup / escrow

What to back up from the data directory (`$MESHMCP_HOME`, default
`~/.config/meshmcp`):

- `meshmcp.yaml` — the gateway's declarative state. Safe to store; it contains
  no secrets (the setup key is env-only by design).
- `audit.jsonl` (+ checkpoint files) — the tamper-evident history. Append-only;
  back up freely. Verification needs no secret.
- `paired.json`, grant stores — trust state; restoring them restores
  recognition and grants exactly.
- **The NetBird state file (`meshmcp-nb.json`) contains the WireGuard PRIVATE
  key.** Escrow it only encrypted, or prefer not to back it up at all: a fresh
  identity plus re-pairing is cheap, an exfiltrated private key is not.

## Security incident?

See [SECURITY.md](../SECURITY.md) for reporting. For a suspected audit-log
tamper: do not restart the gateway (it will refuse an unverifiable chain —
that refusal is the evidence); copy the ledger, run
`meshmcp audit verify --log <copy>`, and preserve the break report.
