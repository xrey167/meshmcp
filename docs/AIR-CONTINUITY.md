# Air Continuity — “Continue on…” for agents

Air already has the recognizable parts of a device ecosystem: Nearby/Home,
Drop, Universal Clipboard (`push`), Cast/Screen, Ring, Steer, Shortcuts-like
workflows, approvals, and a shared receipt stream. **Continuity is the connective
tissue:** move the *meaning of active work* to another trusted mesh identity,
then continue it under that destination's own policy and authority.

The first shipped primitive is **Air Handoff**:

```text
source agent/device              destination device                    destination agent
       │                                  │                                    │
       │  target-key-bound Context Capsule│                                    │
       ├─────────────────────────────────►│  offered (inert, local inbox)       │
       │◄─────────────────────────────────┤  stored/replayed ACK or rejection   │
       │                                  │                                    │
       │                                  │  explicit accept                    │
       │                                  │  receiver chooses tool + exact key  │
       │                                  ├───────────────────────────────────►│
       │                                  │    claimed dispatch + task steer    │
       │                                  │◄───────────────────────────────────┤
       │                                  │  validated + audited + enqueued ACK │
       │                                  │  state = continued                  │
```

The offer command reports success only after a bounded application ACK confirms
storage (or an identity-bound replay); transport closure alone is not success.
“Continued” means the destination inbox returned a valid application ACK after
strict validation, receipt audit, and enqueue—not that the tool succeeded. The
tool's result belongs to the destination's normal execution/audit path.

## Try it

On the destination workstation, start a deny-by-default inbox:

```bash
meshmcp air handoff receive \
  --inbox ~/.meshmcp/handoffs \
  --nb-config ~/.meshmcp/handoff-destination.json \
  --port 9140 \
  --allow 'pubkey:<source-wireguard-key>'
```

The receiver prints its full target key. Keep both endpoint identities stable
with `--nb-config`; without it, each command registers a new peer. From the
source:

```bash
meshmcp air handoff offer \
  --nb-config ~/.meshmcp/handoff-source.json \
  --target-key '<destination-wireguard-key>' \
  --work task:task-17 \
  --goal 'Continue the ACME outage analysis' \
  --summary 'Three suppliers are affected; validate the ERP exposure.' \
  --cursor ./resume-cursor.json \
  --artifact exposure.json=sha256:<64-hex-content-hash> \
  --memory-ref corpus:acme \
  --secret-ref secret:erp-readonly \
  --sensitivity sensitive \
  100.64.0.22:9140
```

On the destination:

```bash
meshmcp air handoff list --inbox ~/.meshmcp/handoffs  # sensitive goals are redacted here
meshmcp air handoff show --inbox ~/.meshmcp/handoffs <handoff-id>
meshmcp air handoff accept --inbox ~/.meshmcp/handoffs <handoff-id>

# Start (or separately provision) the destination agent with a persistent key,
# an exact allow entry for the controller, and its own receipt chain.
meshmcp agent --nb-config ~/.meshmcp/handoff-agent.json \
  --role reader --steer-port 9120 \
  --steer-allow 'pubkey:<controller-wireguard-key>' \
  --steer-audit ~/.meshmcp/handoff-agent-steer.jsonl \
  100.64.0.2:9101

# Run the agent in its own terminal. During provisioning, `air whoami` with
# each persistent --nb-config prints the full controller/agent key to pin here.

# The receiver—not the capsule—chooses the tool that imports/continues work.
meshmcp air handoff continue \
  --inbox ~/.meshmcp/handoffs \
  --nb-config ~/.meshmcp/handoff-controller.json \
  --agent-key '<destination-agent-wireguard-key>' \
  --tool resume_analysis \
  <handoff-id> 100.64.0.31:9120

# If delivery times out/crashes, it remains dispatching. Check the agent's
# receipts first; only then explicitly re-arm that unknown outcome.
meshmcp air handoff rearm --inbox ~/.meshmcp/handoffs \
  --note 'checked agent receipt: no matching delivery' <handoff-id>

# Move old terminal receipts—and expired unknown dispatches—out of the bounded
# active inbox without deleting their evidence or replay/collision tombstones.
meshmcp air handoff archive --inbox ~/.meshmcp/handoffs --older-than 168h
```

The destination agent's steer inbox must independently allow the persistent
controller identity. The controller verifies the literal agent IP against
`--agent-key` before claiming the dispatch and on every reconnect, so accepted
context is not released to an address-only target. `resume_analysis` follows
that agent's normal tool path; gateway firewall policy applies when the agent
is connected through a governed meshmcp gateway. A sender cannot put a tool
name in the capsule and cause it to execute.

## Context Capsule v1

The portable wire and state types live in `air/handoff.go`:

- exact `TargetKey` (the destination's WireGuard public key);
- 128-bit random correlation and offer-replay ID;
- creation/expiry with a maximum 24-hour TTL;
- a descriptive work reference (`agent`, `session`, `task`, or `workflow`);
- goal, summary, and a bounded JSON cursor;
- content-addressed artifact references—large bytes stay in CAS;
- logical memory and intended secret-reference fields (free-form content is not DLP-scanned);
- labels and sensitivity metadata;
- a SHA-256 content hash over the canonical capsule JSON.

The whole inline capsule is capped at 256 KiB. Its wire parser is bounded, IDs
are path-safe, artifact names cannot traverse directories, and every
caller-influenced display/audit field is bounded or sanitized.

The durable inbox uses atomic write + fsync + rename, serializes cooperating
processes with an OS advisory lock, and never silently evicts history. On POSIX
it repairs the directory/record modes to `0700`/`0600`. Windows `chmod` does not
install private DACLs, so place the inbox below a user-private profile directory
whose inherited ACL excludes other users. Ancestor path components remain an
operator-controlled trust boundary. The state machine is deliberately small:

```text
offered ──► accepted ──► dispatching ──► continued
   ├────────► declined         └─ rearm --note ─► accepted
   └────────► expired
accepted ───► expired
```

Offer retries with the same ID, content hash, and verified source key are
idempotent. The same ID with different content or a different source key is
rejected. Continuation is different: `accepted → dispatching` is claimed under
the cross-process lock before network I/O. Concurrent dispatches therefore lose
the claim. A timeout/crash leaves `dispatching` as an unknown outcome; after
checking downstream receipts, the operator must use the distinct, noted
`rearm` command. Retrying ordinary `accept` cannot re-arm it. There is no
exactly-once tool-execution claim. Each claim durably records the selected
agent address, exact agent key, tool, claim time, and—when received—the
application-ACK time. Unknown attempts remain in that bounded history after a
re-arm, preserving where context may have gone. Once an unknown dispatch is
expired and past retention, `archive` can free its active-inbox slot without
changing `dispatching` or erasing its receipt/tombstone.

## Trust boundaries

Air Handoff preserves six invariants:

1. **The source is transport-derived.** `SourcePeer` and `SourceKey` come from
   the mesh connection (`session.Meta`), never from capsule JSON.
2. **Each target is exact.** The receiver compares the capsule's `TargetKey`
   with its own transport key. Before sending context—and on every reconnect—
   the source resolves the destination device IP to that exact transport key.
   Continuation applies the same check to the receiver-selected agent IP and
   `--agent-key`. Hostnames, groups, and globs are not legal context-bearing
   destinations.
3. **Received context is inert.** Receive only validates, rate-limits, stores,
   and audits. It never launches an agent or calls a tool.
4. **Consent precedes continuation.** `offered → continued` is illegal. The
   local owner must accept first.
5. **Destination authority is fresh.** The destination chooses the tool.
   Sender labels never become policy execution labels. The continuation carries
   explicit `handoff`/`untrusted-context` handling hints for the destination
   tool, but the current `policy.Filter` does not interpret argument hints as
   taint labels; gateway rules apply through the agent's normal configured path.
6. **Secrets and grants are not authority.** `SecretRefs` are intended for
   logical names only, and a destination must independently possess permission
   to resolve them. The format cannot detect a credential pasted into free-form
   goal/cursor text, so senders must treat capsule authoring as sensitive input
   handling. Source-bound capabilities/tokens must not be placed in a capsule.

The receiver writes restart-seeded, hash-chained audit records for accepted and
fully parsed offer decisions. Repetitive pre-ACL and rate-limit denials are
sampled at most once per minute per identity to bound hostile log growth. Valid
stored offers use only the correlation ID and capsule hash as provenance—not
inline goal, cursor, or secret references. Malformed framing has no trustworthy
ID/hash, and a fail-closed audit error is returned even though an atomic store
may already have completed. A `receipt_unconfirmed` NACK therefore means
“inspect the destination”; a fresh CLI invocation cannot reproduce the same
sealed bytes merely by reusing the ID. Accept/decline are local inbox state; the
destination agent writes separate `air/steer/authorize` and `air/steer/enqueue`
records to its own configured audit sink. Only an enqueue `allow` is positive
downstream delivery evidence; authorization alone is not. The shared ID makes
those records correlatable, but it does not make them one atomic chain or
deduplicate tool execution. If enqueue succeeds but its second audit append
fails, the sender receives `audit_unavailable` and work may still execute; the
Handoff deliberately remains `dispatching` until the operator checks receipts.

Use a dedicated audit file per Handoff receiver and per steerable agent. Those
commands enforce one cooperative writer and restart-seed their own chain, but a
different meshmcp service writing the same path does not participate in that
sidecar lock; sharing the file would fork its cursor.

Offer and steer application ACKs are a coordinated protocol upgrade. Upgrade
the controller and destination agent together; mixed old/new peers do not fall
back to transport-only success.

## What v1 is not

Handoff v1 is **application-level continuation in a fresh agent/session**. It
does not move a live byte-stream session between device identities.

That distinction is security-critical. `session.Server` binds reattachment to
the original `CreatorKey`; weakening it would turn knowledge of a session ID
into a takeover primitive. Current migration is gateway failover for the same
client identity, not ownership transfer to a different key. The source work is
therefore left running if Handoff fails.

Also, the content hash is an integrity/correlation address, not a sender
signature. Sender authenticity comes from the WireGuard transport identity and
the receiver's ACL.

## The ecosystem around Handoff

The next useful additions are shared layers, not more unrelated verbs:

| Layer | Experience | Technical direction |
|---|---|---|
| **Air Manifest** | “What can this device/agent do?” | A well-known, versioned availability manifest (`context.import`, `agent.launch`, `display.image`, `approval`). It is a hint; policy remains authority. |
| **Air Presence** | Trusted device and agent status | Short-lived, identity-stamped leases over governed PubSub. NetBird reachability is “Nearby,” not proof of physical proximity. |
| **Smart Targeting** | `Continue on… → RTX workstation` | Deterministic resolution over exact device IDs, trusted groups, required capabilities, load, and user preference; result still binds an exact key. |
| **Air Spaces** | Personal/team selective sync | Trust groups and scoped knowledge/memory replication with destination-side authorization. |
| **Air Shortcuts** | One automation experience | Unify Workflow + Bind + Scheduler + PubSub with idempotency, recursion, concurrency, time, and cost bounds. |
| **Air Keychain UX** | Reuse authority safely | Synchronize logical references and re-issue destination-bound grants; never synchronize raw secrets or source-bound tokens. |
| **Find Work** | Locate task/session/artifact | Search identity-stamped presence, catalogs, receipts, CAS, and task/session views from Air Home. |

True live session movement is a later protocol, not a UI toggle. It requires a
session v2 with client cursor snapshot/restore, an exact-target single-use
handoff token, owner epochs and fencing, atomic freeze/drain, and backend
context export/import. Exactly-once byte delivery must remain distinct from
exactly-once tool execution.

The product rule remains simple: every new experience uses **a transport-derived
identity, destination-side authority, and one correlation ID across every
receipt-producing boundary**.
