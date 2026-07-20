# meshmcp Policy DSL Specification — v0.1

Status: draft · Format owner: meshmcp · License: open (adopt freely)

This spec defines a declarative language for **what an agent identity may do**:
which tools and methods it may call, how often, when, under what human
approval, and how classified data may flow. It is transport-agnostic — any
enforcement point that can see JSON-RPC and a caller identity can implement it.

## 1. Document

A policy is a YAML (or JSON) object:

```yaml
default_allow: false          # verdict for a tools/call matching no rule
rules:                        # ordered; first match wins
  - <rule>
  - <rule>
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `default_allow` | bool | `false` | Verdict for a `tools/call` that matches no rule. Deny is the safe posture. |
| `rules` | list | `[]` | Ordered rules; the first matching rule decides. |

## 2. Rule

```yaml
- peers:   ["<glob-or-pubkey>", ...]   # caller identities this rule applies to
  tools:   ["<glob>", ...]             # tool names it governs (tool rule)
  methods: ["<glob>", ...]             # OR JSON-RPC methods it governs (method rule)
  allow:   true|false                  # base verdict when matched
  # --- constraints (refine an allow rule; ignored on a deny rule) ---
  rate:           { max: <int>, per: "<duration>" }
  when:           { days: [...], hours: "HH:MM-HH:MM", tz: "<IANA>" }
  require_cosign: true|false
  taint_source:   true|false
  taint_guard:    true|false
  emit_labels:    ["<label>", ...]
  block_labels:   ["<label>", ...]
```

A rule governs **tools** when `tools` is set, or **methods** when `methods` is
set (not both). `peers`, `tools`, and `methods` are lists of matchers.

### 2.1 Matchers

- **Peer**: `pubkey:<key>` matches a caller's exact cryptographic key;
  `group:<name>` matches any caller the enforcement point's group resolver reports
  a member of that named group (role/group-based authorization — resolved from the
  gateway config or a directory/management API, deny if no resolver is attached);
  otherwise a shell glob (`path.Match`) against the caller FQDN. `*` matches any.
  Empty `peers` matches every caller.
- **Tool / Method**: shell glob against the tool name / JSON-RPC method. `*`
  matches any.

### 2.2 Evaluation

For a `tools/call`, rules are scanned in order. A rule is *applicable* when its
peer and tool matchers match AND, if `when` is present, the current time is
inside the window. The first applicable rule decides:

- `allow: false` → **deny**.
- `allow: true` → evaluate constraints in this order, any of which can change
  the outcome:
  1. **block_labels / taint_guard** — if the session carries any blocked label,
     **deny**.
  2. **rate** — if the identity's token bucket for this rule is empty, **deny**.
  3. **require_cosign** — if no valid human co-sign exists, **cosign** (held);
     otherwise continue.
  4. Otherwise **allow**, adding `emit_labels` (and `tainted` if `taint_source`)
     to the session.

If no rule is applicable, the verdict is `default_allow`.

A window-gated rule that is *out of window* is **not applicable** and evaluation
falls through to later rules — it does not deny by itself.

Methods (`methods` rules) are governed only when a method rule matches; an
unmatched method is allowed (so protocol methods like `initialize` are never
blocked by accident). Method rules do not use the constraint fields.

## 3. Constraints

### 3.1 rate — `{ max: int, per: duration }`
A token bucket **per (rule, identity)**. `max` tokens refill linearly over
`per` (Go duration string, e.g. `"1m"`, `"10s"`; empty = `"1s"`). Each matched
call consumes one token; an empty bucket denies.

### 3.2 when — `{ days, hours, tz }`
- `days`: list of `mon|tue|wed|thu|fri|sat|sun`; empty = every day.
- `hours`: `"HH:MM-HH:MM"` local to `tz`; empty = all day. A range whose start
  is after its end is an overnight window (e.g. `"22:00-06:00"`).
- `tz`: IANA name (e.g. `"UTC"`, `"Europe/Berlin"`); empty = UTC.

### 3.3 require_cosign — bool
A matched call is held as **cosign** until a human identity approves the
`(peer, tool)` pair out of band. Approvals MAY expire.

### 3.4 Data-flow labels
Labels model where classified or untrusted data has flowed in a session (a set,
accumulated across calls):

- `emit_labels`: labels this call adds to the session (e.g. `["pii"]`).
- `block_labels`: deny the call if the session already carries any of these.
- `taint_source`: sugar for `emit_labels: ["tainted"]`.
- `taint_guard`: sugar for `block_labels: ["tainted"]`.

This expresses controls no LLM guardrail or ordinary firewall can — e.g. "PII
read from an internal tool may never reach an external-egress tool":

```yaml
- { peers: ["*"], tools: ["read_customer"], allow: true, emit_labels: ["pii"] }
- { peers: ["*"], tools: ["post_external"], allow: true, block_labels: ["pii"] }
```

`taint_guard` on privileged tools + `taint_source` on data-fetching tools is
prompt-injection defense at the network layer: once untrusted data enters the
session, the guarded tool will not be routed, regardless of what the model was
convinced to do.

## 4. Verdicts

`allow` (route it), `deny` (refuse inline with a JSON-RPC error), `cosign` (hold
for human approval; refused to the caller with an explanation until approved).
Every decision SHOULD be written to a §AUDIT-RECORD log.

## 5. Reference implementation

`meshmcp/policy` (`policy.go`, `engine.go`, `cosign.go`). A JSON Schema is in
`policy.schema.json`.
