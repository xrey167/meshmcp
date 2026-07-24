# Security Closure Report

This report maps each reproduced security finding to its root cause, fix,
tests, and residual risk. It is appended to as hardening phases land. Findings
are reproduced against the current tree before any fix is written; a failing
regression test is added first and confirmed to fail on the vulnerable code.

Baseline recorded at start of this work:

- Base commit (earlier review): `b993d5649c3415eac582c29d3be977a5bc3d4a49`
- `go build ./...` — passes (exit 0).
- `go test ./...` — passes except `meshmcp/mcp:TestTaskSteer`, a **pre-existing
  flaky** notification-timing test that fails identically on the base commit
  under load (`-count=3`) and is unrelated to any change here. A fix for it is
  already staged in an unmerged PR (#7, "TestTaskSteer flaky fix"). It is
  recorded here as an existing failure, not one introduced by this work.

---

## F-P1 · ID-less `tools/call` bypasses tool policy — REPRODUCED, FIXED

**Severity:** Critical (authorization bypass; a denied tool reaches the backend).

**Component:** `policy/filter.go` — the per-connection JSON-RPC policy filter.

**Reproduced:** Yes, against the current tree.

### Root cause

`handleLine` classified a JSON-RPC line by the *presence of an `id`* before
classifying it by *method name*:

```go
if len(msg.ID) == 0 {            // (1) no id  -> notification path
    return f.handleNotification(line, msg.Method)
}
if msg.Method == "tools/call" {  // (2) only reached when an id is present
    return f.handleToolCall(line, msg, capToken)
}
```

A `tools/call` sent **without an `id` field** matched branch (1) and was routed
to `handleNotification`, which authorizes by *method policy* (`DecideMethod`).
Method governance is opt-in and does not govern `tools/call`, so
`DecideMethod("tools/call")` returned *allow* with `RuleID == -1` and the call
was forwarded straight to the backend — skipping tool policy, capability
enforcement, hooks, labels, rate limits, co-sign, secret handling, and the
tool-level audit record entirely.

A caller could therefore invoke **any** denied tool simply by omitting the
JSON-RPC id.

A second, related differential: Go's `encoding/json` silently keeps the **last**
of duplicated object keys. A line such as
`{"method":"tools/call","method":"tools/list",...}` was parsed by the filter as
`tools/list` (ungoverned, forwarded), while a backend that keeps the **first**
key would execute `tools/call`. The authorized bytes and the executed request
could diverge on `method`, `id`, or `params.name`.

### Fix

`policy/filter.go`:

1. **Dispatch by method name first.** `tools/call` is now classified by method
   name *before* the id-presence check, so every `tools/call` always enters
   `handleToolCall` and passes through full tool policy.
2. **Reject an id-less / `id: null` `tools/call`** as a protocol-invalid MCP
   request (a `tools/call` is a JSON-RPC *request* and MUST carry a valid,
   non-null id). The rejection is audited as a deny and never forwarded.
   `validRequestID` accepts a string (including `""`) or a number and rejects an
   absent or `null` id.
3. **Reject a `tools/call` with a missing/empty `params.name`** (a wrong-typed
   name already fails the strict peek unmarshal upstream).
4. **Reject duplicate JSON keys at any depth** (`checkNoDuplicateKeys`) on every
   governed line, plus trailing data after the first value, so the strict peek
   and the backend cannot interpret the same payload differently. Ambiguous
   lines are audited and dropped, never forwarded.

The batch, unparseable-line, and oversized-line defenses that already existed
are unchanged and now covered by regression tests.

### Tests (`policy/filter_idless_test.go`)

Each was confirmed to **fail on the vulnerable code** and pass after the fix:

- `TestFilterIDlessToolCallDenied` — id-less denied tool never reaches backend; audited deny.
- `TestFilterIDlessToolCallAllowedRejected` — id-less call is rejected as invalid even for an allowed tool.
- `TestFilterExplicitNullIDToolCall` — `id: null` tools/call rejected.
- `TestFilterEmptyStringIDToolCall` — `""` is a valid id; call goes through tool policy (denied vs allowed).
- `TestFilterNumericAndStringIDToolCall` — numeric/string ids route through tool policy.
- `TestFilterMalformedParams` — number/absent/empty `name`, non-object `params` all rejected.
- `TestFilterDuplicateSecurityKeys` — duplicate `method` / `id` / `params.name` (dangerous value first) rejected.
- `TestFilterBatchRejected` — top-level batch refused.
- `TestFilterOversizedLine` — line past the cap tears the connection down.
- `TestFilterOrdinaryNotificationStillPasses` — genuine notifications still forwarded after the reordering.
- `FuzzFilterClassification` — property test: under a deny-all policy, **no
  input** causes any bytes a lenient parser reads as a `tools/call` to be
  forwarded. Ran 166k+ executions with no failure.

### Commands run

- `go test ./policy/ -run TestFilter -v` — all pass.
- `go test ./policy/ -run FuzzFilterClassification -fuzz ... -fuzztime 15s` — pass (166k execs).
- `go vet ./policy/` — clean.
- `go test -race ./policy/` — pass.
- `go build ./...` — pass.

### Compatibility impact

A client that sent `tools/call` without an id (or with `id: null`) previously
had the call silently forwarded; it now receives a JSON-RPC error
(`-32001`, "missing or null JSON-RPC id"). This is a correctness fix: such a
message is not a valid MCP `tools/call`. No compliant client is affected.
Duplicate-key and trailing-data messages are now rejected; well-formed
JSON-RPC is unaffected.

### Residual risk

- This closes the id-based classification bypass and the duplicate-key
  differential for the stdio policy filter. Enforcement parity across the
  Streamable-HTTP transport (Phase 7) is tracked separately; the HTTP path must
  route through the same classification to inherit this guarantee.
- Definition-of-Done item satisfied: *"An ID-less tools/call cannot bypass tool
  policy."*

### Commit

`policy: close ID-less tools/call bypass and duplicate-key parser differential`

---

## F-P5 · Audit verification over-reports completeness and trust — REPRODUCED, FIXED

**Severity:** High (a false "complete, non-repudiable, verified" claim over an
incomplete or untrusted audit log undermines the product's core security claim).

**Component:** `policy/verify_signed.go` (`VerifySigned`) and its CLI callers in
`audit.go`.

**Reproduced:** Yes, against the current tree (see failing tests below).

### Root cause

`VerifySigned` set `res.OK = true` whenever there was at least one valid
checkpoint, and the CLI (`audit.go`) then printed *"non-repudiable: the log is
complete and unedited, provable with the public key alone."* This was wrong in
four ways:

1. **Uncovered tail.** Records after the last checkpoint's `ToSeq` are unsealed,
   yet `OK=true` was returned and reported as *complete*. A verifier could show
   `covered_records < records` and still call the log complete.
2. **No pinned key required for trust.** With an empty `expectPub`,
   `VerifyCheckpoint` skips the pin check and verifies only the self-signature,
   so a whole-file rewrite re-signed by an *attacker's* key verified as OK and
   was reported "provable with the public key alone."
3. **Duplicate / non-monotonic record sequence numbers** were silently
   collapsed into a map (`hashBySeq[rec.Seq]`), never detected.
4. **Mixed signers.** Without a pin, checkpoints signed by two different keys
   all passed (each self-consistent), so an attacker could append their own
   checkpoints over a rolled-back log.

Additionally, the signed `Count` was trusted for `covered_records` without being
checked against the covered span, so a forged `Count` could inflate coverage.

### Fix

`policy/verify_signed.go`:

- Report **four distinct outcomes** via a new `Status` field (plus `Sealed` and
  `Trusted` booleans): `invalid`, `untrusted_key` (valid but no expected key
  pinned), `unsealed` (valid & trusted but a tail is uncovered), `sealed`
  (valid, trusted, every record covered). `OK` now means only "the checkpoint
  chain is structurally and cryptographically valid."
- **Sealed** requires the last checkpoint to cover the final record with gapless
  coverage from seq 1.
- **Trusted** requires an explicitly pinned `expectPub` (enforced on every
  checkpoint). Without a pin the result is `untrusted_key`, never trusted.
- **Reject** duplicate / non-monotonic record sequence numbers, mixed signers,
  a `Count` that does not equal the covered span, inverted ranges, and lines
  that do not parse as a record.
- Honest doc comment: "gateway-signed tamper-evident decision log"; explicitly
  states it does not prove every real-world action was observed and cannot alone
  defend against a key-holding insider without external anchoring.

`audit.go`:

- `audit verify --checkpoints` now prints a tiered, honest verdict and **exits
  non-zero unless `Status == sealed`** (i.e. valid, fully covered, and pinned to
  an expected key). The false "complete/non-repudiable/with the public key
  alone" line is removed.
- `audit attest` verdict now includes `sealed`, `trusted`, and `status`.

### Tests (`policy/verify_signed_states_test.go`)

Each confirmed to **fail on the vulnerable code** first, pass after the fix:

- `TestSignedVerifyUnsealedTail` — uncovered tail ⇒ `OK` true but `Sealed` false, `Status=unsealed`.
- `TestSignedVerifySealedWhenFlushed` — flushed + pinned ⇒ `OK && Sealed && Trusted`, `Status=sealed`.
- `TestSignedVerifyUntrustedKey` — no pinned key ⇒ `Trusted` false, `Status=untrusted_key`.
- `TestSignedVerifyDuplicateSeq` — duplicate record seq ⇒ invalid.
- `TestSignedVerifyMixedSigners` — checkpoints signed by two keys ⇒ invalid.

Existing tests (`TestSignedVerifyIntact`, `DetectsFullRewrite`,
`DetectsForgedCheckpoint`, `PinsSigner`) still pass unchanged.

### Commands run

- `go test ./policy/ -run 'TestSignedVerify|TestMerkle'` — all pass.
- `go build ./...` — pass. `go vet ./policy/ .` — clean.
- `go test -race ./policy/` — pass. `go test ./...` — pass except the
  pre-existing `mcp:TestTaskSteer` flake.

### Compatibility impact

`meshmcp audit verify --checkpoints` **without `--pubkey`, or over a log with an
unsealed tail, now exits non-zero** (previously exit 0). This is intentional:
such a result is not a trusted, complete verification. Pin `--pubkey <hex>` and
flush a checkpoint to get a `sealed` result and exit 0. The JSON result gains
`sealed`/`trusted`/`status`; existing `ok`/`records`/`covered_records` fields are
unchanged.

### Residual risk

- Sealing and trust are established; **rollback of both the log and its local
  checkpoints by a key-holding insider** is only defended by external anchoring
  (`Anchor` interface / `FileAnchor` exist; a documented external witness is
  still Labs/optional). This limit is now stated in the verifier's own doc and
  the CLI output rather than overclaimed.
- Restart-safe append continuity (parse+verify existing chain, seed the writer
  from the verified tail, refuse to append to an unverifiable log) is a separate
  Phase 5 item, not yet implemented here.

### Definition-of-Done items satisfied

- *"Audit verification cannot report completeness with an uncovered tail."*
- *"Audit trust requires a pinned expected key."*

### Commit

`policy: honest four-state audit verification (sealed/trusted/unsealed/invalid)`

---

## F-P2 · Control plane authorizes any reachable mesh peer — REPRODUCED, FIXED

**Severity:** Critical (privilege escalation; any mesh peer could mint join
credentials, rewrite policy, and mutate the service registry).

**Component:** `control/control.go` (handlers) and `control.go` (`cmdControl`).

**Reproduced:** Yes. The handler performed **no authorization at all**: any peer
that could reach the mesh port could `POST /v1/enroll` (mint a setup key),
`POST/DELETE /v1/registry` (register/deregister services), `PUT /v1/policy/<name>`
(replace a distributed policy), and `GET /v1/policies` / `GET /v1/policy/<name>`
(read administrative state). WireGuard membership was treated as full admin.

### Root cause

`Server.Handler` wired the routes directly to handlers with no identity check.
The engineering principle "WireGuard membership is authentication, not
authorization" was violated: reaching the port was sufficient to administer the
mesh. Additional gaps: policy `PUT` validated only that YAML parsed (not the
full policy validator), no request-body limits, no strict/unknown-field
rejection, and the policy name was taken from the URL with only a `/` check
(weak path-traversal defense).

### Fix

`control/auth.go` (new) + `control/control.go`:

- **Default-deny RBAC** with six roles (`control.admin`, `enrollment.issue`,
  `registry.read`, `registry.write`, `policy.read`, `policy.write`; admin
  implies all). `StaticAuthorizer` maps a **WireGuard public key** (the durable
  identity) to roles; unknown keys hold nothing.
- **Transport-derived identity.** `Server.Identify` resolves the caller's
  WireGuard key from the mesh source address (`client.IdentityForIP`), never
  from headers or the body. Every privileged handler calls `authorize(role)`
  first.
- **Fail closed.** With no authorizer/resolver configured, every privileged
  route returns 403. `cmdControl` **refuses to start** when privileged routes
  are exposed without an `--acl` (no silent fall-back).
- **Audited.** Every allow and deny records actor key, action, target, result,
  reason, and a per-request correlation id.
- **Hardening:** 1 MiB body limits (`MaxBytesReader`), strict JSON decoding
  (`DisallowUnknownFields`), strict policy-name validation (rejects `/`, `\`,
  `..`, leading dot, NUL, non-`[A-Za-z0-9._-]`), and `ValidatePolicy` now uses
  strict YAML (`KnownFields(true)`) **and** the complete `policy.Validate()`.
- **ACL loader** (`LoadAuthorizer`) uses strict YAML and rejects unknown fields,
  unknown roles, empty keys, and an empty grant set, so a typo fails startup.
- Enrollment is gated by `enrollment.issue`; the node label in the body is
  documented as a non-identity label. (A true one-time unjoined-node bootstrap
  credential flow remains a Phase-2 follow-up — see residual risk.)

### Tests (`control/control_rbac_test.go`)

- `TestControlOrdinaryPeerCannotMutate` — an identified peer with no roles gets
  403 on all seven privileged operations; registry and policy state stay empty;
  every denial is audited with the actor key + correlation id.
- `TestControlFailsClosedWithoutAuth` — no authorizer ⇒ all privileged routes
  403; `/healthz` stays open.
- `TestControlRoleGranularity` — `registry.write` does not grant `registry.read`.
- `TestControlIgnoresBodyIdentity` — a body naming an admin actor does not elevate.
- `TestControlUnattributableCallerDenied` — a caller the transport cannot map is denied.
- `TestValidPolicyName`, `TestLoadAuthorizerStrict` — traversal and strict-ACL cases.

Existing happy-path tests now run as an admin caller and pass unchanged.

### Commands run

- `go test ./control/` and `go test -race ./control/` — pass.
- `go build ./...`, `go vet ./control/ .` — clean.
- Full suite green except the pre-existing `mcp:TestTaskSteer` flake.

### Compatibility impact

`meshmcp control` now **requires `--acl <file>`** when it serves any privileged
route; it exits with an error otherwise (previously it served them unauthed).
The local `--addr` dev listener has no mesh transport identity, so its
privileged routes fail closed (403). Example ACL: `examples/control-acl.yaml`.
Migration noted for operators.

### Residual risk / follow-ups (documented, not yet done)

- **Bootstrap flow:** an unjoined node still authenticates enrollment via its
  mesh identity; a separate one-time, short-lived, narrowly-scoped bootstrap
  credential is the intended design and remains a follow-up.
- **Optimistic concurrency** on policy replacement (version/ETag) is not yet
  implemented.
- The Air control endpoint (PR #9) is a separate surface with its own ACL work.

### Definition-of-Done item satisfied

- *"Ordinary mesh peers cannot mutate control or approval state"* (control half;
  the approval-plane half is Phase 2.2 / Phase 3).

### Commit

`control: default-deny transport-derived RBAC on the control plane`

---

## F-P2.2 · Empty approver config = any mesh peer may approve — REPRODUCED, FIXED

**Severity:** High (a low-privilege agent could approve its own held
`require_cosign` call).

**Component:** `approvals.go` (`cmdApprovals`).

**Reproduced:** Yes. `--approver` was optional and documented as *"empty = any
mesh peer"*: when no approver was configured, the `decide` handler's
authorization check (`if authorized != nil && !authorized(r)`) was skipped, so
any mesh peer could `POST /v1/approve` or `/v1/deny`.

### Root cause

The approver ACL was opt-in. An empty operator ACL silently meant "any mesh
peer may approve," so the human-in-the-loop control could be self-satisfied by
the very agent whose call was being held.

### Fix

`cmdApprovals` now **fails closed at startup in mesh mode**: at least one
`--approver` (FQDN glob or `pubkey:<key>`) is required, else it refuses to
start. The approver identity is still derived from the transport (the handler
already did this and ignores caller-supplied identity). The local `--addr` dev
listener (fixed `operator@local`, local bind) is exempt and clearly not a mesh
administrative endpoint.

### Tests

- `TestApprovalsRequiresApproverACLInMeshMode` — mesh mode with no `--approver`
  returns a fail-closed startup error (network-free; guard runs before the mesh
  starts).
- Existing `TestApprovalsOperatorAllowlist` (unauthorized approver ⇒ 403) and
  `TestApprovalsFlow` still pass.

### Compatibility impact

`meshmcp approvals` served on the mesh now requires `--approver`. Deployments
relying on the implicit "any peer" behavior must add an explicit approver ACL.

### Residual risk

- This makes approval *authorization* mandatory. Request-bound, signed,
  single-use approval *objects* (argument-hash binding, TTL, replay protection)
  are Phase 3 and not yet implemented — current approvals remain per-(peer,tool)
  ambient grants with an optional TTL.

### Definition-of-Done item advanced

- *"Ordinary mesh peers cannot mutate control or approval state"* — approval
  half (authorization). The request-binding half is Phase 3.

### Commit

`approvals: require a mandatory approver ACL on the mesh (fail closed)`

---

## F-P6.4 · Router auto-retries unknown-outcome mutating calls — REPRODUCED, FIXED

**Severity:** High (a non-idempotent tool — a payment, a deploy — could execute
twice on failover).

**Component:** `router.go` (`upstreamPool.call`).

**Reproduced:** Yes. `pool.call` failed over to the next replica on **any**
transport error from `uc.Call`, including for `tools/call`, even when the
request had already been dispatched on a live connection and only the *response*
was lost. The regression test drives a replica whose transport dies mid
`tools/call`; on the old code the router silently re-sent the call to a healthy
replica (double execution).

### Root cause

The failover loop did not distinguish "never connected" (request not sent — safe
to try elsewhere) from "dispatched, then transport failed" (ambiguous outcome —
the upstream may have executed the side effect). It also did not distinguish
read-only methods from potentially-mutating `tools/call`.

### Fix

`upstreamPool.call` now:

- Fails over freely when `p.get` fails (the request was never sent on that
  replica).
- On a transport error **after** dispatch, re-sends only methods that are safe
  to repeat (`safeToRetryAfterDispatch`: read-only discovery/read/ping). For a
  potentially-mutating call (`tools/call` and anything unknown) it marks the
  replica down and **returns the ambiguous failure** instead of retrying.
- Idempotency keys that would make a mutating retry safe are not yet enforced
  end-to-end, so `tools/call` stays non-retryable after dispatch (documented).

### Tests (`router_test.go`)

- `TestRouterDoesNotRetryMutatingCallAfterAmbiguousFailure` — dispatched
  `tools/call` + mid-flight transport death ⇒ error surfaced, healthy replica
  executed **0** times. Confirmed failing on the pre-fix code.
- `TestRouterFailsOverReadOnlyAfterDispatch` — a `resources/read` that dies
  mid-flight **is** retried and succeeds once (fix does not break safe failover).
- Existing `TestRouterFailsOverToHealthyReplica` (dead/refused replica) still
  passes — pre-send failover is unchanged.

### Commands run

`go test . -run TestRouter` ✓ · `go test -race .` ✓ · `go build ./...` ✓ ·
`go vet .` ✓.

### Compatibility impact

A `tools/call` that fails with a transport error after being dispatched now
returns an error to the caller instead of transparently retrying. The caller
must decide whether to retry (ideally with an idempotency key). Read-only
failover is unchanged.

### Residual risk / follow-up

- Full tool retry classification with **enforced** idempotency keys across the
  gateway/backend contract (so idempotent mutating calls can safely retry) is
  the remaining Phase-6 work. The current fix is the safe default (no retry).

### Definition-of-Done item satisfied

- *"Unknown-outcome mutating calls are not automatically retried."*

### Commit

`router: do not auto-retry unknown-outcome mutating calls on failover`

---

## F-P9.1 · Gateway config silently ignores misspelled security fields — REPRODUCED, FIXED

**Severity:** Medium-High (a mistyped security control fails open — the operator
believes it is enabled but it never fires).

**Component:** `config.go` (`loadConfig`).

**Reproduced:** Yes. `loadConfig` used `yaml.Unmarshal`, which silently ignores
unknown keys. A typo such as `audit_fail_clsoed`, `defualt_allow`,
`require_cosgin`, or `taint_gaurd` was dropped with no error, so the intended
control simply did not apply.

### Fix

`loadConfig` now decodes with `yaml.NewDecoder(...).KnownFields(true)`, so an
unknown/misspelled/misplaced key is a startup error. Verified that **all 20 real
gateway example configs** (every `examples/*.yaml` with a top-level `backends:`)
still load; the non-gateway configs (router, pubsub, air, federation, …) use
their own structs and are unaffected.

### Tests (`config_test.go`)

- `TestConfigStrictRejectsSecurityTypos` — misspelled `audit_fail_closed`,
  `default_allow`, `require_cosign`, and `taint_guard` each fail startup;
  the valid base config loads.
- `TestExampleGatewayConfigsLoadStrictly` — every gateway example still loads
  under strict decoding (guards against over-strictness).

### Compatibility impact

A config with an unknown/misspelled key now fails to start (previously ignored).
This is the intended fail-closed behavior; operators must fix typos. All shipped
example gateway configs are unaffected.

### Residual risk / follow-up

- This covers the gateway config. Extending strict decoding uniformly to the
  other subsystem configs (router, pubsub, air, federation) plus invalid
  duration/timezone/TTL negative tests is the remaining Phase-9 work. (The
  control-plane ACL loader already uses strict decoding — see F-P2.)

### Definition-of-Done item satisfied

- *"Security configuration typos fail startup"* (gateway config).

### Commit

`config: strict YAML decoding so security-field typos fail startup`

---

## F-P3 · Co-sign approval is ambient, not request-bound — REPRODUCED, FIXED (core)

**Severity:** High (an approval for one operation authorizes any other call to
the same tool — approving `transfer($10)` also authorizes `transfer($10000)`).

**Component:** `policy/engine.go` (co-sign decision) + `policy/filter.go`.

**Reproduced:** Yes. `DecideToolCall` consulted `Approved(CosignKey(peer, tool))`
— keyed only on `(peer, tool)` — and never received the arguments, so a single
human approval authorized every subsequent call to that tool by that peer,
regardless of amount/path/target, until TTL. Approvals were also not single-use.

### Fix

New request-bound approval primitive (`policy/approval_token.go`):

- `ApprovalToken` bound to and signed over `peer_key, backend, tool, args_hash,
  session, nonce, decision, approver, policy_hash, created_at, expires_at`.
- `canonicalArgsHash` canonicalizes JSON arguments (sorted keys) so key-order /
  whitespace do not break a legitimate approval, but any value change does.
- `FileApprovalStore`: signed `0600` tokens; **atomic single-use** consume via
  `rename` (exactly one concurrent consumer wins; replays find nothing); TTL
  default 5 min, clamped ≤ 1 h, non-disableable (zero → default); Ed25519 signed
  and verified against a pinned key.

Wired into enforcement:

- `Engine.SetRequestApprovals` + `DecideToolCallBound` consume an argument-bound
  approval for a `require_cosign` rule; falls back to the legacy ambient store
  when none is attached (existing behavior/tests preserved).
- `Filter.handleToolCall` calls `DecideToolCallBound` with the backend and the
  actual arguments.

### Tests (`policy/approval_token_test.go`)

Argument binding, canonical-args stability, single-use, **concurrent
single-winner** (race-clean), backend binding, TTL (expiry + non-disableable +
clamp), signature/pinning, `0600` perms, and an **end-to-end filter** test
(un-approved → co-sign; approved exact args → forwarded once; different args →
not forwarded; replay → not forwarded).

### Compatibility impact

None by default: with no request-approval store attached, the legacy ambient
co-sign path is unchanged. A gateway opts in by attaching a `FileApprovalStore`.

### Residual risk / follow-up

- The approver-service grant wiring (the last mile) lands in **F-P3.2** below.
  Now closed.
- Spec: `docs/spec/APPROVAL-TOKEN.md`.

### Definition-of-Done item satisfied

- *"Approvals are signed, short-lived, request-bound and single-use"* (the
  enforcement primitive and gateway path here; end-to-end approver wiring in
  **F-P3.2**).

### Commit

`policy: request-bound, signed, single-use co-sign approval tokens`

---

## F-P6.1 · Session ownership is load-then-save, no fencing — REPRODUCED, FIXED (store layer)

**Severity:** High (two gateways can concurrently believe they own a session —
split-brain — and a superseded gateway can keep writing).

**Component:** `session/store.go`, `session/server.go`.

**Reproduced:** Yes. `Server.checkpoint` persisted ownership with an
**unconditional** `store.Save` (`ps.Owner = s.instance`), with no
compare-and-swap, no lease expiry, and no fencing generation. Two gateways can
both `Load` a session and both `Save` it (last write wins); a gateway that lost
ownership keeps overwriting state. The `FileStore` doc also over-claimed
cross-gateway hand-off ("HA").

### Fix

Add an atomic CAS lease primitive (`session.LeaseStore`) implemented by both
`MemStore` and `FileStore`:

- `AcquireLease(id, owner, expectedGen, ttl, now)` — grants ownership only when
  no live lease is held by another owner AND `expectedGen` matches the stored
  generation (optimistic concurrency), and **increments** the generation. Two
  racing takeovers of an expired lease cannot both win.
- `RenewLease` / `ReleaseLease` / `SaveIfOwned` — require the presented
  `(owner, generation)` to still match; a superseded owner (stale generation) is
  **fenced** out of writes.
- Monotonic fencing generation + `LeaseExpiry` fields added to
  `PersistedSession` (`omitempty`, backward-compatible).
- `FileStore` performs each CAS under its cross-process lock (read-modify-write
  is atomic for a single host / lock-correct shared filesystem). Its doc now
  states plainly it is single-node development, **not** cross-gateway HA;
  production needs a real CAS backend (PostgreSQL, etcd, Redis).

### Tests (`session/lease_cas_test.go`, run against **both** stores)

- `TestLeaseMutualExclusion` — a live lease cannot be acquired by another owner.
- `TestLeaseFencingStaleOwnerCannotWrite` — after takeover, the old owner's
  `SaveIfOwned` fails; the new owner's succeeds.
- `TestLeaseConcurrentAcquireSingleWinner` / `TestLeaseConcurrentTakeoverSingleWinner`
  — exactly one of 24 racing gateways wins (fresh lease and expired-lease
  takeover). Race-clean.
- `TestLeaseRenewAndRelease` — renew/release reject wrong owner or stale gen.

### Compatibility impact

None: existing `Save`/`Load`/`DeleteIfOwner` and all session tests are unchanged;
the lease API is additive.

### Residual risk / follow-up

- Store-layer primitive only; the server-side wiring (checkpoints through
  `SaveIfOwned`, fence-on-supersede, takeover-on-reattach) lands in **F-P6.1w**
  below. Now closed.

### Definition-of-Done item satisfied

- *"Two gateways cannot concurrently own the same production session"* — enforced
  and proven at the store layer here, then wired into the running server in
  **F-P6.1w**.

### Commit

`session: atomic CAS ownership lease with fencing generation`

---

## F-P4 · Router is an unrestricted confused deputy — REPRODUCED, FIXED (primitive)

**Severity:** High (any caller reaching the router can drive any upstream tool
with the router's authority; the router can widen a caller's scope).

**Component:** `router.go` (forwarding), `policy/delegation.go` (new).

**Reproduced:** Yes. The router forwards under its own WireGuard identity and
conveys the downstream caller only as unsigned `_meta`; the proxy tool handlers
(`registerProxyTool` → `pool.call`) apply no caller identity or policy. The
router is a confused deputy.

### Fix (design + enforcement primitive)

Signed delegation tokens with scope intersection (`policy/delegation.go`):

- `DelegationToken` signed over `caller, router, audience, backend, tool,
  req_hash, nonce, exp` (lifetime capped at 5 min) by a **pinned** trusted
  router authority.
- `VerifyDelegation` binds a token to the exact hop and rejects: a non-authority
  signer (empty pin never verifies), a different audience/backend/tool, a
  different presenting router, changed arguments, expiry, and a replayed nonce
  (`NonceStore`).
- `AuthorizeDelegated` computes the upstream decision as the **intersection** of
  original-caller policy ∩ router-service policy ∩ delegation — so a router
  cannot widen a caller's authority and a caller cannot exceed the router's.

### Tests (`policy/delegation_test.go`)

Forged origin metadata; delegation for another backend/audience; changed
arguments; expired (+ lifetime cap); replayed nonce; wrong presenting router;
router-exceeds-caller and caller-exceeds-router intersection; nested hops
(first-hop token does not authorize a second hop); compromised-router-widening
(tamper breaks the signature). Race-clean.

### Compatibility impact

None yet — additive primitive. Router/federation remain **experimental** until
wired.

### Residual risk / follow-up

- The router does not yet mint tokens per hop, and upstreams do not yet call
  `VerifyDelegation`/`AuthorizeDelegated` in the proxy path; the minimum interim
  hardening (default-deny **caller ACL** on the router + full tool policy at the
  router) ships with the wiring. Both identities must be preserved in the audit
  record when wired. Design + status: `docs/spec/ROUTER-DELEGATION.md`.

### Definition-of-Done item

- *"Router forwarding cannot widen a downstream caller's authority"* — the
  enforcement primitive (intersection + signed, hop-bound, single-use tokens) is
  implemented and proven; the router/upstream wiring is the documented follow-up.

### Commit

`policy: signed router/federation delegation tokens + scope intersection`

---

## F-P8 · A backend can echo an injected secret back to the agent — REPRODUCED, FIXED

**Severity:** Medium-High (defeats credential isolation: the agent references a
secret by name but the backend replies with the raw value).

**Component:** `policy/filter.go` (response pump), `policy/redact.go` (new),
`secrets/broker.go`, `policy/secret.go` (interface).

**Reproduced:** Yes. Secret injection substituted the real value into the request
toward the backend, but the backend→agent response stream was forwarded verbatim.
A backend that echoes its arguments returns the injected credential to the agent.
`TestFilterRedactsEchoedSecret` demonstrates it.

### Fix

Response-side redaction:

- New `Redactor` (`policy/redact.go`): a concurrency-safe set of injected secret
  byte-values with a `Redact` method; ignores values shorter than 4 bytes (no
  over-matching) and is nil-safe (no-op).
- The `SecretResolver.Resolve` interface now also returns the **injected values**
  (raw and JSON-escaped forms — the broker reports both). These bytes are for
  in-memory redaction only and are never audited, traced, or logged.
- The filter records injected values in a per-session redactor and scrubs them
  from every backend→peer line **before** it reaches the trace or the agent
  (`pumpInner`), replacing them with `[redacted-secret]`.

### Tests (`policy/redact_test.go`)

- `TestRedactorBasic`, `...MultipleAndUnicode`, `...IgnoresShortAndNoMatch`,
  `...NilSafe` — unit coverage incl. multiple secrets, Unicode, short-value and
  no-match passthrough.
- `TestFilterRedactsEchoedSecret` — end-to-end: a backend echoes the injected
  secret; the agent-visible response carries the placeholder, not the value; the
  backend really received the injected value (proving redaction is response-side,
  not a failure to inject). Race-clean.

### Compatibility impact

Interface change to `SecretResolver.Resolve` (now returns injected values); only
the `secrets.Broker` implements it (updated). Redaction is automatic once a
secret is injected.

### Residual risk

- Best-effort echo defense, **not** a leak-proof guarantee: a malicious backend
  can transform/split/exfiltrate a value out of band and remains within the
  secret's exposure boundary (documented in the threat model). Prefer short-lived
  scoped credentials. Backend egress restriction is a follow-up.

### Definition-of-Done / mission item

- Phase 8: *"Add response-side detection or redaction for injected values"* and
  *"Prevent backends from trivially echoing injected credentials where feasible."*

### Commit

`policy: response-side redaction of injected secret values`

---

## F-P9.2 · Capability revocation fails OPEN when the store is unavailable — REPRODUCED, FIXED

**Severity:** High (a revoked or unverifiable capability can widen a default deny
when the revocation store is unreachable).

**Component:** `policy/revocation.go`, `serve.go`.

**Reproduced:** Yes. `FileRevocation.IsRevoked` returned `os.Stat(...) == nil`,
so **any** stat error — a missing/unreadable revocation directory, an I/O or
permission failure — was read as "not revoked" (`false`). If the revocation
store went away, every capability sailed through even though its revocation
state was unknown. Capabilities are used precisely to widen a default deny, so
this is fail-open at the worst point.

### Fix

`IsRevoked` now **fails closed**: a malformed id, an unreachable/non-directory
store, or a lookup error all return `true` (treated as revoked). Only a
reachable store with no marker for the id returns `false`. `NewFileRevocation`
creates the store directory at startup, so a later-missing directory means the
store was **lost** (fail closed), not merely "never used". `serve.go` uses the
constructor and **fails startup** if the configured store cannot be created.

### Tests (`policy/revocation_test.go`)

- `TestRevocationFailsClosedWhenStoreUnavailable` — a missing store dir, a
  corrupt (non-directory) store, and a malformed id all fail closed; a reachable
  empty store still reports not-revoked. (Case 1 fails on the pre-fix code.)
- `TestRevocationVerifierFailsClosedOnUnavailableStore` — end-to-end: a valid
  capability is rejected by the verifier when its revocation store is
  unavailable.
- Existing `TestFileRevocationFailsClosedInVerifier` still passes.

### Compatibility impact

A configured revocation store that becomes unreachable now denies capabilities
(previously allowed them). This is the intended fail-closed behavior. The normal
reachable-empty-store case is unchanged.

### Definition-of-Done / mission item

- Phase 9.2: *"Revocation lookup failures must fail closed when capabilities are
  being used to widen a default deny."* — and *"Capability revocation failures
  cannot widen access."*

### Commit

`policy: capability revocation fails closed when the store is unavailable`

---

## F-P7 · stdio and HTTP enforcement drift — REPRODUCED, FIXED

**Severity:** High (a request hardened on stdio was softer over HTTP: the Phase-1
protections applied to stdio only).

**Component:** `policy/classify.go` (new), `policy/filter.go`, `httppolicy.go`.

**Reproduced:** Yes. The stdio `Filter` (post Phase-1) rejects an id-less /
null-id / empty-name / duplicate-key `tools/call` and governs methods, but the
HTTP `httpEnforcer.decide` only checked `msg.Method == "tools/call"` and then
`DecideToolCall`. Over HTTP an **id-less tools/call for an allowed tool was
forwarded**, a duplicate-key smuggle passed, and governed non-tool methods
(e.g. `tasks/cancel`) passed through — different decisions than stdio for the
same request and identity.

### Fix

Introduce a single shared classifier, `policy.ClassifyRPC`, as the source of
truth for how a JSON-RPC line classifies (batch / invalid / tool-call /
notification / method) and which are protocol-invalid. Both transports route
through it:

- `policy/filter.go` `handleLine` now dispatches on `ClassifyRPC` (the stdio
  Phase-1 logic, unchanged in effect); `handleToolCall`/`handleMethod` take the
  classified fields.
- `httppolicy.go` `decide` now uses `ClassifyRPC` too — rejecting id-less /
  null-id / empty-name / duplicate-key tool calls and batches identically, and
  governing non-tool methods with `DecideMethod` like stdio.

### Tests

- `conformance_test.go` `TestStdioHTTPConformance` — 9 cases (allowed/denied
  tool, id-less, null-id, empty name, duplicate key, batch, governed method,
  ungoverned method) asserting the stdio filter and the HTTP enforcer reach the
  **same** allow/deny outcome for the same request+identity. This fails on the
  pre-fix HTTP path for the id-less/null-id/empty-name/dup-key/governed-method
  cases.
- All existing filter and HTTP-enforcer tests still pass; policy + root race-clean.

### Compatibility impact

The HTTP path now rejects malformed/ambiguous tool calls and enforces method
rules it previously ignored — a security tightening. Well-formed traffic is
unaffected.

### Residual risk / follow-up

- ~~Taint labels, secret injection, and capability upgrades remain on the stdio
  path~~ — **closed (task 9, HTTP parity slice v1)**: the HTTP/remote enforcer
  now tracks per-session taint labels (keyed by the transport-proven peer key +
  `Mcp-Session-Id`; a label-bearing policy DENIES a session-less `tools/call`
  rather than silently skipping), injects secrets after audit with per-peer
  response redaction (JSON buffered, SSE line-streaming; an unscannable
  compressed/oversized response is refused 502), folds capabilities through the
  shared `policy.FoldCapability` (token stripped from every governed body), and
  records `args_hash`/`policy_hash` on held co-signs. Honest residuals, matching
  or strictly tightening stdio: labels attach at decision time (same as stdio);
  redaction is best-effort under the same threat model; a fresh session id
  starts label-clean (≈ a stdio reconnect) and idle label state expires after
  24h; per-peer session-state caps DENY new sessions (never evict). DLP, shadow
  policies, and router delegation remain stdio-only and config-refused for
  HTTP/remote backends. Gateway `hooks:` decision events (bus/webhook) are
  emitted by the stdio filter only — HTTP/remote decisions are recorded in the
  audit ledger (including capabilities-only backends, which resolve the shared
  ledger or their own `audit_log` like any policy backend) but not published on
  the event bus; wiring the event hook into the HTTP enforcer is a follow-up.

### Definition-of-Done item satisfied

- *"Stdio and HTTP enforce the same declared controls"* (classification, tool/
  method decisions, taint labels, secret injection + redaction, capabilities;
  DLP/shadow/router-delegation remain stdio-only and are refused in config,
  never silently unenforced).

### Commit

`policy: shared JSON-RPC classifier for stdio/HTTP enforcement parity`

---

## F-R1..R4 · Correctness defects in shipped primitives (review follow-up) — FIXED

A code review found real correctness bugs in the primitives above. Each is fixed
with a regression test.

- **R1 — argument-hash integer collision.** `canonicalArgsHash` decoded numbers
  through `float64`, so distinct integers above 2^53 (e.g. two large amounts)
  collided to the same hash — an approval/delegation bound to one amount could
  match another. Now decodes with `UseNumber()` (exact) and rejects trailing
  data. Test: `TestApprovalArgsHashIntegerPrecision` (2^53+1 vs 2^53+2). Applies
  to both approval tokens and delegation `req_hash`.
- **R2 — redactor lazy-init data race.** `Filter.redactor` was created lazily in
  the `Write` goroutine while `pumpInner` read it concurrently. It is now created
  at filter construction (always non-nil); the lazy init is removed. Verified
  under `-race`.
- **R3 — HTTP audit not fail-closed.** The HTTP enforcer discarded audit-write
  errors, so `audit_fail_closed` did not fail closed there. It now denies an
  allowed `tools/call`/method when the record cannot be written and the log is
  fail-closed, matching stdio. Test: `TestHTTPEnforcerFailsClosedOnAuditError`.
- **R4 — audit chain linkage unverified.** `VerifySigned` recomputed hashes but
  never compared the stored `Hash` or verified `PrevHash` linkage, so a tampered
  record in the unsealed tail (not Merkle-covered) went undetected. It now
  verifies, per record, that the stored hash matches the content and that
  `PrevHash` links to the previous record — the whole chain (including the tail)
  is validated. Tests: `TestSignedVerifyDetectsBrokenLinkage`,
  `TestSignedVerifyDetectsTailTamper`; and `TestSignedVerifyDetectsFullRewrite`
  now genuinely re-hashes the plain chain to prove only the signed Merkle root
  catches an insider rewrite.

### Commit

`policy: fix review-found defects (arg-hash precision, redactor race, HTTP fail-closed, audit linkage)`

---

## F-P5.1 · Audit chain reset on gateway restart — REPRODUCED, FIXED (wired)

**Severity:** High (a restart silently forks the audit chain — a second `seq 1`
and a fresh checkpoint root in the same file — making it unverifiable).

**Component:** `serve.go` (audit + checkpoint construction).

**Reproduced:** Yes. `serve.go` opened the audit and checkpoint files in append
mode but constructed the `AuditLog`/`Checkpointer` with sequence and checkpoint
state at zero. After a restart the next record was `seq 1` again and a new
checkpoint chain (`prev_checkpoint: ""`) began in the same file.

### Fix (runtime wiring)

- `seedAuditFromExisting` reads and **verifies** the existing log (`VerifyChain`)
  and returns its tail `(seq, lastHash)`; `seedCheckpointFromExisting` returns
  the last checkpoint's ordinal + hash. Both are wired into the shared-audit,
  per-backend-audit, and checkpointer construction paths, calling
  `AuditLog.SeedFrom` / `Checkpointer.SeedFrom` so a restart continues the SAME
  chain.
- **Fail closed:** if the existing log does not verify, startup **refuses to
  append** (rather than silently resetting the chain).

### Tests (`serve_restart_test.go`)

- `TestAuditRestartContinuity` — write 4 records + a checkpoint, "restart" via
  the seed helpers, write 4 more; the combined file verifies as one **sealed,
  trusted** chain with 8 contiguous records, 2 checkpoints, and exactly one
  `seq 1`.
- `TestAuditRestartRefusesTamperedLog` — seeding refuses a tampered existing log.

### Definition-of-Done item satisfied

- *"Restarting a gateway does not silently break its audit chain."*

### Commit

`serve: seed audit + checkpoint chain from the verified tail on restart`

---

## F-P3.1 · Approval binding gaps + unprotected approver endpoints (review) — FIXED

**Component:** `policy/approval_token.go`, `policy/engine.go`, `approvals.go`.

Review follow-ups on the request-bound approval work:

- **Session binding.** `bindingKey` now includes the session id, so an approval
  for one session cannot be consumed under another. Test:
  `TestApprovalSessionBinding`.
- **Policy-version binding.** `ApprovalToken`/`ApprovalRequest` carry a policy
  hash; `ConsumeApproval` rejects a token whose policy hash differs from the
  request's (both non-empty) — an approval granted under one policy is not
  honored after the policy changes. The engine computes and passes its policy
  hash (`Engine.PolicyHash`, cached). Test: `TestApprovalPolicyHashBinding`.
- **Approver endpoint protection.** `/v1/pending` (enumerating every held
  request) is now approver-ACL-only; `/v1/status` is restricted to the requester
  (own peer) or an authorized approver, so a peer cannot probe another's
  approvals. `/v1/request` remains the framework-facing ask (a proxy legitimately
  registers on behalf of a named agent); its security controls are downstream
  (approve/deny are ACL-gated; grants are request-bound + single-use). Test:
  `TestApprovalsEndpointsProtected`.

Remaining (tracked): the approver service does not yet *grant* a request-bound
token, and `serve.go` does not yet attach a `FileApprovalStore` — closed in
**F-P3.2** below.

### Commit

`approvals: session + policy-version binding; protect pending/status endpoints`

---

## F-P3.2 · Request-bound approvals not wired to the approver or the gateway — FIXED (wired)

**Severity:** High (the request-bound primitive and the gateway decision path
existed, but nothing minted request-bound tokens and `serve.go` never attached a
store — so in production a `require_cosign` call was still released by an
**ambient** `(peer, tool)` grant, not one bound to the exact arguments. The
hardened path was unreachable end-to-end).

**Component:** `policy/pending.go`, `policy/filter.go`, `approvals.go`,
`serve.go`, `config.go`.

**Reproduced:** Yes. `Engine.SetRequestApprovals` + `DecideToolCallBound`
consumed argument-bound approvals, but (a) `Pending` carried no argument/policy
binding, (b) the approver's `/v1/approve` only wrote an ambient `policy.Grant`,
and (c) no runtime path called `SetRequestApprovals`. So a gateway that opted in
could never have a held call released (the approver's ambient grant is ignored in
request-bound mode); a gateway that did not opt in bound approvals only to
`(peer, tool)`.

### Fix (runtime wiring, opt-in, fail-closed)

- **Held call carries its binding.** `Pending` gains `ArgsHash` + `PolicyHash`;
  the filter records `canonicalArgsHash(args)` and `Engine.PolicyHash()` on every
  held `require_cosign` call. `Pending.ApprovalRequest()` rebuilds the exact
  request-bound operation, so the approver never needs the raw arguments or a copy
  of the policy.
- **Approver mints the token.** With a shared signing key
  (`meshmcp approvals --approval-key`), `/v1/approve` reads the held record and
  calls `FileApprovalStore.Grant`, minting a signed, single-use approval bound to
  the exact arguments + policy version. A grant with no held request-bound call
  fails closed (`409`), never a silent ambient-only fallback. The ambient grant
  is still written for backward compatibility / the `/v1/status` view.
- **Gateway enforces it.** A new backend config `approval_signing_key` (the
  Ed25519 key SHARED with the approver) makes `serve.go` load the key
  **fail-closed** and call `eng.SetRequestApprovals(NewFileApprovalStore(...))`.
  Once set, ambient co-sign no longer releases held calls — only a request-bound
  token does. `config.go` rejects `approval_signing_key` without `cosign_store`
  (a security-config error must fail startup).

### Key model (explicit, not silent)

Gateway and approver share one Ed25519 key file: the approver signs minted
approvals; the gateway pins that public key to trust them. It is **opt-in** — with
no `approval_signing_key` / `--approval-key`, the ambient co-sign path is
unchanged, so no existing deployment changes behavior.

### Tests

- `approvals_test.go`
  - `TestApproverMintsRequestBoundApproval` — a held call recorded as the filter
    writes it, approved via `/v1/approve` with a request-bound store, yields a
    token the gateway consumes for the **exact** arguments, refuses a
    different-argument call, is single-use, and clears the pending record.
  - `TestApproverRequestBoundNoHeldCall` — approving with no held request-bound
    call fails closed (`409`), never an unbound grant.
- `config_test.go`
  - `TestConfigApprovalKeyRequiresCosignStore` — `approval_signing_key` without
    `cosign_store` fails startup; paired, it validates.
- Existing `policy.TestFilterRequestBoundCosignEndToEnd`,
  `TestApprovalPolicyHashBinding`, and the approver-endpoint/ACL tests are
  unchanged and still pass (argument, policy, single-use, and endpoint-protection
  guarantees).

### Compatibility impact

None by default. The new `Pending` fields are `omitempty`; the approver option
and the gateway config are opt-in; the ambient path is preserved when the key is
absent.

### Residual risk / follow-up

- The pending file is keyed by `(peer, tool)`, so two concurrently-held calls to
  the same tool with different arguments collapse to the latest record; the other
  stays blocked (fail-closed) until re-requested. Keying pending by the full
  binding is a future refinement. Logged, not silent.
- Distributing the shared approval key across hosts is an operator concern (same
  as any signing key); single-operator setups share one file over the mesh.

### Definition-of-Done item satisfied

- *"Approvals are signed, short-lived, request-bound and single-use"* — now
  reachable end-to-end: the human approver mints the argument-bound token and the
  gateway enforces it in place of ambient co-sign.

### Commit

`approvals: wire request-bound grant end-to-end (approver mints, gateway enforces)`

---

## F-P4.Air · Air control default-allows on empty ACL + arbitrary steer methods — FIXED (wired)

**Severity:** High (any mesh peer could list and steer live sessions; a steer
could inject arbitrary server->client methods).

**Component:** `aircontrol.go`, `acl.go`, `serve.go`.

**Reproduced:** Yes. The Air control endpoint gated on `acl.allows`, which
returns true for an empty pattern list, so an unconfigured ACL admitted any
identified mesh peer. The steer method was unrestricted.

### Fix

- **Default-deny:** the Air handler treats an **empty ACL as deny-all**
  (`acl.empty()`), so an operator must explicitly allowlist steerers.
- **Startup guard:** `serve.go` refuses to start the Air control endpoint when
  `control.allow` is empty.
- **Steer method allowlist:** only `notifications/*` (server->client
  notifications) may be steered; a server->client request (`sampling/*`,
  `roots/list`, …) or any other method is rejected and audited.

### Tests (`aircontrol_test.go`)

- `TestAirControlEmptyACLDeniesAll` — empty ACL ⇒ 403 on sessions and steer.
- `TestAirControlSteerMethodAllowlist` — `sampling/createMessage`, `tools/call`,
  `roots/list`, `initialize` all rejected. Existing Air tests updated to an
  explicit allowlist (default-deny) and pass.

### Commit

`air: default-deny control ACL + steer-method allowlist`

---

## F-P8.2 · Secret injection regex-replaces across the whole message — FIXED

**Severity:** Medium (a marker outside declared arguments could be substituted;
injection was not bound to a declared argument location).

**Component:** `secrets/broker.go`.

**Reproduced:** Yes. `Resolve` ran `refRe.ReplaceAllFunc` over the entire raw
JSON line, so a `{{secret:NAME}}` marker anywhere (method, id, params.name,
_meta) would be resolved, and there was no argument-location binding.

### Fix

- Injection is **confined to `params.arguments`**: the request is parsed, and
  markers are collected and substituted only in string values within arguments.
  A marker anywhere else is left literal and never resolved.
- `replaceMarkers` rebuilds the arguments value and `json.Marshal` re-escapes
  each secret, so a value with quotes/backslashes/newlines cannot break the
  message.
- New `Grant.Locations` binds a grant to declared argument paths (dotted globs,
  e.g. `headers.*`); a secret reference at a non-matching location is denied.

### Tests (`secrets/broker_test.go`)

- `TestBrokerOnlyInjectsIntoArguments` — a marker in `params.name` stays literal;
  the argument marker is injected.
- `TestBrokerLocationBinding` — allowed at `headers.*`, denied elsewhere.
- `TestBrokerNestedAndMultiple` — nested objects/arrays, multiple secrets,
  Unicode. Existing broker tests still pass.

### Commit

`secrets: inject only into declared argument locations, not whole-message regex`

---

## F-P4.2 · Router serves any mesh peer (confused deputy) — FIXED (caller ACL)

**Severity:** High (any mesh peer could drive any upstream tool through the
router under the router's identity).

**Component:** `router.go`.

**Reproduced:** Yes. `handleRouterConn` served every connecting mesh peer with no
caller ACL.

### Fix (the mission's "at minimum" for delegation)

- New `RouterConfig.Allow` — a **default-deny** caller ACL (`pubkey:<key>` or FQDN
  globs). `loadRouterConfig` **fails startup** when it is empty.
- `handleRouterConn` derives the caller's WireGuard identity and rejects any
  caller not on the allow list (`routerCallerAllowed`; empty ACL admits no one),
  so the router can no longer act as an unrestricted confused deputy.
- Example router configs updated with an `allow` list.

### Tests (`router_test.go`)

- `TestRouterRequiresAllowList` — config without `allow` fails to load;
  `routerCallerAllowed` denies on empty ACL, admits a listed caller, denies an
  unlisted one.
- `TestRouterExampleConfigsLoad` — shipped example router configs load.

### Residual risk

Full tool policy at the router and signed, hop-bound delegation to upstreams
(so upstream policy computes caller ∩ router ∩ delegation) remain the next step
— the primitive exists (`policy/delegation.go`) and is tracked in
`docs/spec/ROUTER-DELEGATION.md`. The caller ACL removes the open-deputy exposure.

### Commit

`router: default-deny caller ACL (close open confused-deputy exposure)`

---

## F-P6.1w · Session ownership lease wired into the running server — FIXED (wired)

**Severity:** High (until wired, the CAS lease existed but the server still
checkpointed via unconditional `Save`: two gateways could still both write — and
thus both execute — the same session, and a superseded gateway was never fenced).

**Component:** `session/server.go`, `session/store.go`.

**Reproduced:** Yes. Before this change `Server.checkpoint` called
`s.store.Save(ps)` unconditionally, so a gateway that had been superseded kept
overwriting the new owner's persisted state.

### Fix (runtime wiring)

- `Server` detects a lease-capable store (`WithStore` type-asserts `LeaseStore`)
  and records the fencing generation it holds per session (`serverSession.leaseGen`).
- **Open (fresh session):** `attach` calls `AcquireLease(id, instance, 0, ttl, now)`
  before pumping; a store error degrades to serving without migration rather than
  failing the client.
- **Reattach / failover:** `rehydrate` calls a new **`TakeoverLease`** primitive
  *before* spawning the backend. `attach` has already verified the reattach
  carries the session **creator's** transport identity, so this is an authorized
  takeover: it bumps the fencing generation (fencing the previous gateway) and,
  among racing takers, only one wins the generation CAS. A lost race fails the
  reattach cleanly with no wasted backend spawn.
- **Every checkpoint:** writes go through `SaveIfOwned(ps, instance, leaseGen)`.
  When it reports the lease is no longer held, the gateway logs the supersede and
  **yields the session** (`go s.remove`), so a fenced gateway stops serving and
  the same session is never driven by two gateways at once.
- `TakeoverLease` is deliberately distinct from `AcquireLease`: unlike acquire it
  does not refuse a still-*live* lease (a client-driven migration must not wait
  out the whole TTL), but it keeps the generation CAS so a takeover can never
  split-brain into two owners. It is gated on a verified creator-identity
  reattach — it is not a general lease-steal.

### Tests

- `session/lease_cas_test.go`
  - `TestLeaseTakeover` — `AcquireLease` cannot steal a live lease, but an
    identity-bound `TakeoverLease` can, bumps the generation, fences the old
    owner, and rejects a stale-generation takeover.
  - `TestLeaseConcurrentTakeoverLiveSingleWinner` — 24 gateways racing to take
    over the same *live* lease: exactly one wins.
- `session/server_lease_test.go`
  - `TestServerCheckpointFencedAfterTakeover` — once a second gateway takes the
    session over, the original gateway's `checkpoint` is fenced and cannot
    overwrite the new owner's persisted state.
- `session/migration_test.go` — `TestSessionMigratesAcrossGateways` still passes,
  now exercising the full acquire → takeover → `SaveIfOwned` path end-to-end
  (unchanged assertions; not weakened).

### Compatibility impact

None. A store that does not implement `LeaseStore` still uses the best-effort
`Save` path. `MemStore`/`FileStore` gain `TakeoverLease`; all prior session and
lease tests are unchanged.

### Residual risk / follow-up

- The lease TTL equals the session TTL and is not renewed per-checkpoint, so a
  session served continuously past its TTL runs on a lapsed (but still owned)
  lease; writes still succeed via owner+generation match, and takeover still
  requires an authenticated reattach, so this is benign. Per-checkpoint renewal
  is a cheap future refinement.
- `FileStore`'s CAS is single-host (cross-process file lock), not distributed HA
  — already documented on `LeaseStore`.

### Definition-of-Done item satisfied

- *"Two gateways cannot concurrently own the same production session"* — now
  enforced in the running server: fresh sessions acquire, reattaches take over
  with a fencing generation bump, and every checkpoint is lease-gated so a
  superseded gateway is fenced out of writes and yields.

### Commit

`session: wire CAS ownership lease + fencing into the running server`

---

## F-P4.3 · Router forwards any tool for an admitted caller — FIXED (router-side policy)

**Severity:** High (the default-deny caller ACL controls *who* may reach the
router, but an admitted caller could still drive *any* upstream tool the router
could reach — the router applied no per-call authorization before forwarding).

**Component:** `router.go`.

**Reproduced:** Yes. `handleRouterConn` admitted a caller by ACL and then proxied
every upstream tool unconditionally; there was no per-`tools/call` policy check.

### Fix (the mission's "at minimum": full tool policy at the router)

- `RouterConfig.Policy` (optional) — a standard `policy.Policy` enforced at the
  router. When set, `cmdRouter` builds one `policy.Engine`.
- Every proxied `tools/call` is authorized in the proxy tool handler **before**
  dispatch, keyed by the ORIGINAL caller's transport identity (`fqdn`, `pubKey`
  from `peerIdentity`, never `_meta`) and the **namespaced** tool name
  (`svca.transfer`). A non-allow decision returns an `isError` denial and the
  call is **never dispatched upstream** (`enforce` runs before `pool.call`).
- Router policy uses allow/deny/rate rules; a `require_cosign` rule denies at the
  router (it is not a co-sign enforcement point). Optional — with no policy the
  router keeps prior mesh + caller-ACL admission.

This cannot widen a caller's authority (it only denies), reducing the
confused-deputy blast radius from "any upstream tool" to exactly what the router
policy permits — enforcement the router owns locally, with no wire-protocol
change and no upstream changes.

### Tests (`router_test.go`)

- `TestRouterEnforcesToolPolicy` — an admitted caller may call `svc.ok` (allowed
  by policy) but is denied `svc.secret`; the denied call returns an `isError`
  result AND the upstream tool handler is never invoked (`secretCalls == 0`).
- `TestRouterExampleConfigsLoad` — now also loads `examples/router-policy.yaml`
  (a router with a tool policy + rate limit).

### Compatibility impact

None. `Policy` is optional and additive; the three internal `buildAggregate`
call sites gain a `nil` enforcer (no enforcement) and behave exactly as before.

### Residual risk / follow-up

- Router-side policy covers `tools/call` (the confused-deputy tool-driving risk).
  Resource/prompt read policy at the router is a follow-up.
- The router has no audit sink of its own yet; denials are logged with the caller
  identity. A hash-chained router audit (recording caller + router + tool) is a
  follow-up.
- The full **signed-delegation** upstream verification (per-hop `DelegationToken`
  minted by the router, `VerifyDelegation` + `AuthorizeDelegated` at the upstream)
  remains Labs — it needs the audience-discovery, authority-key-distribution, and
  token-transport decisions called out in `docs/spec/ROUTER-DELEGATION.md`.

### Definition-of-Done item satisfied

- The router's stated minimum — *default-deny caller ACL (F-P4.2) **and** full
  tool policy at the router before forwarding* — is now enforced end to end.

### Commit

`router: enforce tool policy per caller before forwarding`

---

## Wave 3 · Threat-model re-audit (defense-in-depth sweep) — FIXED

A fresh pass over every core security surface (identity binding, the policy
filter, control-plane RBAC, the approval plane, audit integrity, secret
isolation, the SQL guard, session fencing, router/federation delegation, OAuth/
DPoP, crypto usage, capability revocation, egress, DoS limits, tool input, and
fail-closed config) against `docs/THREAT-MODEL.md`. Nine issues were reproduced
by reading the code and fixed with a failing-first regression test each. After
the fixes landed, an independent adversarial re-read of the **patched** tree
could no longer confirm any of the nine as exploitable — each rejection cited the
mitigating check added below.

Most core surfaces (F-P1 policy filter, control RBAC, approval plane, audit
integrity, secret isolation/redaction, capability revocation, crypto usage,
egress fail-closed, F-P9.1 strict config, the ROADMAP P0-3 audit-write path) were
re-confirmed intact — no regression.

### W3-1 · SQL-guard column redaction bypassed by projection alias/expression — FIXED
**Severity:** High (confidentiality break). **Component:** `air/sqlguard`.
`CheckRedaction` scanned only tokens *after* the top-level `FROM`, so a redacted
column in the projection under an alias or expression (`SELECT ssn AS x`,
`lower(email)`, `ssn || ''`, `CASE WHEN ssn=? …`) was never inspected, and
`ApplyRedaction` masks by the *output* column name — which the alias/expression
renames. An authorized reader recovered the masked value verbatim.
**Fix:** `CheckRedaction` now also scans the projection and permits a redacted
column there only as a bare (optionally schema-qualified) column reference whose
output name is the redacted name; any alias, function, operator, or projected
subquery is rejected (`ErrRedactedNotBare`). Predicate and bare-projection
behavior are unchanged. **Test:** `TestCheckRedaction_ForbidsRedactedColumnAliasedOrWrapped`.

### W3-2 · Federation `OrgFor` fails open for an unattributable caller under a wildcard — FIXED
**Severity:** Medium. **Component:** `federation/boundary.go`.
A `Match:"*"` mapping resolved an org for a caller the transport could not
attribute (both pubkey and FQDN empty), exposing the org's tool set and
misattributing the crossing — inconsistent with `acl.allows`' S30 invariant and
with `OrgForIssuer`'s own empty-issuer guard.
**Fix:** `OrgFor` returns `""` when both `peerFQDN` and `peerKey` are empty.
**Test:** `TestOrgFor_UnattributableCallerDeniedUnderWildcard`.

### W3-3 · Audit `DelegatedCaller` populated from an UNVERIFIED delegation token — FIXED
**Severity:** Low (audit over-claiming). **Component:** `policy/delegation_wire.go`.
On a token that decoded but failed verification, `applyDelegation` still copied
its attacker-chosen `Caller`/`Nonce` into the tamper-evident record, letting an
admitted router emit deny records attributing attempts to arbitrary victim keys.
**Fix:** caller/nonce are carried only from a token that verified (`err == nil`);
a failed verification records an empty `DelegatedCaller` (the router is still
attributed by its transport identity). **Test:** `TestFilterDelegationForgedCallerNotAudited`.

### W3-4 · Session reattach identity binding fails open on an empty transport key — FIXED
**Severity:** Medium. **Component:** `session/server.go`.
The binding compared `creatorKey != meta.PeerKey`, so two peers the mesh admitted
by FQDN only (no resolved pubkey, `PeerKey==""`) matched `"" == ""` and could take
over each other's sessions — while the move/failover paths already fail closed on
empty identity.
**Fix:** a new `identityMatches` binds on the pubkey when either side has one,
falls back to the mesh FQDN when both are key-less (so legitimate FQDN-only resume
still works but a *different* FQDN cannot collide), and fails closed when either
side is fully unattributable — mirroring `acl.allows`. **Tests:**
`TestSessionReattachEmptyKeyFailsClosed` (+ existing binding/resume tests, incl.
FQDN-only resume, stay green).

### W3-5 · Move-control strands warm backends across differing prepares — FIXED
**Severity:** Low (resource exhaustion). **Component:** `session/move.go`.
`ServeMoveControl` tracked only the last `preparedID`, so `prepare(idA); prepare(idB)`
on one connection left idA's spawned backend unreaped on disconnect.
**Fix:** a new prepare for a different session aborts the prior un-committed one
(one warm move per control connection). **Test:** `TestMoveControl_OneWarmPerConnection`.

### W3-6 · Behind-front mode collapses per-IP OAuth rate limits to one global bucket — FIXED
**Severity:** Medium (ingress DoS). **Component:** `edge`.
In `behind_front` mode the edge binds loopback, so every caller's `RemoteAddr` is
the local front and the per-IP pre-auth limiters (`token`/`authorize`/`register`)
shared one bucket — one caller could 429 all hosted clients.
**Fix:** an opt-in `forwarded_header` (valid *only* with `behind_front`; refused
otherwise so a directly-exposed edge cannot be spoofed) makes the limiters key on
the right-most value of that trusted header via `Server.rateLimitKey`. Audit still
records the honest transport peer. **Tests:** `TestRateLimitKey`,
`TestConfigValidateForwardedHeader`.

### W3-7 · Unbounded task accumulation in the MCP framework — FIXED
**Severity:** Medium (memory-exhaustion DoS). **Component:** `mcp/tasks.go`.
Task records (one per `tools/call` with `task:true`) were never reaped, unlike
every other client-driven allocation, so a peer could grow the map until OOM.
**Fix:** a `maxTasks` cap; at the cap the oldest *finished* task is evicted, and
if none can be reclaimed the new task is refused (fail closed). **Test:**
`TestTaskManagerBoundedEviction`.

### W3-8 · Unbounded request body in the framework HTTP transport — FIXED
**Severity:** Low (defense-in-depth). **Component:** `mcp/http.go`.
`HTTPHandler` did `io.ReadAll(r.Body)` with no cap, unlike every other HTTP
ingress in the tree. **Fix:** the body is wrapped in `http.MaxBytesReader`
(8 MiB, mirroring the stdio scanner cap) before reading; an oversized body returns
413. **Test:** `TestHTTPBodyCap`.

### W3-9 · fs sandbox does lexical-only containment (symlink escape) — FIXED
**Severity:** Medium. **Component:** `cmd/mcpserver/prompt_mcp/tools`.
`sandbox()` checked only that the *lexical* path was under `--root`, so a symlink
that already exists inside root (`link -> /etc`) let `read_file`/`write_file`
follow it out of the sandbox.
**Fix:** after the lexical check the real (symlink-resolved) path of the longest
existing prefix is re-verified to stay within the resolved root — covering both
existing reads and to-be-created writes — while internal symlinks still work.
**Test:** `TestSandboxRejectsSymlinkEscape`, `TestSandboxAllowsInternalPathsAndSymlinks`.

### Verification

`go build ./...` passes; the changed packages
(`air/sqlguard`, `federation`, `policy`, `session`, `edge`, `mcp`,
`cmd/mcpserver/prompt_mcp/tools`) pass `go test` and `go vet`.
