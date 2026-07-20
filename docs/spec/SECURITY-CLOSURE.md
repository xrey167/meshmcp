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
