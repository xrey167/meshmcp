# Contributing to meshmcp

Thanks for your interest. meshmcp is a security product, so contributions are
held to a security-first bar.

> **License note:** meshmcp's license is currently proprietary and under review
> (see [`LICENSE`](LICENSE) and [`LICENSE-DECISION.md`](LICENSE-DECISION.md)).
> Until an open license is chosen, external contributions may be limited — please
> open an issue to discuss before investing significant effort, and be aware a
> contributor agreement (CLA/DCO) may be required once the license is settled.

## Reporting security issues

Do **not** open a public issue for a vulnerability. Follow
[`SECURITY.md`](SECURITY.md) (private vulnerability reporting).

## Development

Requirements: Go as pinned in `go.mod`. A C toolchain is needed for `-race`.

Before every push, the same gates CI enforces must pass locally:

```bash
gofmt -l .            # must print nothing
go vet ./...
go build ./...
go test ./...
go test -race ./...
```

Advisory (not yet blocking, being burned down):

```bash
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

## Security-change workflow (required)

Every change that touches a security control follows test-first, documented
hardening:

1. **Reproduce** the issue against the current tree.
2. Add a **failing regression test** and confirm it fails on the vulnerable code.
3. Implement the **smallest robust fix**.
4. Confirm the test passes; run the package tests, the full suite, and `-race`.
5. Add **fuzz or property tests** where input parsing or a state machine is
   involved.
6. Document the invariant the test protects, and add a
   `docs/spec/SECURITY-CLOSURE.md` entry (reproduced / root cause / fix / tests /
   residual risk).

### Principles (from the threat model)

- Treat every mesh peer as potentially compromised; WireGuard membership is
  authentication, not authorization.
- Derive identity from the authenticated transport at every enforcement point —
  never from headers, `_meta`, request bodies, or filenames.
- Default-deny privileged and administrative operations.
- Security-config errors must fail startup, not silently fall back.
- Do not claim a stronger guarantee than the code and tests establish (e.g. no
  "exactly-once execution" without an end-to-end idempotency protocol).

### Error copy

- **Every user-facing error names a next step.** One sentence of what failed,
  then the command or fix that resolves it — never a bare plumbing chain as the
  whole message. The command boundary (`presentError` in `cmd/meshmcp/errors.go`)
  adds hints for the common failure shapes; a new failure mode that users will
  hit should either carry its own guidance (the way the missing-setup-key path
  does) or add a shape to `hintFor`.
- A denial must say why and what would change the outcome (see the pairing
  decline reason); a refusal that names no path forward is a dead end, not
  security.

## Commits and PRs

- Keep commits narrow and reviewable; one security fix per commit where possible.
- Never weaken a test to make it pass.
- Pin any new third-party GitHub Action by full commit SHA.
- Describe the security invariant your change establishes in the PR.
