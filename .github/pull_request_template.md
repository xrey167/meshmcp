## What this changes

## Security invariant

<!-- Per CONTRIBUTING.md: describe the security invariant your change
establishes or preserves (identity from transport, default-deny, fail-closed,
audited). "None touched" is a fine answer when true. -->

## Verification

- [ ] `gofmt -l .` is empty
- [ ] `go vet ./...` is clean
- [ ] `go test -race ./...` passes (no new skips)
- [ ] User-facing errors name a next step (CONTRIBUTING.md → Error copy)
