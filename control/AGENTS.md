<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-17 | Updated: 2026-07-17 -->

# control

## Purpose
The managed control plane: a single mesh service that handles node **enrollment** (issuing NetBird setup keys / credentials), the service **registry**, and **policy distribution**. Lets an operator onboard peers and push named policies to gateways centrally. Backs `meshmcp control`.

## Key Files
| File | Description |
|------|-------------|
| `control.go` | Package doc + the control-plane service: enrollment endpoints, registry, and policy handout. |
| `netbird.go` | The NetBird API issuer. `Doer` is the injectable `*http.Client` subset used to request setup keys (mockable in tests). |
| `store.go` | `FilePolicyStore` — named policies persisted as `<name>.yaml` in a directory, served to gateways. Also `StaticEnroll` — the default fixed-credential `EnrollFunc` (swap for `NetBirdIssuer`). |

## For AI Agents

### Working In This Directory
- `netbird.go` talks to an external NetBird management API — always go through the `Doer` interface so `netbird_test.go` can inject a fake transport; never hard-code a live client.
- Enrollment issues real credentials; treat setup keys as secrets (never log them).

### Testing Requirements
- `CGO_ENABLED=1 go test ./control/ -race`.

## Dependencies

### Internal
- Distributes `policy.Policy` documents; consumed by root `control.go`.

### External
- `net/http` (via `Doer`) to the NetBird management API.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
