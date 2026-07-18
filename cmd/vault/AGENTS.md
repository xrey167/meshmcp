<!-- Parent: ../AGENTS.md -->

# cmd/vault

## Purpose
A mesh secrets-vault MCP server (F26): a zero-exposure, identity-gated secrets
manager. It STORES and ROTATES secrets into the same JSON store the credential
broker (`secrets/`) injects from, so agents keep referencing secrets by name
(`{{secret:NAME}}`) and never hold the value. It deliberately exposes NO get
tool — values leave only via the gateway's broker injection into an authorized
backend call, never back to the caller. The firewall governs who may
set/rotate/delete and audits each.

## Key Files
| File | Description |
|------|-------------|
| `main.go` | `vaultStore` (atomic 0600 JSON) + tools `set_secret` / `rotate_secret` / `delete_secret` / `list_secrets` (names only). |
| `main_test.go` | set/rotate(server-side value)/delete/persist + the no-`get`-tool confused-deputy guard. |

## For AI Agents
- The store format is exactly `secrets.FileStore`'s (`{"name":"value"}`, 0600),
  so a gateway `secrets.file` pointing at the same path injects vault-managed
  secrets. Keep it that way.
- **Never add a tool that returns a secret VALUE.** `rotate_secret` generates the
  new value server-side and returns only confirmation; that invariant is the
  whole point (see the test).

### Testing
- `CGO_ENABLED=1 go test ./cmd/vault/ -race`.
