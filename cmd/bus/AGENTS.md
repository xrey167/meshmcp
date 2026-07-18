<!-- Parent: ../AGENTS.md -->

# cmd/bus

## Purpose
A governed event-bus MCP server (F28): identity-stamped, policy-filtered pub/sub
over the mesh. `publish(topic, payload)` appends an event stamped with the
caller's mesh identity (`MESHMCP_PEER_KEY`) and a global sequence; `poll(topic,
since)` pulls new events after a cursor (pull-based, fits MCP request/response
and the resumable session); `topics` lists topics + counts. The firewall in
front governs who may publish/subscribe to which topics and audits every
crossing — subscription becomes a capability, each delivery attributable.

## Key Files
| File | Description |
|------|-------------|
| `main.go` | `busStore` (append-only JSONL, global seq, per-topic partition) + the three MCP tools. |
| `main_test.go` | Publish/poll cursor semantics + persistence/seq-continuity across reload. |

## For AI Agents
- Built on the dependency-free `mcp/` framework, like `cmd/memory` and `cmd/kg`.
- The store is `0600` JSONL; the global sequence is the delivery cursor and must
  stay monotonic across a reload (see the test).
- Governed by the gateway unmodified — keep tool names (`publish`/`poll`/`topics`)
  stable or update `examples/bus.yaml` and its policy together.

### Testing
- `CGO_ENABLED=1 go test ./cmd/bus/ -race`.
