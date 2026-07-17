# protocol — MCP data models (Go)

Go models generated from the official **Model Context Protocol** TypeScript
schema (`schema.ts`, revision **2025-06-18**), granular and grouped **one Go
package per protocol domain**.

Source of truth:
`modelcontextprotocol/modelcontextprotocol` → `schema/2025-06-18/schema.ts`.

## Layout

| Package        | Domain (schema `@category`)                                    |
| -------------- | -------------------------------------------------------------- |
| `base`         | Shared envelopes, pagination, scalars, metadata, `Role`        |
| `jsonrpc`      | JSON-RPC 2.0 request / notification / response / error frames  |
| `initialize`   | Handshake, `Client`/`ServerCapabilities`, `Implementation`     |
| `ping`         | Liveness ping                                                  |
| `progress`     | `notifications/progress`                                       |
| `cancellation` | `notifications/cancelled`                                      |
| `resource`     | Resources, templates, contents, `resources/*`                 |
| `content`      | Content-block union: text / image / audio / link / embedded    |
| `prompt`       | Prompts, arguments, messages, `prompts/*`                     |
| `tool`         | Tools, annotations, `tools/*`                                 |
| `logging`      | `logging/setLevel`, `notifications/message`                    |
| `sampling`     | `sampling/createMessage`, model preferences                    |
| `completion`   | `completion/complete`, prompt/resource references              |
| `roots`        | `roots/list`, roots changed                                    |
| `elicitation`  | `elicitation/create`, restricted primitive schemas             |
| `messages`     | Top-level client/server message unions (documented aliases)    |

## Conventions

- **`extends` → embedding.** A TS interface that `extends Result` /
  `PaginatedResult` / `BaseMetadata` embeds the corresponding `base` struct so
  fields (`_meta`, `nextCursor`, `name`/`title`) marshal inline.
- **Concrete requests are standalone.** Each request redefines `method` (a
  literal) and typed `params`, so it does not embed the generic `base.Request`.
  Method names are exported as constants (`resource.MethodRead`, …).
- **Unions → marker interface + `Decode*`.** TS union types (e.g. `ContentBlock`,
  `PrimitiveSchemaDefinition`, resource contents, completion `ref`) become a Go
  interface with a marker method and a `Decode*` helper that discriminates the
  concrete type from JSON. Containers holding a union implement
  `json.Unmarshaler` so they round-trip transparently — see
  `content.DecodeBlock`, `resource.DecodeContents`,
  `elicitation.DecodePrimitiveSchema`, `completion.DecodeReference`.
- **`string | number` fields** (`RequestId`, `ProgressToken`) are left as `any`.
- **Open objects** (`_meta`, `[key: string]: unknown`) map to `base.Meta`
  (`map[string]any`).
- **Cross-package dependencies are acyclic:**
  `content → resource`; `prompt`/`tool`/`sampling → content`; everything → `base`.

## Tests

`protocol/roundtrip_test.go` exercises the polymorphic decoders and embedding:

```
go test ./protocol/...
```
