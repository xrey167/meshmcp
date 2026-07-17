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

### Draft additions (post-2025-06-18)

The base models above come from `schema.ts` (2025-06-18). The `basic/patterns`
and `basic/transports` spec sections are defined by prose, not `schema.ts`, and
the **draft** revision adds types and a transport layer that are **not** in
2025-06-18. These live in clearly-marked draft packages:

| Package                         | Covers                                                          |
| ------------------------------- | -------------------------------------------------------------- |
| `mrtr`                          | Multi Round-Trip Requests: `InputRequiredResult`, `InputRequests`/`InputResponses`, `requestState` (replaces server-initiated requests) |
| `subscriptions`                 | `subscriptions/listen`, notification `Filter`, acknowledgment, `subscriptionId` `_meta` key (replaces `resources/subscribe`) |
| `transport`                     | Transport-agnostic constants: content types, well-known `_meta` request-metadata keys |
| `transport/stdio`               | Newline-delimited framing (`Delimiter`, `Frame`) + lifecycle rules |
| `transport/streamablehttp`      | HTTP headers (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`), error codes (`-32020 HeaderMismatch`), and the Base64 sentinel `EncodeHeaderValue`/`DecodeHeaderValue` helpers |

These are additive and marked as draft-era in their package docs; they do not
alter the 2025-06-18 base models.

### Experimental extensions

| Package      | Covers                                                                    |
| ------------ | ------------------------------------------------------------------------- |
| `servercard` | MCP Server Card: static pre-connection discovery document (`ServerCard`, `Repository`, `Remote`, `Input`, `KeyValueInput`, `Icon`) — from `experimental-ext-server-card/schema.ts` (Server Card WG, SEP-2127) |

### Working groups without a stable schema (not modelled)

Several MCP working-group pages are **charters** (mission, membership, cadence)
and define no wire types. Their proposed types live in unmerged SEPs or
experimental repos and are omitted here to avoid modelling a moving target:

- **File Uploads** (`FileInputDescriptor`) — unmerged SEP-2356.
- **Skills over MCP** — Resources-based extension; survey + unmerged SEP-2640
  (`experimental-ext-skills` has design docs, no `schema.ts`).
- **Triggers & Events** — still "Ideating"; no schema yet.

Only Server Card publishes a stable `schema.ts`, so only it is modelled. If a
SEP above lands (or you want speculative models from a specific SEP), add a
package the same way.

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
