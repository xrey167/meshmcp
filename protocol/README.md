# protocol — MCP data models (Go)

Granular Go models for the **Model Context Protocol** wire format, faithfully
translated from the official TypeScript sources and grouped **one Go package
per protocol domain**. Coverage spans three layers:

1. **Base** — the stable `schema.ts` revision **2025-06-18** (source of truth:
   `modelcontextprotocol/modelcontextprotocol` → `schema/2025-06-18/schema.ts`).
2. **Draft** — the post-2025-06-18 revision (server/discover, MRTR,
   subscriptions, structured error catalog, sampling tool-use, form/url
   elicitation, the streamable-HTTP + stdio transports, and the OAuth 2.1
   authorization layer), in clearly-marked era-separated packages.
3. **Extensions** — Server Card, Tasks (`io.modelcontextprotocol/tasks`) and
   Apps (`ext-*` repos) — plus a small client-side response cache.

Every package has round-trip / conformance tests against real payloads and the
official example fixtures. Marker-interface unions, `Decode*` discriminators,
and struct embedding are the recurring translation patterns (see Conventions).

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
| `transport`                     | Transport-agnostic constants (content types, well-known `_meta` keys) and the typed `_meta` views: `RequestMeta` (protocolVersion / clientInfo / clientCapabilities / progressToken / logLevel), `ResultMeta` (serverInfo), `NotificationMeta` (subscriptionId) |
| `transport/stdio`               | Newline-delimited framing (`Delimiter`, `Frame`) + lifecycle rules |
| `transport/streamablehttp`      | HTTP headers (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`), error codes (`-32020 HeaderMismatch`), and the Base64 sentinel `EncodeHeaderValue`/`DecodeHeaderValue` helpers |
| `authorization`                 | OAuth 2.1 authorization layer: Protected Resource Metadata (RFC 9728), Authorization Server Metadata (RFC 8414/OIDC), Client ID Metadata Document, Dynamic Client Registration (RFC 7591), the token endpoint (`TokenRequest.Form()` for client_credentials / private_key_jwt / jwt-bearer / RFC 8693 token-exchange incl. the ID-JAG cross-app-access flow, `TokenResponse`, `TokenExchangeResponse`, `TokenErrorResponse`), plus the MCP discovery-URL ordering and a `WWW-Authenticate` challenge parser |
| `discover`                      | `server/discover` handshake (replaces `initialize`): `DiscoverRequest`, `DiscoverResult`, draft `ServerCapabilities`, `resultType` discriminator (re-exports `caching.CacheableResult`) |
| `caching`                       | Draft result caching hints: `CacheableResult` (`ttlMs` / `cacheScope`) shared across all cacheable verbs (tools/list, resources/list, prompts/list, resources/read, server/discover), plus a client-side `ResponseCache` that honours the hints with `use`/`refresh`/`bypass` strategies, public/private scope partitioning, and notification-driven on-demand revalidation (`InvalidateForNotification`) |
| `mcperror`                      | Draft error catalog: `Error`, `ErrorResponse`, standard + MCP-reserved codes (`-32020..-32022`), and the structured data payloads (`UnsupportedProtocolVersionData`, `MissingRequiredClientCapabilityData`) |
| `elicitationdraft`              | Draft `elicitation/create` redesign: form/url request modes and the expanded restricted schemas (string/number/boolean + single/multi-select enum variants, titled/untitled/legacy) with a discriminating `DecodePrimitiveSchema` |
| `samplingtools`                 | Draft sampling tool-use: `ToolUseContent`, `ToolResultContent`, `ToolChoice`, message content as a single block **or array**, and a request params extended with `tools` / `toolChoice` |

Draft frames verified end-to-end (`protocol/*_test.go`) against real
2026-07-28 payloads and the official `schema/draft/examples` fixtures:
`server/discover`, `tools/call` (incl. array/object `structuredContent`),
`completion/complete`, `sampling/createMessage` (incl. multi-block tool-use),
`notifications/cancelled`, every `Client`/`ServerCapabilities` fragment, and
the `Tool` schema examples. Two fidelity fixes fell out of this: tool
`inputSchema`/`outputSchema` and tool-result `structuredContent` are now kept
as raw JSON (arbitrary JSON Schema / any JSON), and capability objects preserve
present-empty `{}` distinctly from absent.

These are additive and marked as draft-era in their package docs; they do not
alter the 2025-06-18 base models.

**Not yet ported from the draft `schema.ts`.** The draft is a large redesign
(164 exports vs 98). The self-contained draft additions are modelled in
era-separated packages — `discover`, `mcperror`, `mrtr`, `subscriptions`,
`samplingtools` (tool-use), `elicitationdraft` (form/url modes + enum
schemas), and typed request `_meta` in `transport`. What remains un-ported is
the pervasive `resultType` field the draft adds to *every* result; the
2025-06-18 result models ignore it on decode without failing (a draft-only
field), rather than each carrying it. Add a draft result variant the same way
if you need it typed.

### Experimental extensions

| Package      | Covers                                                                    |
| ------------ | ------------------------------------------------------------------------- |
| `servercard` | MCP Server Card: static pre-connection discovery document (`ServerCard`, `Repository`, `Remote`, `Input`, `KeyValueInput`, `Icon`) — from `experimental-ext-server-card/schema.ts` (Server Card WG, SEP-2127) |
| `tasks`      | Tasks extension `io.modelcontextprotocol/tasks` (SEP-2663): async request processing — `Task`/`DetailedTask`, `CreateTaskResult`, `tasks/get`·`update`·`cancel`, `notifications/tasks` — from `ext-tasks/schema/draft/schema.ts` |
| `apps`       | MCP Apps extension (`ext-apps`): host↔embedded-UI bridge — `ui/*` requests/results/notifications, host/app capabilities, host context (with `Platform` + responsive `IsMobile`/`SupportsTouch`/`SupportsDisplayMode` helpers), resource CSP/permissions — from `ext-apps/src/spec.types.ts` |

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

Every package is tested. Coverage includes: the polymorphic decoders and their
`default → error` branches (`content`, `resource`, `completion`, `sampling`,
`samplingtools`, `jsonrpc`, both elicitation packages), union marshal
round-trips, struct embedding, real 2026-07-28 draft frames, the official
`schema/draft/examples` fixtures (ServerCapabilities, Tool), and the
hand-written helpers (response cache modes/scope/invalidation, OAuth discovery
ordering + `WWW-Authenticate` parsing, the streamable-HTTP Base64 sentinel,
stdio framing).

```
go build ./... && go vet ./protocol/... && go test ./protocol/...
```
