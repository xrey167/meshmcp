# `air` — meshmcp's Air module

The portable, mesh-independent core of meshmcp's Air layer: the domain types and
pure logic for **Presence**, **Activities**, discovery, steering, **Continuity
handoffs**, Home, and declarative workflows. It has
no dependency on the WireGuard mesh client, the policy engine, or the session
layer — the command-line and HTTP wiring that binds these to a live mesh lives in
the main package, which imports this one. So the Air model can be tested and
evolved on its own, and every parsing / validation / addressing invariant is
proven here.

## What's in it

| File | Provides |
|------|----------|
| `catalog.go` | `Catalog` / `CatalogEntry` discovery model — builder (`NewCatalog`/`Add`/`Sorted`/`Names`), lookup (`Entry`), filters (`Steerable`/`Resumable`), and `Valid()` + `Transport*` constants |
| `discovery.go` | ARD (Agentic Resource Discovery) legs 2–3: `DNSRecords` generation (with zone-injection-safe validation), `ParseCatalogTXT`, `ResolveCatalog` (TXT then SRV) over injectable lookups, and `FetchCatalog` (transport-agnostic fetch+parse over an injected `http.Client`, bounded body) |
| `presence.go` | Versioned, bounded `Announcement` / `Presence` / `Activity` contracts; verified identity and observed-address stamping; concurrency-safe TTL registry; exact friendly-name/FQDN/full-key service resolver |
| `home.go` | The shared Home read model, hero summary, stable change signature, and receipt parser consumed by CLI and web |
| `change.go` | Stable catalog snapshots and human-readable endpoint deltas |
| `notice.go` | Bounded, terminal-safe notices used by Air's human-facing event surfaces |
| `handoff.go` | Air Continuity's target-bound `ContextCapsule`, canonical SHA-256 sealing, bounded offer + ACK framing, destination delivery-attempt receipts, and explicit lifecycle (`offered` → `accepted` → `dispatching` → `continued`, or `declined`/`expired`) |
| `steer.go` | `SteerEnvelope` (+ `Validate`), the `Task`/`Nudge`/`Cancel`/`TaskArgs` constructors, `String()`, and the newline-JSON framing (`ParseEnvelopes`/`WriteEnvelope`) |
| `target.go` | The `Target` addressing grammar — `agent` / `session` / `task` / `group` — with `ParseTarget` and a round-tripping `String()` |
| `workflow.go` | The declarative `Workflow` schema, `ParseWorkflow`, full `Validate()` (including `${var.field}` reference checking against prior `as:` captures), `Plan()`, and `${var}` expansion |
| `view.go` | The live-view rows — `Session` (a gateway's control view) and `PeerRow` (the page's Nearby view) |

## Design invariants

- **Deny/reject over silently degrade.** A malformed steer type, an unknown
  target kind, an undefined workflow variable, a zone-unsafe DNS name, or an
  oversized TXT record is an error at parse/validate time — never silently
  mis-applied or followed.
- **Injectable I/O.** DNS resolution takes `TXTLookup`/`SRVLookup` so it is
  fully offline-testable; the package performs no network or filesystem I/O
  except reading DNS through those injected functions.
- **The mesh stays out.** Identity, policy, audit, and the WireGuard transport
  are the main package's job; this package only shapes and validates the data
  that crosses them.
