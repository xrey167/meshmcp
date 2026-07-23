# `pgstore` — PostgreSQL-backed session and replay stores

A single `Store` type implementing four interfaces on PostgreSQL:
`session.SessionStore`, `session.LeaseStore`, `policy.NonceStore`, and
`policy.DPoPReplayStore`. Unlike `session.FileStore` (single-node; CAS via a
cross-process file lock), the lease compare-and-swap here is a real
**distributed** CAS — every lease op is a row-locked transaction — so the
single-winner and fencing guarantees hold across hosts.

Opened via `Open(dsn)`, which pings the database and applies the embedded
schema idempotently (`CREATE TABLE IF NOT EXISTS`). The gateway selects this
store when `session_store` is a `postgres://` DSN.

## Design invariants

- **CAS decided under a row lock.** Acquire/Takeover run in one transaction
  with `SELECT ... FOR UPDATE`; the fresh-id race is arbitrated by
  `INSERT ... ON CONFLICT DO NOTHING`. Renew/Release/SaveIfOwned are single
  conditional UPDATEs on `(id, owner, generation)` — rowcount 0 means fenced.
- **Columns are the source of truth.** `owner`/`generation`/`lease_expiry`
  live as columns and override the JSON payload's copies on Load/List, so a
  stale payload can never resurrect a superseded owner.
- **Fail closed.** Any database error in the replay stores (`Use`, `UseJTI`,
  `ConsumeNonce`) reports the nonce as unusable — an outage never re-enables
  replay.
- **DPoP nonces are a separate table** from delegation nonces: sharing one
  table would let a crafted DPoP proof un-burn a victim's delegation nonce
  (rationale in `schema.go`).

## Tests

Conformance comes from the shared harnesses (`session/storetest`,
`policy/replaytest`), run against a live database when `MESHMCP_TEST_PG_DSN`
is set (skipped otherwise). Each subtest uses a random table prefix, so
parallel runs against one database do not collide.
