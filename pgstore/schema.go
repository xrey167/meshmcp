package pgstore

// Embedded schema, applied idempotently at Open. The sessions columns
// owner/generation/lease_expiry are the source of truth for the lease CAS;
// payload is the full JSON-encoded session.PersistedSession (its embedded
// copies of those fields are overridden from the columns on load).
//
// DPoP nonces get their own table, deliberately separate from delegation
// nonces: delegation records a nonce as USED (present = replayed) while DPoP
// consumes an ISSUED nonce by deleting it (present = valid). Sharing one
// table would let a crafted DPoP proof delete — and thereby un-burn — a
// delegation nonce.
const (
	// lease_expiry is Unix nanos (0 = no lease), exactly as
	// session.PersistedSession.LeaseExpiry — a TIMESTAMPTZ would truncate to
	// microseconds and diverge from the other backends' round-trip.
	ddlSessions = `CREATE TABLE IF NOT EXISTS %s (
	id           TEXT PRIMARY KEY,
	owner        TEXT NOT NULL,
	generation   BIGINT NOT NULL,
	lease_expiry BIGINT NOT NULL,
	payload      BYTEA NOT NULL
)`

	ddlNonces = `CREATE TABLE IF NOT EXISTS %s (
	nonce  TEXT PRIMARY KEY,
	expiry TIMESTAMPTZ NOT NULL
)`

	ddlDPoPNonces = `CREATE TABLE IF NOT EXISTS %s (
	nonce  TEXT PRIMARY KEY,
	expiry TIMESTAMPTZ NOT NULL
)`

	ddlDPoPJTIs = `CREATE TABLE IF NOT EXISTS %s (
	jti    TEXT PRIMARY KEY,
	expiry TIMESTAMPTZ NOT NULL
)`

	// Idempotency claims (mcp.ClaimStore): the primary-key insert is the
	// atomic claim; done/result record the terminal outcome (result NULL =
	// executed but uncacheable). Rows expire at expiry — the dedup horizon.
	ddlIdemClaims = `CREATE TABLE IF NOT EXISTS %s (
	key    TEXT PRIMARY KEY,
	expiry TIMESTAMPTZ NOT NULL,
	done   BOOLEAN NOT NULL DEFAULT FALSE,
	result BYTEA
)`
)
