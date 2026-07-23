package air

import "fmt"

// Durable air stores stamp their on-disk JSON with a top-level schema_version so
// a store written by a newer build is refused by an older one rather than
// silently misread (which, for a security store, could drop paired identities or
// grants). The discipline is uniform: write the current version, and on load
// reject anything newer (fail closed) while accepting a 0/absent version as a
// legacy pre-versioning file at the current version.

// checkSchemaVersion enforces reject-newer / accept-older for a durable store's
// on-disk format. store names the store for the error; onDisk is the version
// read from the file (0 when the field is absent — a legacy file); current is
// the version this build writes. A newer on-disk version is a fail-closed error.
func checkSchemaVersion(store string, onDisk, current int) error {
	if onDisk > current {
		return fmt.Errorf("%s: on-disk schema version %d is newer than this build supports (%d) — upgrade meshmcp", store, onDisk, current)
	}
	return nil
}
