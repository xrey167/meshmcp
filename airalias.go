package main

import "github.com/xrey167/meshmcp/air"

// Air's portable domain types and discovery logic live in the air package after
// the carve-out. These aliases keep the main-package call sites — the CLI and
// the mesh/HTTP wiring — reading the same names, so the extraction is a clean
// module boundary rather than a churn of every reference.
type (
	AirCatalog      = air.Catalog
	AirCatalogEntry = air.CatalogEntry
	steerEnvelope   = air.SteerEnvelope
)

const airCatalogPath = air.CatalogPath
