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

	// Workflow schema, carved into air; the runner (airworkflow.go) reads these.
	airWorkflow     = air.Workflow
	airWorkflowStep = air.WorkflowStep
	launchStep      = air.LaunchStep
	steerStep       = air.SteerStep
	agentSteerStep  = air.AgentSteerStep
	callStep        = air.CallStep
)

const airCatalogPath = air.CatalogPath

// Workflow variable-expansion helpers, aliased so the runner's call sites are
// unchanged after the carve-out.
var (
	expandSteer      = air.ExpandSteer
	expandCall       = air.ExpandCall
	expandAgentSteer = air.ExpandAgentSteer
)
