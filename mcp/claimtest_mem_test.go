package mcp_test

import (
	"testing"

	"github.com/xrey167/meshmcp/mcp"
	"github.com/xrey167/meshmcp/mcp/claimtest"
)

// The built-in in-memory claim store must pass the shared conformance
// harness — the same contract any durable backend is held to.

func TestMemClaimStoreConformance(t *testing.T) {
	claimtest.RunClaimStoreConformance(t, func(t *testing.T) mcp.ClaimStore {
		return mcp.NewMemClaimStore()
	})
}
