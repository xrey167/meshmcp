package policy_test

import (
	"testing"

	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/policy/replaytest"
)

// The built-in in-memory replay stores must pass the shared conformance
// harness — the same contract any durable backend is held to.

func TestMemNonceStoreConformance(t *testing.T) {
	replaytest.RunNonceStoreConformance(t, func(t *testing.T) policy.NonceStore {
		return policy.NewMemNonceStore()
	})
}

func TestMemDPoPReplayStoreConformance(t *testing.T) {
	replaytest.RunDPoPReplayStoreConformance(t, func(t *testing.T) policy.DPoPReplayStore {
		return policy.NewMemDPoPReplayStore()
	})
}
