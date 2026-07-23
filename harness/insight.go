package harness

import (
	"io"

	"github.com/xrey167/meshmcp/insight"
	"github.com/xrey167/meshmcp/policy"
)

// Adaptive behavior via meshmcp's insight subsystem. The harness does not invent
// policy learning: it feeds its own audit stream (the hash-chained record of
// every governed action) through insight's pure functions to profile each role's
// normal footprint, recommend a tightened allowlist, simulate it before
// enforcing, and detect drift. This is the concrete §9.3 integration.

// Tuner drives insight over the harness audit stream to adapt the enforced
// policy. It holds the currently enforced policy so recommendations attribute
// emitted labels correctly.
type Tuner struct {
	current *policy.Policy
}

// NewTuner builds a tuner over the currently enforced policy (CompilePolicy
// output). current may be nil.
func NewTuner(current *policy.Policy) *Tuner { return &Tuner{current: current} }

// Recommend profiles the audit stream and returns a tightened allowlist policy
// plus human-readable notes (e.g. "explorer never used code.write in 10k runs →
// dropped"). It never widens silently: with Generalize off it grants exactly
// what was observed. This is `insight profile` + `insight recommend`.
func (t *Tuner) Recommend(auditR io.Reader) (*policy.Policy, []string, error) {
	corp, err := insight.Profile(auditR, t.current)
	if err != nil {
		return nil, nil, err
	}
	tightened, notes := insight.Recommend(corp, insight.RecommendOptions{})
	return tightened, notes, nil
}

// Simulate dry-runs a candidate policy against the recorded audit stream before
// enforcing it, so a tightening that would break working traffic (regressions)
// is caught first. This is `insight simulate`.
func (t *Tuner) Simulate(auditR io.Reader, candidate *policy.Policy) (insight.SimResult, error) {
	return insight.Simulate(auditR, candidate)
}

// Detect flags drift against a baseline profile (a worker suddenly egressing to
// a new host, an executor touching secrets). This is `insight detect`.
func (t *Tuner) Detect(baselineR, recentR io.Reader) ([]insight.Anomaly, error) {
	baseline, err := insight.Profile(baselineR, t.current)
	if err != nil {
		return nil, err
	}
	return insight.Detect(baseline, recentR, insight.DetectOptions{})
}

// ApplyRecommended profiles, simulates, and — only if the candidate introduces
// no regressions — hot-swaps the governor's enforced policy to the tightened
// one. It returns the notes and the simulation result so the caller can log
// what changed. A candidate with regressions is NOT applied (returns applied=false).
func (t *Tuner) ApplyRecommended(gov *Governor, auditForProfile, auditForSim io.Reader) (applied bool, notes []string, sim insight.SimResult, err error) {
	candidate, notes, err := t.Recommend(auditForProfile)
	if err != nil {
		return false, nil, insight.SimResult{}, err
	}
	sim, err = t.Simulate(auditForSim, candidate)
	if err != nil {
		return false, notes, insight.SimResult{}, err
	}
	if len(sim.Regressions) > 0 {
		return false, notes, sim, nil // would break working traffic — refuse
	}
	gov.SetPolicy(candidate)
	t.current = candidate
	return true, notes, sim, nil
}
