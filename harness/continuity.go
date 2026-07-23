package harness

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/xrey167/meshmcp/air/checkpoint"
)

// Continuity persists the must-survive state of a run so it outlives a crash,
// roam, or handoff. It is identity-bound: only the caller whose key created a
// run may read or advance it. This is the harness's client view of meshmcp's
// air continuity subsystem — the harness invents no continuity of its own.
type Continuity interface {
	// Save persists state, bound to callerKey. Overwriting a run created by a
	// different key is refused.
	Save(state RunState, callerKey string) error
	// Load reads a run's state; ok is false when none exists. A caller key that
	// does not match the creator is refused.
	Load(id RunID, callerKey string) (state RunState, ok bool, err error)
}

// MemContinuity is an in-process Continuity for tests and single-host runs. It
// enforces the same identity binding as the air-backed store.
type MemContinuity struct {
	mu    sync.Mutex
	runs  map[RunID]RunState
	owner map[RunID]string
}

// NewMemContinuity builds an empty in-process store.
func NewMemContinuity() *MemContinuity {
	return &MemContinuity{runs: map[RunID]RunState{}, owner: map[RunID]string{}}
}

// Save persists state under its ID, bound to callerKey.
func (m *MemContinuity) Save(state RunState, callerKey string) error {
	if callerKey == "" {
		return fmt.Errorf("continuity: blank caller key")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if o, ok := m.owner[state.ID]; ok && o != callerKey {
		return fmt.Errorf("continuity: run %s owned by another identity", state.ID)
	}
	m.runs[state.ID] = state
	m.owner[state.ID] = callerKey
	return nil
}

// Load reads a run's state.
func (m *MemContinuity) Load(id RunID, callerKey string) (RunState, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.owner[id]
	if !ok {
		return RunState{}, false, nil
	}
	if callerKey == "" || o != callerKey {
		return RunState{}, false, fmt.Errorf("continuity: run %s owned by another identity", id)
	}
	return m.runs[id], true, nil
}

// AirContinuity persists run state through air/checkpoint — the shared,
// identity-bound, audited resumable-state primitive (spine S5). RunState is
// serialized into the opaque Checkpoint.State payload; the checkpoint's
// CreatorKey binding is what makes a run resumable only by its creator, and
// every save/resume lands on the shared verifiable ledger.
type AirContinuity struct {
	store *checkpoint.Store
}

// NewAirContinuity wraps an air/checkpoint.Store.
func NewAirContinuity(store *checkpoint.Store) *AirContinuity {
	return &AirContinuity{store: store}
}

// Save serializes state into a checkpoint keyed by run id and bound to callerKey.
func (a *AirContinuity) Save(state RunState, callerKey string) error {
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("continuity: marshal run state: %w", err)
	}
	return a.store.Save(checkpoint.Checkpoint{
		RunID:      string(state.ID),
		CreatorKey: callerKey,
		Step:       stageIndex(state.Stage),
		State:      payload,
	})
}

// Load reads and deserializes a run's state, enforcing the identity binding.
func (a *AirContinuity) Load(id RunID, callerKey string) (RunState, bool, error) {
	cp, ok, err := a.store.Load(string(id), callerKey)
	if err != nil || !ok {
		return RunState{}, ok, err
	}
	var state RunState
	if len(cp.State) > 0 {
		if err := json.Unmarshal(cp.State, &state); err != nil {
			return RunState{}, false, fmt.Errorf("continuity: unmarshal run state: %w", err)
		}
	}
	return state, true, nil
}

// stageIndex maps a stage to its ordinal in the canonical pipeline, used as the
// checkpoint's monotonic Step cursor.
func stageIndex(s Stage) int {
	for i, st := range pipelineOrder {
		if st == s {
			return i
		}
	}
	return 0
}
