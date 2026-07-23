package sandbox

import (
	"context"
	"fmt"
)

// Stub stands in for a backend that requires live infrastructure not wired in
// this build (tmux, docker, ssh, openshell). It never executes on the host: its
// Exec fails closed with an explanatory error, so a run that policy required to
// be isolated in a container cannot silently degrade to unsandboxed host
// execution. The backend is defined and selectable; only its live driver is
// pending (Phase 2/4 wiring).
type Stub struct {
	kind string
}

// NewStub builds a fail-closed stub for kind.
func NewStub(kind string) *Stub { return &Stub{kind: kind} }

func (s *Stub) Kind() string { return s.kind }
func (s *Stub) Root() string { return "" }

// Exec fails closed: an isolation backend that is unavailable must not fall
// through to the host.
func (s *Stub) Exec(ctx context.Context, cmd Command) (ExecResult, error) {
	return ExecResult{}, fmt.Errorf("sandbox: %q backend is not available in this build (fail-closed; a run requiring %s isolation will not run on the host)", s.kind, s.kind)
}

func (s *Stub) Close() error { return nil }
