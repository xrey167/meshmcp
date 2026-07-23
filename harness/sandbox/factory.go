package sandbox

import (
	"context"
	"fmt"
)

// Spec requests a sandbox of a given kind for a run/worker.
type Spec struct {
	Kind   string // requested backend
	Min    string // policy-required minimum (AtLeast is applied)
	Root   string // repo/work root for local
	Repo   string // git repo for worktree
	Parent string // parent dir for worktree
	Branch string // branch name for worktree
}

// New builds a sandbox honoring the policy minimum: the returned backend is the
// stronger of Spec.Kind and Spec.Min. Backends that need live infrastructure
// (tmux, docker, ssh, openshell) return a Stub that fails Exec with a clear
// "backend not available in this build" error rather than silently degrading —
// so a run that requires docker isolation cannot fall back to running on the
// host unnoticed.
func New(ctx context.Context, s Spec) (Sandbox, error) {
	kind := s.Kind
	if kind == "" {
		kind = "local"
	}
	if s.Min != "" {
		kind = AtLeast(kind, s.Min)
	}
	switch kind {
	case "local":
		return NewLocal(s.Root), nil
	case "worktree":
		branch := s.Branch
		if branch == "" {
			branch = "harness-worktree"
		}
		return NewWorktree(ctx, s.Repo, s.Parent, branch)
	case "tmux", "docker", "ssh", "openshell":
		return NewStub(kind), nil
	default:
		return nil, fmt.Errorf("sandbox: unknown backend %q", kind)
	}
}
