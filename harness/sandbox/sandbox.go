// Package sandbox provides execution backends for shell/tool work, one per
// isolation level the harness needs. Policy decides the MINIMUM sandbox for a
// given identity + label set: a main/trusted identity may run local, but any
// non-main or channel-originated run defaults to worktree/docker isolation
// (openclaw's group/channel-safety default). Parallel writers get a git
// worktree so conflicting writes are impossible by construction.
package sandbox

import (
	"context"
	"time"
)

// Command is a shell/tool invocation to run inside a sandbox.
type Command struct {
	Args    []string      // argv; Args[0] is the program
	Dir     string        // working directory relative to the sandbox root ("" = root)
	Env     []string      // extra environment ("KEY=VALUE")
	Stdin   string        // optional stdin
	Timeout time.Duration // 0 = no explicit timeout (context still applies)
}

// ExecResult is a command's outcome.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Sandbox is an execution backend. Kind is one of: local, tmux, worktree,
// docker, ssh, openshell.
type Sandbox interface {
	Kind() string
	// Root returns the sandbox's filesystem root (working tree).
	Root() string
	Exec(ctx context.Context, cmd Command) (ExecResult, error)
	// Close releases the sandbox (removes a worktree, kills a tmux/container).
	Close() error
}

// Ordering of isolation strength, weakest → strongest. minSandbox uses it to
// pick the stronger of a requested and a policy-required minimum.
var strength = map[string]int{
	"local":     0,
	"tmux":      1,
	"worktree":  2,
	"ssh":       3,
	"openshell": 3,
	"docker":    4,
}

// AtLeast returns whichever of want/min is the stronger isolation kind, so a
// policy minimum can never be weakened by a caller's request.
func AtLeast(want, min string) string {
	if strength[want] >= strength[min] {
		if _, ok := strength[want]; ok {
			return want
		}
	}
	if _, ok := strength[min]; ok {
		return min
	}
	if _, ok := strength[want]; ok {
		return want
	}
	return "docker" // unknown pair → safest
}
