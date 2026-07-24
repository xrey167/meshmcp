// Package sandbox provides execution backends for shell/tool work, one per
// isolation level the harness needs. Policy decides the MINIMUM sandbox for a
// given identity + label set: a main/trusted identity may run local, but any
// non-main or channel-originated run defaults to worktree/docker isolation
// (openclaw's group/channel-safety default). Parallel writers get a git
// worktree so conflicting writes are impossible by construction.
package sandbox

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
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
//
// It fails CLOSED on unrecognized kinds. An unknown policy minimum is returned
// unchanged so the factory rejects it (unknown backend -> error) rather than
// silently downgrading to host exec; an unknown requested kind resolves to the
// (known) minimum, or is returned as-is when there is no minimum so the factory
// likewise rejects it. Only when both kinds are known is the ordering compared.
func AtLeast(want, min string) string {
	ws, wok := strength[want]
	ms, mok := strength[min]
	// Unknown minimum: never silently satisfy it. Preserve it so New() errors
	// instead of picking a weaker backend behind the policy's back.
	if min != "" && !mok {
		return min
	}
	// Unknown requested kind: fall back to the known minimum, else return the
	// unknown request so the factory rejects it (fail closed, never local).
	if !wok {
		if min != "" {
			return min
		}
		return want
	}
	if ws >= ms {
		return want
	}
	return min
}

// resolveDir joins a sandbox-relative working directory to root and verifies the
// result stays within root: a "../" escape (or an absolute Dir, which Join
// re-roots under the sandbox) can never place a command outside its sandbox.
func resolveDir(root, sub string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("sandbox: resolve root: %w", err)
	}
	if sub == "" {
		return absRoot, nil
	}
	joined := filepath.Join(absRoot, sub)
	rel, err := filepath.Rel(absRoot, joined)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("sandbox: working dir %q escapes the sandbox root", sub)
	}
	return joined, nil
}
