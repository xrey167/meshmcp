package sandbox

import (
	"context"
	"runtime"
	"testing"
)

// TestFactoryUnknownKind asserts an unknown backend is a clean error.
func TestFactoryUnknownKind(t *testing.T) {
	if _, err := New(context.Background(), Spec{Kind: "quantum"}); err == nil {
		t.Fatal("unknown sandbox kind must error")
	}
}

// TestFactoryHonorsMinimum asserts New returns the stronger of Kind and Min, and
// that a stub backend (docker) is fail-closed rather than local.
func TestFactoryHonorsMinimum(t *testing.T) {
	sb, err := New(context.Background(), Spec{Kind: "local", Min: "docker"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer sb.Close()
	if sb.Kind() != "docker" {
		t.Fatalf("policy minimum docker must win over requested local, got %q", sb.Kind())
	}
	// docker is a fail-closed stub in this build.
	if _, err := sb.Exec(context.Background(), Command{Args: []string{"echo", "hi"}}); err == nil {
		t.Fatal("the docker stub must fail closed, not run on the host")
	}
}

// TestAtLeastUnknownPairs asserts AtLeast fails CLOSED on unrecognized kinds: an
// unknown policy minimum is never silently satisfied by a weaker backend.
func TestAtLeastUnknownPairs(t *testing.T) {
	// An unknown MINIMUM must be preserved so the factory rejects it rather than
	// downgrading to host exec — the original fail-open bug.
	if got := AtLeast("local", "alsomystery"); got != "alsomystery" {
		t.Fatalf("an unknown minimum must be preserved (fail closed), got %q", got)
	}
	if _, err := New(context.Background(), Spec{Kind: "local", Min: "alsomystery"}); err == nil {
		t.Fatal("an unrecognized policy minimum must be rejected, not downgraded to local")
	}
	// An unknown REQUESTED kind resolves to the known minimum.
	if got := AtLeast("mystery", "worktree"); got != "worktree" {
		t.Fatalf("unknown request should resolve to the known minimum, got %q", got)
	}
	if got := AtLeast("local", "worktree"); got != "worktree" {
		t.Fatalf("worktree is stronger than local, got %q", got)
	}
	if got := AtLeast("docker", "tmux"); got != "docker" {
		t.Fatalf("docker is stronger than tmux, got %q", got)
	}
}

// TestExecDirContainment asserts a "../" working directory cannot escape the
// sandbox root — a command is confined to its sandbox by construction.
func TestExecDirContainment(t *testing.T) {
	l := NewLocal(".")
	if _, err := l.Exec(context.Background(), Command{Args: []string{"echo", "hi"}, Dir: "../../.."}); err == nil {
		t.Fatal("a ../ working dir must be rejected, not allowed to escape the sandbox root")
	}
	// A sane relative subdir under the root is still fine.
	if _, err := l.Exec(context.Background(), Command{Args: []string{"echo", "hi"}, Dir: "."}); err != nil {
		t.Fatalf("an in-root working dir must be allowed, got %v", err)
	}
}

// TestLocalEmptyCommand asserts an empty command is a clean error.
func TestLocalEmptyCommand(t *testing.T) {
	if _, err := NewLocal(".").Exec(context.Background(), Command{}); err == nil {
		t.Fatal("empty command must error")
	}
}

// TestLocalCapturesStderr asserts stderr is captured alongside stdout.
func TestLocalCapturesStderr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	res, err := NewLocal(".").Exec(context.Background(), Command{Args: []string{"sh", "-c", "echo out; echo err 1>&2"}})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.Stdout == "" || res.Stderr == "" {
		t.Fatalf("expected both streams captured: %+v", res)
	}
}
