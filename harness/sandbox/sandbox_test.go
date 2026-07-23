package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalExec(t *testing.T) {
	sb := NewLocal(".")
	res, err := sb.Exec(context.Background(), Command{Args: []string{"echo", "hi"}})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if strings.TrimSpace(res.Stdout) != "hi" || res.ExitCode != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestLocalNonZeroExitIsResult(t *testing.T) {
	sb := NewLocal(".")
	res, err := sb.Exec(context.Background(), Command{Args: []string{"sh", "-c", "exit 3"}})
	if err != nil {
		t.Fatalf("a non-zero exit should be a result, not an error: %v", err)
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit code = %d, want 3", res.ExitCode)
	}
}

func TestAtLeastNeverWeakens(t *testing.T) {
	if got := AtLeast("local", "docker"); got != "docker" {
		t.Fatalf("policy minimum must win: got %q", got)
	}
	if got := AtLeast("docker", "local"); got != "docker" {
		t.Fatalf("stronger request should stand: got %q", got)
	}
}

func TestStubFailsClosed(t *testing.T) {
	s := NewStub("docker")
	_, err := s.Exec(context.Background(), Command{Args: []string{"echo", "hi"}})
	if err == nil {
		t.Fatal("an unavailable isolation backend must fail closed, not run on the host")
	}
}

func TestWorktreeIsolation(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	// Build a throwaway git repo.
	dir := t.TempDir()
	run := func(args ...string) {
		c := exec.Command(args[0], args[1:]...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", args, out)
		}
	}
	run("git", "init", "-q")
	run("git", "config", "user.email", "t@example.com")
	run("git", "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("git", "add", ".")
	run("git", "commit", "-q", "-m", "init")

	wt, err := NewWorktree(context.Background(), dir, t.TempDir(), "harness-test-branch")
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if wt.Root() == "" {
		t.Fatal("worktree root empty")
	}
	// A write in the worktree must not touch the source repo's file.
	if err := os.WriteFile(filepath.Join(wt.Root(), "f.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src, _ := os.ReadFile(filepath.Join(dir, "f.txt"))
	if strings.TrimSpace(string(src)) != "base" {
		t.Fatalf("source repo file was mutated by the worktree: %q", src)
	}
	if err := wt.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
