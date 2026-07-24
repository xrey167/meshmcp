package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Worktree isolates a worker in its own git worktree so parallel writers cannot
// collide — the gjc isolation model. Each worker gets a private checkout of a
// branch; conflicting writes are impossible by construction (§18). Close removes
// the worktree.
type Worktree struct {
	repo   string // the source repository
	dir    string // the worktree directory
	branch string
}

// NewWorktree creates a git worktree of repo on a fresh branch named branch,
// rooted under parent. repo must be a git repository.
func NewWorktree(ctx context.Context, repo, parent, branch string) (*Worktree, error) {
	if repo == "" {
		repo = "."
	}
	abs, err := filepath.Abs(repo)
	if err != nil {
		return nil, fmt.Errorf("worktree: resolve repo: %w", err)
	}
	if parent == "" {
		parent = os.TempDir()
	}
	dir := filepath.Join(parent, "harness-wt-"+sanitize(branch))
	// `git worktree add -b <branch> <dir>` from the source repo.
	if out, err := git(ctx, abs, "worktree", "add", "-b", branch, dir); err != nil {
		return nil, fmt.Errorf("worktree: add: %w: %s", err, out)
	}
	return &Worktree{repo: abs, dir: dir, branch: branch}, nil
}

func (w *Worktree) Kind() string { return "worktree" }
func (w *Worktree) Root() string { return w.dir }

// Exec runs cmd inside the worktree.
func (w *Worktree) Exec(ctx context.Context, cmd Command) (ExecResult, error) {
	if len(cmd.Args) == 0 {
		return ExecResult{}, errors.New("sandbox: empty command")
	}
	if cmd.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cmd.Timeout)
		defer cancel()
	}
	dir, err := resolveDir(w.dir, cmd.Dir)
	if err != nil {
		return ExecResult{}, err
	}
	c := exec.CommandContext(ctx, cmd.Args[0], cmd.Args[1:]...)
	c.Dir = dir
	if len(cmd.Env) > 0 {
		c.Env = append(c.Environ(), cmd.Env...)
	}
	if cmd.Stdin != "" {
		c.Stdin = bytes.NewReader([]byte(cmd.Stdin))
	}
	var out, errb bytes.Buffer
	c.Stdout = &out
	c.Stderr = &errb
	err = c.Run()
	res := ExecResult{Stdout: out.String(), Stderr: errb.String()}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		return res, err
	}
	return res, nil
}

// Close removes the worktree and its branch. Errors are surfaced so a caller
// can log a leaked worktree rather than silently accumulate them.
func (w *Worktree) Close() error {
	ctx := context.Background()
	if _, err := git(ctx, w.repo, "worktree", "remove", "--force", w.dir); err != nil {
		// best-effort branch cleanup even if remove partially failed
		_, _ = git(ctx, w.repo, "branch", "-D", w.branch)
		return fmt.Errorf("worktree: remove: %w", err)
	}
	_, _ = git(ctx, w.repo, "branch", "-D", w.branch)
	return nil
}

func git(ctx context.Context, repo string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, "git", args...)
	c.Dir = repo
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	err := c.Run()
	return strings.TrimSpace(out.String()), err
}

func sanitize(s string) string {
	return strings.NewReplacer("/", "-", " ", "-", ":", "-").Replace(s)
}
