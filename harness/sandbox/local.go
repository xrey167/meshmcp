package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
)

// Local runs commands directly on the host in a fixed root directory. It is the
// weakest isolation and is used only for the main/trusted identity; policy
// forces a stronger backend for non-main or channel-originated work.
type Local struct {
	root string
}

// NewLocal builds a local sandbox rooted at root (defaults to the current
// directory when empty).
func NewLocal(root string) *Local {
	if root == "" {
		root = "."
	}
	return &Local{root: root}
}

func (l *Local) Kind() string { return "local" }
func (l *Local) Root() string { return l.root }

// Exec runs cmd on the host. The working directory is resolved under the root.
func (l *Local) Exec(ctx context.Context, cmd Command) (ExecResult, error) {
	if len(cmd.Args) == 0 {
		return ExecResult{}, errors.New("sandbox: empty command")
	}
	if cmd.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cmd.Timeout)
		defer cancel()
	}
	c := exec.CommandContext(ctx, cmd.Args[0], cmd.Args[1:]...)
	c.Dir = filepath.Join(l.root, cmd.Dir)
	if len(cmd.Env) > 0 {
		c.Env = append(c.Environ(), cmd.Env...)
	}
	if cmd.Stdin != "" {
		c.Stdin = bytes.NewReader([]byte(cmd.Stdin))
	}
	var out, errb bytes.Buffer
	c.Stdout = &out
	c.Stderr = &errb
	err := c.Run()
	res := ExecResult{Stdout: out.String(), Stderr: errb.String()}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil // a non-zero exit is a result, not a harness error
		}
		return res, err
	}
	return res, nil
}

// Close is a no-op for the local sandbox.
func (l *Local) Close() error { return nil }
