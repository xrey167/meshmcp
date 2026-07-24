package harness

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// SpawnSpec describes a worker process to launch as a minted mesh identity. The
// worker joins the mesh using Creds (from an EnrollMinter) and appears on the
// mesh as exactly Identity.Key.
type SpawnSpec struct {
	Identity Identity
	Creds    WorkerCreds // mesh-join credentials (WG private key + setup key + mgmt URL)
	Command  []string    // argv of the worker process (Command[0] is the program)
	Dir      string      // working directory ("" = inherit)
	ExtraEnv []string    // additional curated env ("K=V"); NON-secret only
	Stdout   io.Writer   // "" → os.Stderr
	Stderr   io.Writer   // "" → os.Stderr
}

// Handle is a running worker process.
type Handle struct {
	Identity Identity
	PID      int
	cmd      *exec.Cmd
}

// Stop kills the worker process (used on retire / operator stop).
func (h *Handle) Stop() error {
	if h.cmd != nil && h.cmd.Process != nil {
		return h.cmd.Process.Kill()
	}
	return nil
}

// Wait blocks until the worker process exits.
func (h *Handle) Wait() error {
	if h.cmd != nil {
		return h.cmd.Wait()
	}
	return nil
}

// Spawner launches worker processes for minted identities.
type Spawner interface {
	Spawn(ctx context.Context, spec SpawnSpec) (*Handle, error)
}

// ExecSpawner launches a worker as a subprocess with a CURATED environment that
// carries only its mesh-join credentials and a minimal base — never the parent
// process's environment. This mirrors cmd/meshmcp's agentChildEnv: an
// orchestrator may hold unrelated secrets that a spawned worker has no business
// inheriting, so the worker's env is built from scratch. The credentials are
// passed by well-known env var names the worker reads to join the mesh; they are
// never logged.
type ExecSpawner struct {
	// BaseEnv are the non-secret variables every worker needs (e.g. PATH). When
	// nil, a minimal PATH derived from the current process is used.
	BaseEnv []string
}

// Standard env var names a spawned worker reads to join the mesh as its identity.
const (
	EnvSetupKey   = "NB_SETUP_KEY"
	EnvMgmtURL    = "NB_MANAGEMENT_URL"
	EnvWGPrivate  = "MESHMCP_WG_PRIVATE_KEY"
	EnvWorkerFQDN = "MESHMCP_WORKER_FQDN"
	EnvWorkerRole = "MESHMCP_WORKER_ROLE"
)

// Spawn launches the worker. It fails closed on an empty command (a worker is
// never started without an argv).
func (s *ExecSpawner) Spawn(ctx context.Context, spec SpawnSpec) (*Handle, error) {
	if len(spec.Command) == 0 {
		return nil, fmt.Errorf("spawn: empty command for worker %s", spec.Identity.FQDN)
	}
	cmd := exec.CommandContext(ctx, spec.Command[0], spec.Command[1:]...)
	cmd.Dir = spec.Dir
	cmd.Env = curatedEnv(s.BaseEnv, spec)
	cmd.Stdout = orWriter(spec.Stdout, os.Stderr)
	cmd.Stderr = orWriter(spec.Stderr, os.Stderr)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("spawn worker %s: %w", spec.Identity.FQDN, err)
	}
	return &Handle{Identity: spec.Identity, PID: cmd.Process.Pid, cmd: cmd}, nil
}

// curatedEnv builds the worker's environment from scratch: a minimal base plus
// only the mesh-join credentials and identity markers. The parent environment is
// deliberately NOT included, so no unrelated secret can leak into a worker.
func curatedEnv(base []string, spec SpawnSpec) []string {
	env := append([]string(nil), base...)
	if len(env) == 0 {
		env = []string{"PATH=" + os.Getenv("PATH")}
	}
	if spec.Creds.SetupKey != "" {
		env = append(env, EnvSetupKey+"="+spec.Creds.SetupKey)
	}
	if spec.Creds.MgmtURL != "" {
		env = append(env, EnvMgmtURL+"="+spec.Creds.MgmtURL)
	}
	if spec.Creds.PrivKey != "" {
		env = append(env, EnvWGPrivate+"="+spec.Creds.PrivKey)
	}
	env = append(env, EnvWorkerFQDN+"="+spec.Identity.FQDN)
	env = append(env, EnvWorkerRole+"="+string(spec.Identity.Role))
	env = append(env, spec.ExtraEnv...)
	return env
}

func orWriter(w, fallback io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return fallback
}

// SpawnWorker launches a worker process for an already-minted identity, pulling
// its mesh-join credentials from the EnrollMinter. It fails closed when the
// identity is unknown to the minter (not minted, or already retired), so a
// worker is never launched without a governed, revocable credential.
func SpawnWorker(ctx context.Context, sp Spawner, minter *EnrollMinter, id Identity, command []string) (*Handle, error) {
	creds, ok := minter.Creds(id.Key)
	if !ok {
		return nil, fmt.Errorf("spawn: no credentials for identity %s (not minted or already retired)", id.FQDN)
	}
	return sp.Spawn(ctx, SpawnSpec{Identity: id, Creds: creds, Command: command})
}
