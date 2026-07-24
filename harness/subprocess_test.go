package harness

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/policy"
)

// TestSubprocessWorkerExecution asserts that, with a Spawner + WorkerCommand
// configured, the scheduler runs execute-stage jobs as external worker PROCESSES
// (not in-process providers): the process runs with the task injected into its
// environment, the run completes, worker records are sealed as "process", and
// the audit chain still verifies.
func TestSubprocessWorkerExecution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	marker := filepath.Join(t.TempDir(), "worker.out")

	var buf bytes.Buffer
	al := policy.NewAuditLog(&buf, fixedClock())
	eng := NewEngine(EngineOpts{
		Audit:   al,
		Spawner: &ExecSpawner{},
		// The worker appends its injected task to a marker file — proof it ran as
		// a process with the curated env.
		WorkerCommand: []string{"sh", "-c", `printf "task=%s\n" "$MESHMCP_TASK" >> ` + marker},
		Now:           func() time.Time { return time.Unix(0, 0) },
	})

	st, err := eng.Run(context.Background(), RunRequest{Goal: "build the widget", Mode: ModeQuick, Actor: Identity{Key: "k"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if st.Status != RunDone {
		t.Fatalf("status = %s (err=%s)", st.Status, st.Error)
	}

	// At least one worker must have run as a subprocess.
	foundProcess := false
	for _, w := range st.Workers {
		if w.SandboxKind == "process" {
			foundProcess = true
		}
	}
	if !foundProcess {
		t.Fatalf("expected a subprocess worker (SandboxKind=process), got %+v", st.Workers)
	}

	// The worker process actually ran with the task injected into its env.
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("worker did not run (no marker file): %v", err)
	}
	if !strings.Contains(string(data), "task=") {
		t.Fatalf("worker ran but MESHMCP_TASK was not injected: %q", string(data))
	}

	// Governance/audit is intact for the subprocess path.
	if res, _ := policy.VerifyChain(bytes.NewReader(buf.Bytes())); !res.OK {
		t.Fatalf("audit chain broke: %s", res.Reason)
	}
}

// TestInProcessDefaultUnchanged asserts the default (no Spawner) still uses
// in-process workers — the subprocess path is strictly opt-in.
func TestInProcessDefaultUnchanged(t *testing.T) {
	eng := NewEngine(EngineOpts{Now: func() time.Time { return time.Unix(0, 0) }})
	st, err := eng.Run(context.Background(), RunRequest{Goal: "do work", Mode: ModeQuick, Actor: Identity{Key: "k"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, w := range st.Workers {
		if w.SandboxKind == "process" {
			t.Fatalf("default engine must not spawn subprocess workers, got %+v", w)
		}
	}
}
