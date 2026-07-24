package harness

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestSpawnEmptyCommandFailsClosed(t *testing.T) {
	sp := &ExecSpawner{}
	if _, err := sp.Spawn(context.Background(), SpawnSpec{Identity: Identity{FQDN: "x"}}); err == nil {
		t.Fatal("an empty command must fail closed")
	}
}

func TestCuratedEnvNoParentLeak(t *testing.T) {
	// A secret in the parent environment must NOT appear in the worker's env.
	t.Setenv("HARNESS_TEST_SECRET", "leak-me")
	spec := SpawnSpec{
		Identity: Identity{FQDN: "executor--r--0", Role: RoleExecutor},
		Creds:    WorkerCreds{SetupKey: "sk", MgmtURL: "https://m", PrivKey: "pk"},
	}
	env := curatedEnv(nil, spec)
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "HARNESS_TEST_SECRET") || strings.Contains(joined, "leak-me") {
		t.Fatalf("parent secret leaked into worker env:\n%s", joined)
	}
	// The mesh-join creds and identity markers MUST be present.
	for _, want := range []string{EnvSetupKey + "=sk", EnvMgmtURL + "=https://m", EnvWGPrivate + "=pk", EnvWorkerFQDN + "=executor--r--0", EnvWorkerRole + "=executor"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in worker env:\n%s", want, joined)
		}
	}
}

func TestSpawnWorkerNoCredsFailsClosed(t *testing.T) {
	m := NewEnrollMinter(&mockEnroller{})
	sp := &ExecSpawner{}
	// An identity the minter never minted has no creds.
	_, err := SpawnWorker(context.Background(), sp, m, Identity{Key: "unknown", FQDN: "x"}, []string{"true"})
	if err == nil {
		t.Fatal("spawning an unminted identity must fail closed")
	}
}

func TestExecSpawnerRunsWithCuratedEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	t.Setenv("HARNESS_TEST_SECRET", "leak-me")
	var out bytes.Buffer
	sp := &ExecSpawner{}
	// The worker echoes its identity marker and setup key, and attempts to echo
	// the parent secret (which must come back empty).
	spec := SpawnSpec{
		Identity: Identity{FQDN: "executor--run--0", Role: RoleExecutor},
		Creds:    WorkerCreds{SetupKey: "setup-123"},
		Command:  []string{"sh", "-c", `printf "%s|%s|%s" "$MESHMCP_WORKER_FQDN" "$NB_SETUP_KEY" "$HARNESS_TEST_SECRET"`},
		Stdout:   &out,
	}
	h, err := sp.Spawn(context.Background(), spec)
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	if h.PID <= 0 {
		t.Fatalf("expected a positive PID, got %d", h.PID)
	}
	if err := h.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	got := out.String()
	if got != "executor--run--0|setup-123|" {
		t.Fatalf("unexpected worker output %q — creds should be injected and the parent secret absent", got)
	}
}

func TestExecSpawnerStopKills(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	sp := &ExecSpawner{}
	h, err := sp.Spawn(context.Background(), SpawnSpec{
		Identity: Identity{FQDN: "w"},
		Command:  []string{"sh", "-c", "sleep 30"},
	})
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}
	if err := h.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	// Wait returns a non-nil error for a killed process (signal: killed).
	if err := h.Wait(); err == nil {
		t.Fatal("a killed worker's Wait should report the signal")
	}
}
