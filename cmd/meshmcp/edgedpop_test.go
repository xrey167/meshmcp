package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeEdgeConfig writes a minimal edge.yaml carrying only the replay-store
// key; cmdEdge's replay-store wiring runs (and must fail) before full config
// validation or any mesh/listener work.
func writeEdgeConfig(t *testing.T, dsn string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "edge.yaml")
	data := "oauth:\n  dpop_replay_store: \"" + dsn + "\"\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCmdEdgeRejectsNonPostgresReplayStore(t *testing.T) {
	path := writeEdgeConfig(t, "mysql://u:p@db/x")
	err := cmdEdge([]string{"--config", path})
	if err == nil || !strings.Contains(err.Error(), "must be a postgres") {
		t.Fatalf("want scheme error, got %v", err)
	}
}

// TestCmdEdgeRefusesStartOnReplayStoreOpenFailure: an unreachable shared
// replay store is fatal (fail closed) and the error carries the redacted DSN,
// never the password.
func TestCmdEdgeRefusesStartOnReplayStoreOpenFailure(t *testing.T) {
	for _, tc := range []struct {
		name, dsn, secret string
	}{
		// Connect (dial) failure: pgconn omits the password itself.
		{"dial failure", "postgres://u:secretpw@127.0.0.1:1/db?sslmode=disable&connect_timeout=2", "secretpw"},
		// Parse failure with the password as a URL query parameter: pgx's
		// ParseConfigError echoes the raw connection string, so this leaks
		// unless pgstore scrubs its errors.
		{"parse failure with query password", "postgres://u@127.0.0.1:1/db?password=S3cretQP&sslmode=bogus", "S3cretQP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeEdgeConfig(t, tc.dsn)
			err := cmdEdge([]string{"--config", path})
			if err == nil {
				t.Fatal("want startup refusal, got nil")
			}
			if !strings.Contains(err.Error(), "open dpop_replay_store") {
				t.Fatalf("want open failure, got %v", err)
			}
			if strings.Contains(err.Error(), tc.secret) {
				t.Fatalf("error leaks the DSN password: %v", err)
			}
		})
	}
}
