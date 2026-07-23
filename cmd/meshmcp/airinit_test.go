package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/air"
)

// writeScaffold builds and writes a scaffold to a temp path, returning the path.
func writeScaffold(t *testing.T, opts scaffoldOptions) string {
	t.Helper()
	if opts.OutPath == "" {
		opts.OutPath = filepath.Join(t.TempDir(), "meshmcp.yaml")
	}
	cfg, _, err := buildScaffoldConfig(opts)
	if err != nil {
		t.Fatalf("buildScaffoldConfig: %v", err)
	}
	data, err := renderScaffoldYAML(cfg)
	if err != nil {
		t.Fatalf("renderScaffoldYAML: %v", err)
	}
	if err := os.WriteFile(opts.OutPath, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return opts.OutPath
}

// TestScaffoldRoundTripValid proves the generated config loads through the REAL
// loadConfig and carries the safe defaults: deny-by-default + audit on.
func TestScaffoldRoundTripValid(t *testing.T) {
	path := writeScaffold(t, scaffoldOptions{DeviceName: "gw"})

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("generated config failed to load: %v", err)
	}
	if cfg.AuditLog == "" {
		t.Errorf("audit is off — expected a gateway-wide audit ledger")
	}
	if len(cfg.Backends) == 0 {
		t.Fatalf("no backends generated")
	}
	for _, b := range cfg.Backends {
		if b.Policy == nil {
			t.Fatalf("backend %q has no policy", b.Name)
		}
		if b.Policy.DefaultAllow {
			t.Errorf("backend %q is not deny-by-default", b.Name)
		}
	}
	if cfg.Control == nil || cfg.Control.Port == 0 {
		t.Errorf("control endpoint missing — pairing seam not laid")
	}
	if len(cfg.Control.Allow) == 0 {
		t.Errorf("control endpoint has no allow list (would fail loadConfig's default-deny check)")
	}
}

// TestScaffoldNoSecretsOnDisk proves the irreducible setup key is never written.
func TestScaffoldNoSecretsOnDisk(t *testing.T) {
	t.Setenv("NB_SETUP_KEY", "super-secret-value")
	path := writeScaffold(t, scaffoldOptions{DeviceName: "gw"})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "super-secret-value") {
		t.Fatalf("setup key leaked into the config file")
	}
	if strings.Contains(string(data), "setup_key:") {
		t.Errorf("config wrote a literal setup_key field")
	}
}

// TestScaffoldBackendWiring proves --backend name=cmd and name=http wire the
// correct transport and increment ports deterministically.
func TestScaffoldBackendWiring(t *testing.T) {
	specs := []air.BackendSpec{
		{Name: "kg", Stdio: []string{"python", "-m", "srv"}},
		{Name: "web", HTTP: "http://127.0.0.1:3001"},
	}
	path := writeScaffold(t, scaffoldOptions{DeviceName: "gw", Backends: specs})
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Backends) != 2 {
		t.Fatalf("want 2 backends, got %d", len(cfg.Backends))
	}
	kg := cfg.Backends[0]
	if kg.Name != "kg" || len(kg.Stdio) != 3 || kg.Port != scaffoldFirstPort {
		t.Errorf("kg backend wired wrong: %+v", kg)
	}
	web := cfg.Backends[1]
	if web.Name != "web" || web.HTTP != "http://127.0.0.1:3001" || web.Port != scaffoldFirstPort+1 {
		t.Errorf("web backend wired wrong: %+v", web)
	}
}

// TestInitNoClobberAndForce proves init refuses to overwrite without --force.
func TestInitNoClobberAndForce(t *testing.T) {
	// Root scaffold state under a temp home so the test never writes into the
	// real user config dir.
	t.Setenv("MESHMCP_HOME", t.TempDir())
	dir := t.TempDir()
	out := filepath.Join(dir, "meshmcp.yaml")

	if err := cmdAirInit([]string{"--out", out, "--name", "gw"}); err != nil {
		t.Fatalf("first init: %v", err)
	}
	// Second init without --force must refuse.
	if err := cmdAirInit([]string{"--out", out, "--name", "gw"}); err == nil {
		t.Fatalf("expected no-clobber error on second init")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("unexpected error: %v", err)
	}
	// With --force it succeeds.
	if err := cmdAirInit([]string{"--out", out, "--name", "gw2", "--force"}); err != nil {
		t.Fatalf("force init: %v", err)
	}
	cfg, err := loadConfig(out)
	if err != nil {
		t.Fatalf("load after force: %v", err)
	}
	if cfg.Mesh.DeviceName != "gw2" {
		t.Errorf("force did not overwrite: device = %q", cfg.Mesh.DeviceName)
	}
}

// TestSetupKeyAbsentInitSucceeds proves that a missing setup key does not crash
// init; the config is still generated and the guidance path is signalled.
func TestSetupKeyAbsentInitSucceeds(t *testing.T) {
	t.Setenv("NB_SETUP_KEY", "")
	_, summary, err := buildScaffoldConfig(scaffoldOptions{DeviceName: "gw", OutPath: "x.yaml"})
	if err != nil {
		t.Fatalf("init failed with absent key: %v", err)
	}
	if summary.SetupKeyFound {
		t.Errorf("setup key reported found when absent")
	}
	if !strings.Contains(summary.NextStep, "export NB_SETUP_KEY") {
		t.Errorf("guidance next-step missing, got %q", summary.NextStep)
	}
}

// TestSetupKeyPresentDetected proves a present $NB_SETUP_KEY is detected.
func TestSetupKeyPresentDetected(t *testing.T) {
	t.Setenv("NB_SETUP_KEY", "present")
	_, summary, err := buildScaffoldConfig(scaffoldOptions{DeviceName: "gw", OutPath: "x.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if !summary.SetupKeyFound {
		t.Errorf("present setup key not detected")
	}
	if summary.NextStep != "air up" {
		t.Errorf("next step = %q, want 'air up'", summary.NextStep)
	}
}

// TestUpScaffoldsMissingConfigAndFriendlyKeyError proves `air up` scaffolds a
// missing config, then returns the friendly key error (not a panic/raw error)
// when the setup key is absent.
func TestUpScaffoldsMissingConfigAndFriendlyKeyError(t *testing.T) {
	t.Setenv("NB_SETUP_KEY", "")
	t.Setenv("MESHMCP_HOME", t.TempDir())
	dir := t.TempDir()
	out := filepath.Join(dir, "meshmcp.yaml")

	err := cmdAirUp([]string{out})
	if !errors.Is(err, errSetupKeyMissing) {
		t.Fatalf("expected errSetupKeyMissing, got %v", err)
	}
	// The config must have been scaffolded on the way.
	if _, statErr := os.Stat(out); statErr != nil {
		t.Fatalf("air up did not scaffold the missing config: %v", statErr)
	}
	cfg, lerr := loadConfig(out)
	if lerr != nil {
		t.Fatalf("scaffolded config invalid: %v", lerr)
	}
	if cfg.AuditLog == "" || cfg.Backends[0].Policy.DefaultAllow {
		t.Errorf("scaffolded-by-up config is not safe-by-default")
	}
}

// TestScaffoldBaseDirRootsIdentity proves the whole point of the canonical data
// directory: with a BaseDir set, the generated identity (nb config), audit
// ledger, and pairing store all live at absolute paths under that dir — so two
// scaffolds written to different working directories share ONE mesh identity
// instead of silently forking a second one.
func TestScaffoldBaseDirRootsIdentity(t *testing.T) {
	home := t.TempDir()

	// Two configs written to different CWD-relative output paths, but both
	// rooting their state at the same canonical data dir.
	cfgA, _, err := buildScaffoldConfig(scaffoldOptions{OutPath: "/work/a/meshmcp.yaml", DeviceName: "gw", BaseDir: home})
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	cfgB, _, err := buildScaffoldConfig(scaffoldOptions{OutPath: "/work/b/meshmcp.yaml", DeviceName: "gw", BaseDir: home})
	if err != nil {
		t.Fatalf("build B: %v", err)
	}

	// Identity path is what stabilizes the mesh IP across restarts; it must be
	// the SAME absolute path for both, and must live under the data dir.
	wantIdentity := filepath.Join(home, "meshmcp-nb.json")
	if cfgA.Mesh.ConfigPath != wantIdentity {
		t.Errorf("identity path = %q, want %q", cfgA.Mesh.ConfigPath, wantIdentity)
	}
	if cfgA.Mesh.ConfigPath != cfgB.Mesh.ConfigPath {
		t.Errorf("identity forked: %q != %q", cfgA.Mesh.ConfigPath, cfgB.Mesh.ConfigPath)
	}
	if cfgA.AuditLog != filepath.Join(home, "audit.jsonl") || cfgA.AuditLog != cfgB.AuditLog {
		t.Errorf("audit path not rooted/shared: A=%q B=%q", cfgA.AuditLog, cfgB.AuditLog)
	}
	if cfgA.Control.PairStore != filepath.Join(home, "paired.json") || cfgA.Control.PairStore != cfgB.Control.PairStore {
		t.Errorf("pair store not rooted/shared: A=%q B=%q", cfgA.Control.PairStore, cfgB.Control.PairStore)
	}
}

// TestScaffoldBaseDirEmptyKeepsCWDDefaults proves the back-compat path: with no
// BaseDir, the historical CWD-relative defaults are preserved unchanged, so
// existing workflows (and the pure round-trip tests) keep working.
func TestScaffoldBaseDirEmptyKeepsCWDDefaults(t *testing.T) {
	cfg, _, err := buildScaffoldConfig(scaffoldOptions{OutPath: "meshmcp.yaml", DeviceName: "gw"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cfg.Mesh.ConfigPath != "./meshmcp-nb.json" {
		t.Errorf("identity path = %q, want ./meshmcp-nb.json", cfg.Mesh.ConfigPath)
	}
	if cfg.AuditLog != scaffoldAuditLog {
		t.Errorf("audit path = %q, want %q", cfg.AuditLog, scaffoldAuditLog)
	}
	if cfg.Control.PairStore != scaffoldPairStore {
		t.Errorf("pair store = %q, want %q", cfg.Control.PairStore, scaffoldPairStore)
	}
}

// TestDataDirPathHonorsMeshmcpHome proves $MESHMCP_HOME overrides the OS config
// dir and that dataDirPath resolves without creating anything.
func TestDataDirPathHonorsMeshmcpHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "custom-home")
	t.Setenv("MESHMCP_HOME", home)
	got, err := dataDirPath()
	if err != nil {
		t.Fatalf("dataDirPath: %v", err)
	}
	if got != home {
		t.Errorf("dataDirPath = %q, want %q", got, home)
	}
	// Resolve-only: must NOT have created the directory as a side effect.
	if _, statErr := os.Stat(home); !os.IsNotExist(statErr) {
		t.Errorf("dataDirPath created %s (should be resolve-only): %v", home, statErr)
	}
}

// TestInitJSONShape proves --json emits the documented summary shape.
func TestInitJSONShape(t *testing.T) {
	t.Setenv("NB_SETUP_KEY", "")
	// buildScaffoldConfig drives the same summary the CLI marshals; assert shape
	// via JSON round-trip so field names/tags are locked.
	_, summary, err := buildScaffoldConfig(scaffoldOptions{DeviceName: "gw", OutPath: "meshmcp.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"config_path", "device_name", "backends", "audit_log",
		"deny_by_default", "control_port", "pair_address",
		"setup_key_env", "setup_key_found", "next_step",
	} {
		if _, ok := m[key]; !ok {
			t.Errorf("json summary missing key %q", key)
		}
	}
	if m["deny_by_default"] != true {
		t.Errorf("deny_by_default should be true in the summary")
	}
	if m["pair_address"] != "gw.netbird.cloud:9600" {
		t.Errorf("pair_address = %v", m["pair_address"])
	}
}
