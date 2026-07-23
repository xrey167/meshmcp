package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/edge"
	"github.com/xrey167/meshmcp/pgstore"
)

// cmdEdge runs the public OAuth ingress: `meshmcp edge --config edge.yaml`.
//
// The edge is meshmcp's only public listener and is off unless this command is
// run explicitly with an operator-written config. It terminates OAuth for
// hosted MCP clients (e.g. claude.ai custom connectors) and exposes exactly one
// tool-scoped mesh backend at /mcp. See docs/spec/OAUTH-STANDARDS.md (the
// recorded exposure-model decision) and docs/COOKBOOK.md.
func cmdEdge(args []string) error {
	fs := flag.NewFlagSet("edge", flag.ExitOnError)
	configPath := fs.String("config", "", "path to edge.yaml (required)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: meshmcp edge --config edge.yaml")
		fmt.Fprintln(os.Stderr, "       meshmcp edge clients <list|approve|deny|revoke> --state <dir> [client_id]")
		fmt.Fprintln(os.Stderr, "       meshmcp edge authz   <list|approve|deny> --state <dir> [request_id]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "The public OAuth ingress for hosted MCP clients (e.g. claude.ai).")
		fmt.Fprintln(os.Stderr, "Off by default; runs only when invoked with an operator-written config.")
	}

	// Management subcommands own the remaining args via their own flag sets.
	if len(args) > 0 {
		switch args[0] {
		case "clients":
			return cmdEdgeClients(args[1:])
		case "authz":
			return cmdEdgeAuthz(args[1:])
		case "tokens":
			return cmdEdgeTokens(args[1:])
		}
	}

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		fs.Usage()
		return fmt.Errorf("edge: --config is required")
	}

	cfg, err := loadEdgeConfig(*configPath)
	if err != nil {
		return err
	}

	var opts edge.Options
	// A configured shared DPoP replay store must open before anything else
	// starts: an edge that silently fell back to per-process replay tracking
	// would be a security downgrade, so open failure refuses startup.
	if dsn := cfg.OAuth.DPoPReplayStore; dsn != "" {
		if !isPostgresDSN(dsn) {
			return fmt.Errorf("edge: oauth.dpop_replay_store must be a postgres:// or postgresql:// DSN")
		}
		store, err := pgstore.Open(dsn)
		if err != nil {
			return fmt.Errorf("edge: open dpop_replay_store %s: %w", redactDSN(dsn), err)
		}
		defer store.Close()
		opts.DPoPReplay = store
		fmt.Fprintf(os.Stderr, "meshmcp edge: dpop replay store %s (shared)\n", redactDSN(dsn))
	}

	// Join the mesh so the one configured backend (a mesh address) is reachable,
	// exactly as `federate` does. When no setup key is configured, fall back to a
	// plain TCP dial so an edge co-located with its backend (or a test) still
	// works without a mesh.
	meshKey, err := resolveEdgeSetupKey(cfg.Mesh)
	if err != nil {
		return err
	}
	if meshKey != "" {
		client, err := startMesh(edgeMeshOptions(cfg.Mesh, meshKey), os.Stderr)
		if err != nil {
			return fmt.Errorf("edge: join mesh: %w", err)
		}
		defer client.Stop(context.Background())
		opts.DialBackend = func(ctx context.Context) (net.Conn, error) {
			return client.Dial(ctx, "tcp", cfg.Backend.Addr)
		}
		fmt.Fprintf(os.Stderr, "meshmcp edge: joined mesh, backend %s reachable over WireGuard\n", cfg.Backend.Addr)
	}

	srv, err := edge.New(cfg, opts)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "meshmcp edge: serving %s on %s (backend %q)\n", cfg.PublicURL, cfg.Listen, cfg.Backend.Name)
	return srv.Run(ctx)
}

// resolveEdgeSetupKey resolves the NetBird setup key from a file, env var, or
// literal (in that order of preference for keeping the secret out of config).
func resolveEdgeSetupKey(m edge.MeshConfig) (string, error) {
	if m.SetupKeyFile != "" {
		b, err := os.ReadFile(m.SetupKeyFile)
		if err != nil {
			return "", fmt.Errorf("edge: read mesh setup_key_file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if m.SetupKey != "" {
		return m.SetupKey, nil
	}
	env := m.SetupKeyEnv
	if env == "" {
		env = "NB_SETUP_KEY"
	}
	return os.Getenv(env), nil
}

// edgeMeshOptions maps the edge MeshConfig onto the shared meshOptions. The edge
// blocks inbound mesh connections — it only dials out to its one backend.
func edgeMeshOptions(m edge.MeshConfig, key string) *meshOptions {
	mgmt := m.ManagementURL
	if mgmt == "" {
		mgmt = os.Getenv("NB_MANAGEMENT_URL")
	}
	logLevel := m.LogLevel
	if logLevel == "" {
		logLevel = "warn"
	}
	return &meshOptions{
		DeviceName:    m.DeviceName,
		ManagementURL: mgmt,
		SetupKey:      key,
		ConfigPath:    m.ConfigPath,
		LogLevel:      logLevel,
		BlockInbound:  true,
		WireguardPort: m.WireguardPort,
	}
}

// loadEdgeConfig reads edge.yaml with strict decoding — an unknown or misspelled
// key is a startup error, not a silently ignored line, the same discipline the
// gateway's loadConfig uses for security-relevant fields.
func loadEdgeConfig(path string) (edge.Config, error) {
	var cfg edge.Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("edge: read config %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("edge: parse config %s: %w", path, err)
	}
	return cfg, nil
}
