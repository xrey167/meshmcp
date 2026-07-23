package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/edge"
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
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "The public OAuth ingress for hosted MCP clients (e.g. claude.ai).")
		fmt.Fprintln(os.Stderr, "Off by default; runs only when invoked with an operator-written config.")
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

	srv, err := edge.New(cfg, edge.Options{})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "meshmcp edge: serving %s on %s (backend %q)\n", cfg.PublicURL, cfg.Listen, cfg.Backend.Name)
	return srv.Run(ctx)
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
