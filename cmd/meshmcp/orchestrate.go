package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"

	"github.com/netbirdio/netbird/client/embed"
	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/mcp"
	"github.com/xrey167/meshmcp/mcpclient"
)

// OrchestrateConfig configures a server-to-server node: it joins the mesh,
// serves an MCP endpoint with a "research" tool, and fulfils that tool by
// calling another MCP server's tools over the mesh.
type OrchestrateConfig struct {
	Mesh       MeshConfig `yaml:"mesh"`
	ListenPort int        `yaml:"listen_port"`
	Upstream   string     `yaml:"upstream"` // peer-ip:port of the server to call
}

func loadOrchestrateConfig(path string) (*OrchestrateConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg OrchestrateConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return nil, errors.New("listen_port must be 1-65535")
	}
	if cfg.Upstream == "" {
		return nil, errors.New("upstream is required")
	}
	return &cfg, nil
}

// cmdOrchestrate runs the server-to-server orchestrator.
func cmdOrchestrate(args []string) error {
	fs := flag.NewFlagSet("orchestrate", flag.ExitOnError)
	cfgPath := fs.String("config", "orchestrate.yaml", "path to the orchestrate config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadOrchestrateConfig(*cfgPath)
	if err != nil {
		return err
	}

	client, err := startMesh(cfg.Mesh.options(), os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	if st, err := client.Status(); err == nil {
		log.Printf("orchestrator up: %s (%s) — upstream %s on port %d",
			st.LocalPeerState.IP, st.LocalPeerState.FQDN, cfg.Upstream, cfg.ListenPort)
	}

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", cfg.ListenPort))
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", cfg.ListenPort, err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, shutdownSignals...)
	go func() { <-sig; ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("orchestrator shutting down")
			return nil
		}
		go handleOrchestrateConn(client, conn, cfg.Upstream)
	}
}

func handleOrchestrateConn(client *embed.Client, conn net.Conn, upstream string) {
	defer conn.Close()
	ctx := context.Background()
	s := mcp.New("meshmcp-orchestrator", "0.1.0")
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		return client.Dial(ctx, "tcp", addr)
	}
	registerResearch(s, dial, upstream)
	_ = s.Serve(ctx, conn, conn)
}

// registerResearch registers the server-to-server demo tool. Its handler
// calls two tools (add + echo) on the upstream server over the mesh and
// combines their results — a server acting as a client to another server.
func registerResearch(s *mcp.Server, dial dialFunc, upstream string) {
	s.AddTool(mcp.Tool{
		Name: "research",
		Description: "Server-to-server demo: over the mesh, calls add + echo on the upstream MCP " +
			"server and combines the results.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"topic": map[string]any{"type": "string", "description": "text to echo via the upstream"},
				"a":     map[string]any{"type": "number", "description": "first addend"},
				"b":     map[string]any{"type": "number", "description": "second addend"},
			},
			"required": []string{"topic"},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Topic string  `json:"topic"`
				A     float64 `json:"a"`
				B     float64 `json:"b"`
			}
			_ = json.Unmarshal(args, &a)

			conn, err := dial(ctx, upstream)
			if err != nil {
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("upstream dial failed: " + err.Error())}, IsError: true}, nil
			}
			uc := mcpclient.New(conn, nil)
			defer uc.Close()
			if _, err := uc.Initialize(ctx, "meshmcp-orchestrator"); err != nil {
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("upstream initialize failed: " + err.Error())}, IsError: true}, nil
			}

			sum := callText(ctx, uc, "add", map[string]any{"a": a.A, "b": a.B})
			echoed := callText(ctx, uc, "echo", map[string]any{"text": a.Topic})

			out := fmt.Sprintf("orchestrated over the mesh via upstream %s:\n  add(%v,%v) = %s\n  echo(%q) = %s",
				upstream, a.A, a.B, sum, a.Topic, echoed)
			return mcp.ToolResult{Content: []mcp.Content{mcp.Text(out)}}, nil
		},
	})
}

// callText calls an upstream tool and extracts the first text content.
func callText(ctx context.Context, uc *mcpclient.Client, tool string, args any) string {
	raw, err := uc.CallTool(ctx, tool, args, false)
	if err != nil {
		return "error: " + err.Error()
	}
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || len(r.Content) == 0 {
		return strings.TrimSpace(string(raw))
	}
	return r.Content[0].Text
}
