package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/federation"
	"github.com/xrey167/meshmcp/mcp"
	"github.com/xrey167/meshmcp/mcpclient"
	"github.com/xrey167/meshmcp/policy"
)

// FederateConfig configures a federation boundary: it exposes a local upstream
// MCP server to remote orgs on other meshes, admitting only granted tools and
// auditing every crossing.
type FederateConfig struct {
	Mesh     MeshConfig           `yaml:"mesh"`
	Port     int                  `yaml:"port"`     // mesh port remote orgs connect to
	Upstream string               `yaml:"upstream"` // local MCP server addr to expose (mesh addr)
	Audit    string               `yaml:"audit"`    // crossing audit log (JSONL, hash-chained)
	Grants   []federation.Grant   `yaml:"grants"`
	Mappings []federation.Mapping `yaml:"mappings"`
}

// cmdFederate runs a federation boundary as a mesh peer.
func cmdFederate(args []string) error {
	fs := flag.NewFlagSet("federate", flag.ExitOnError)
	cfgPath := fs.String("config", "federate.yaml", "path to the federation config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	data, err := os.ReadFile(*cfgPath)
	if err != nil {
		return err
	}
	var cfg FederateConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse %s: %w", *cfgPath, err)
	}
	if cfg.Upstream == "" || cfg.Port == 0 {
		return fmt.Errorf("federate config needs upstream and port")
	}

	var audit *policy.AuditLog
	if cfg.Audit != "" {
		f, err := os.OpenFile(cfg.Audit, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		audit = policy.NewAuditLog(f, func() string { return time.Now().UTC().Format(time.RFC3339) })
	}
	boundary := federation.NewBoundary(cfg.Grants, cfg.Mappings, audit)

	client, err := startMesh(cfg.Mesh.options(), os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		return client.Dial(ctx, "tcp", addr)
	}
	ln, err := client.ListenTCP(fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		return fmt.Errorf("listen mesh port %d: %w", cfg.Port, err)
	}
	defer ln.Close()
	log.Printf("federation boundary on mesh port %d -> upstream %s", cfg.Port, cfg.Upstream)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil
		}
		go func(c net.Conn) {
			defer c.Close()
			// Resolve the remote org from the caller's cryptographic mesh identity.
			pubKey, fqdn := peerIdentity(client, c.RemoteAddr())
			org := boundary.OrgFor(fqdn, pubKey)
			ctx := context.Background()
			srv, cleanup := buildBoundaryServer(ctx, dial, boundary, org, cfg.Upstream)
			defer cleanup()
			_ = srv.Serve(ctx, c, c)
		}(conn)
	}
}

// buildBoundaryServer builds an MCP server for a single remote org: it exposes
// only the upstream tools that org is granted, and each call is re-checked and
// audited before being relayed to the local upstream (stamped with the org's
// local principal). Split out from the command so it is unit-testable against
// an in-process upstream. An empty org yields a server that admits nothing.
func buildBoundaryServer(ctx context.Context, dial dialFunc, b *federation.Boundary, org, upstream string) (*mcp.Server, func()) {
	s := mcp.New("meshmcp-federation", "0.1.0")

	conn, err := dial(ctx, upstream)
	if err != nil {
		log.Printf("federation: dial upstream %s: %v", upstream, err)
		return s, func() {}
	}
	uc := mcpclient.New(conn, nil)
	// Stamp the origin org + local principal into every relayed call's _meta,
	// so the local upstream's policy and audit see who is behind the crossing.
	uc.RequestMeta = map[string]any{
		"meshmcpFederationOrg":       org,
		"meshmcpFederationPrincipal": b.Principal(org),
	}
	if _, err := uc.Initialize(ctx, "meshmcp-federation"); err != nil {
		log.Printf("federation: initialize upstream: %v", err)
	}

	if tools, err := uc.ListTools(ctx); err == nil {
		for _, t := range tools {
			if !b.Allowed(org, t.Name) {
				continue // don't even advertise ungranted tools
			}
			tool := t
			var schema map[string]any
			if len(tool.InputSchema) > 0 {
				_ = json.Unmarshal(tool.InputSchema, &schema)
			}
			s.AddTool(mcp.Tool{
				Name:        tool.Name,
				Description: tool.Description,
				InputSchema: schema,
				Handler: func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
					// Re-check + audit at call time — advertising is not authorizing.
					if ok, reason := b.Check(org, tool.Name); !ok {
						return mcp.ToolResult{}, fmt.Errorf("federation boundary: %s", reason)
					}
					raw, err := uc.CallTool(ctx, tool.Name, args, false)
					if err != nil {
						return mcp.ToolResult{}, err
					}
					var tr mcp.ToolResult
					if err := json.Unmarshal(raw, &tr); err != nil {
						return mcp.ToolResult{}, err
					}
					return tr, nil
				},
			})
		}
	}
	return s, func() { uc.Close() }
}
