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

	"gopkg.in/yaml.v3"

	"meshmcp/mcp"
	"meshmcp/mcpclient"
)

// meshmcp graphrag — GraphRAG bridge (S3).
//
// It serves one tool, graph_search, that combines entity-centric retrieval
// from the knowledge graph (F2) with document retrieval from the vector store
// (F3), both reached over the mesh. A query first pulls the top documents from
// `vectors.search`, then expands named entities via `kg_neighbors`, returning a
// merged context — richer than either source alone, and every hop is identity-
// attributed and audited by the gateways in front of each backend.

// GraphRAGConfig configures the bridge.
type GraphRAGConfig struct {
	Mesh       MeshConfig `yaml:"mesh"`
	ListenPort int        `yaml:"listen_port"`
	Vectors    string     `yaml:"vectors"` // mesh addr of the vectors backend
	KG         string     `yaml:"kg"`      // mesh addr of the kg backend
}

func loadGraphRAGConfig(path string) (*GraphRAGConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg GraphRAGConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return nil, errors.New("listen_port must be 1-65535")
	}
	if cfg.Vectors == "" || cfg.KG == "" {
		return nil, errors.New("both vectors and kg upstream addresses are required")
	}
	return &cfg, nil
}

func cmdGraphRAG(args []string) error {
	fs := flag.NewFlagSet("graphrag", flag.ExitOnError)
	cfgPath := fs.String("config", "graphrag.yaml", "path to the graphrag config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadGraphRAGConfig(*cfgPath)
	if err != nil {
		return err
	}

	client, err := startMesh(cfg.Mesh.options(), os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	ln, err := client.ListenTCP(fmt.Sprintf(":%d", cfg.ListenPort))
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", cfg.ListenPort, err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() { <-sig; ln.Close() }()

	dial := func(ctx context.Context, addr string) (net.Conn, error) { return client.Dial(ctx, "tcp", addr) }
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("graphrag shutting down")
			return nil
		}
		go func(conn net.Conn) {
			defer conn.Close()
			s := mcp.New("meshmcp-graphrag", "0.1.0")
			registerGraphSearch(s, dial, cfg.Vectors, cfg.KG)
			_ = s.Serve(context.Background(), conn, conn)
		}(conn)
	}
}

func registerGraphSearch(s *mcp.Server, dial dialFunc, vectorsAddr, kgAddr string) {
	s.AddTool(mcp.Tool{
		Name:        "graph_search",
		Description: "GraphRAG: retrieve documents for the query from the vector store, then expand entities via the knowledge graph, returning a merged context.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string", "description": "the question / search text"},
				"k":     map[string]any{"type": "number", "description": "number of seed documents (default 5)"},
			},
			"required": []string{"query"},
		},
		Handler: func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Query string  `json:"query"`
				K     float64 `json:"k"`
			}
			if err := json.Unmarshal(args, &a); err != nil || a.Query == "" {
				return mcp.ToolResult{Content: []mcp.Content{mcp.Text("query is required")}, IsError: true}, nil
			}

			docs := callJSON(ctx, dial, vectorsAddr, "search", map[string]any{"query": a.Query, "k": a.K})
			entities := extractEntities(docs)
			triples := map[string]json.RawMessage{}
			for _, e := range entities {
				triples[e] = callJSONRaw(ctx, dial, kgAddr, "kg_neighbors", map[string]any{"node": e})
			}
			out := mergeGraphRAG(a.Query, docs, triples)
			return mcp.ToolResult{Content: []mcp.Content{mcp.Text(out)}}, nil
		},
	})
}

// mergeGraphRAG formats a combined context from vector hits and KG expansions.
// Kept pure (no I/O) so it is unit-testable.
func mergeGraphRAG(query string, docs searchResult, kgByEntity map[string]json.RawMessage) string {
	out := fmt.Sprintf("GraphRAG context for %q\n\nDocuments (%d):\n", query, len(docs.Results))
	for _, d := range docs.Results {
		out += fmt.Sprintf("  - [%s] (score %.3f) %s\n", d.ID, d.Score, truncate(d.Text, 120))
	}
	if len(kgByEntity) > 0 {
		out += "\nKnowledge-graph expansion:\n"
		for entity, raw := range kgByEntity {
			out += fmt.Sprintf("  %s:\n", entity)
			var kg struct {
				Triples []struct{ S, P, O string } `json:"triples"`
			}
			_ = json.Unmarshal(raw, &kg)
			for _, t := range kg.Triples {
				out += fmt.Sprintf("    (%s %s %s)\n", t.S, t.P, t.O)
			}
		}
	}
	return out
}

// searchResult mirrors the vectors `search` tool JSON output.
type searchResult struct {
	Count   int `json:"count"`
	Results []struct {
		ID    string  `json:"id"`
		Score float64 `json:"score"`
		Text  string  `json:"text"`
	} `json:"results"`
}

// extractEntities pulls candidate entity strings (document ids) to expand in
// the KG. A production version would run NER; ids are a deterministic proxy.
func extractEntities(r searchResult) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range r.Results {
		if !seen[d.ID] {
			seen[d.ID] = true
			out = append(out, d.ID)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// callJSON dials addr, calls tool, and decodes its first text content as a
// searchResult (best-effort; returns an empty result on any error).
func callJSON(ctx context.Context, dial dialFunc, addr, tool string, args any) searchResult {
	raw := callJSONRaw(ctx, dial, addr, tool, args)
	var r searchResult
	_ = json.Unmarshal(raw, &r)
	return r
}

// callJSONRaw dials addr and returns the tool's first text content as raw JSON.
func callJSONRaw(ctx context.Context, dial dialFunc, addr, tool string, args any) json.RawMessage {
	conn, err := dial(ctx, addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	uc := mcpclient.New(conn, nil)
	defer uc.Close()
	if _, err := uc.Initialize(ctx, "meshmcp-graphrag"); err != nil {
		return nil
	}
	raw, err := uc.CallTool(ctx, tool, args, false)
	if err != nil {
		return nil
	}
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || len(r.Content) == 0 {
		return nil
	}
	return json.RawMessage(r.Content[0].Text)
}
