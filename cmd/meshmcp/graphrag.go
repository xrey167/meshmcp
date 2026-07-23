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

	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/air/know"
	"github.com/xrey167/meshmcp/air/rag"
	"github.com/xrey167/meshmcp/embed"
	"github.com/xrey167/meshmcp/mcp"
	"github.com/xrey167/meshmcp/mcpclient"
)

// meshmcp graphrag — GraphRAG bridge (S3).
//
// It serves one tool, graph_search, that combines entity-centric retrieval
// from the knowledge graph (F2) with document retrieval from the vector store
// (F3), both reached over the mesh. A query first pulls the top documents from
// `vectors.search`, then LINKS real entities against the KG node vocabulary
// (air/rag.LinkEntities — cosine over the shared embedder, deny-below-threshold,
// never fabricating a node) and expands only the linked nodes via
// `kg_neighbors`, returning a merged context — richer than either source alone.
// Every hop is identity-attributed and audited by the gateways in front of each
// backend, and every retrieved KG triple enters the merged context ONLY inside
// the untrusted-content envelope (S6), so a poisoned fact reads as data, never
// as instructions.

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
	signal.Notify(sig, shutdownSignals...)
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

// graphToolCaller is the mesh-call seam runGraphSearch reaches backends
// through: production wires callJSONRaw over the mesh dialer, tests inject a
// fake, so the linking/merging logic is provable without a mesh.
type graphToolCaller func(ctx context.Context, addr, tool string, args any) json.RawMessage

// graphRAGLinkEmbedder is the shared local lexical embedder (the same default
// insight and air-rag use), so entity surfaces and KG node names meet in one
// vector space with zero new deps.
var graphRAGLinkEmbedder = embed.NewHashing(256)

func registerGraphSearch(s *mcp.Server, dial dialFunc, vectorsAddr, kgAddr string) {
	call := func(ctx context.Context, addr, tool string, args any) json.RawMessage {
		return callJSONRaw(ctx, dial, addr, tool, args)
	}
	s.AddTool(mcp.Tool{
		Name:        "graph_search",
		Description: "GraphRAG: retrieve documents for the query from the vector store, link real entities against the knowledge graph, and expand the linked nodes, returning a merged context (KG facts envelope-fenced as untrusted data).",
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
			out := runGraphSearch(ctx, call, vectorsAddr, kgAddr, a.Query, a.K)
			return mcp.ToolResult{Content: []mcp.Content{mcp.Text(out)}}, nil
		},
	})
}

// runGraphSearch is the bridge's whole retrieval flow behind the call seam:
// vector search → entity LINKING against the KG node vocabulary (deny-below-
// threshold, subset-of-vocabulary — doc IDs never reach the KG) → k-hop
// expansion of the linked nodes only → merged, envelope-fenced context.
func runGraphSearch(ctx context.Context, call graphToolCaller, vectorsAddr, kgAddr, query string, k float64) string {
	var docs searchResult
	_ = json.Unmarshal(call(ctx, vectorsAddr, "search", map[string]any{"query": query, "k": k}), &docs)

	// The KG node vocabulary: one wildcard kg_query (governed and audited by
	// the gateway in front of the KG backend), folded to the set of node names.
	var vocab struct {
		Triples []struct {
			S string `json:"s"`
			O string `json:"o"`
		} `json:"triples"`
	}
	_ = json.Unmarshal(call(ctx, kgAddr, "kg_query", map[string]any{}), &vocab)
	seen := map[string]bool{}
	var nodes []string
	for _, t := range vocab.Triples {
		for _, n := range [2]string{t.S, t.O} {
			if n != "" && !seen[n] {
				seen[n] = true
				nodes = append(nodes, n)
			}
		}
	}

	texts := make([]string, 0, len(docs.Results))
	for _, d := range docs.Results {
		texts = append(texts, d.Text)
	}
	links := rag.LinkEntities(graphRAGLinkEmbedder, query, texts, nodes, rag.DefaultLinkThreshold)

	triples := map[string]json.RawMessage{}
	for _, l := range links {
		if _, done := triples[l.Node]; done {
			continue
		}
		triples[l.Node] = call(ctx, kgAddr, "kg_neighbors", map[string]any{"node": l.Node})
	}
	return mergeGraphRAG(query, docs, triples)
}

// mergeGraphRAG formats a combined context from vector hits and KG expansions.
// Kept pure (no mesh I/O) so it is unit-testable. Every entity's retrieved
// triples enter the context ONLY inside the S6 untrusted-content envelope
// (nonce-fenced, breakout-proof), mirroring what the air-rag chunk path already
// does — a poisoned triple object like "ignore prior instructions" is framed as
// data a model must not obey.
func mergeGraphRAG(query string, docs searchResult, kgByEntity map[string]json.RawMessage) string {
	out := fmt.Sprintf("GraphRAG context for %q\n\nDocuments (%d):\n", query, len(docs.Results))
	for _, d := range docs.Results {
		out += fmt.Sprintf("  - [%s] (score %.3f) %s\n", d.ID, d.Score, truncate(d.Text, 120))
	}
	if len(kgByEntity) > 0 {
		out += "\nKnowledge-graph expansion:\n"
		for entity, raw := range kgByEntity {
			var kg struct {
				Triples []struct{ S, P, O string } `json:"triples"`
			}
			_ = json.Unmarshal(raw, &kg)
			var lines []string
			for _, t := range kg.Triples {
				lines = append(lines, fmt.Sprintf("(%s %s %s)", t.S, t.P, t.O))
			}
			out += fmt.Sprintf("  %s:\n", entity)
			out += know.WrapUntrustedFrom(strings.Join(lines, "\n"), "kg:"+entity).Render() + "\n"
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
