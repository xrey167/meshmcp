// kg is a provenance-native knowledge-graph MCP server built on the meshmcp/mcp
// framework (F2). Every triple is stamped with the asserting mesh identity
// (the gateway-supplied MESHMCP_PEER_KEY) and linked into a tamper-evident
// hash chain, so the graph is non-repudiable — you can prove who asserted what,
// and that nothing was silently altered. Because every record carries a
// monotonic sequence number, the graph is also time-travelable: any query can
// run "as of" a past sequence (F8).
//
// It is an ordinary stdio MCP server: run it behind `meshmcp serve` to get
// identity, policy (subgraph labels), and audit for free — no gateway change.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"meshmcp/mcp"
)

func main() {
	storePath := "kg.jsonl"
	for i, a := range os.Args {
		if a == "--store" && i+1 < len(os.Args) {
			storePath = os.Args[i+1]
		}
	}
	st, err := openStore(storePath, func() string { return time.Now().UTC().Format(time.RFC3339) })
	if err != nil {
		fmt.Fprintln(os.Stderr, "kg:", err)
		os.Exit(1)
	}
	// The gateway stamps the caller's cryptographic identity into the
	// subprocess environment; that becomes each triple's provenance.
	peer := os.Getenv("MESHMCP_PEER_KEY")
	if peer == "" {
		peer = os.Getenv("MESHMCP_PEER")
	}
	fmt.Fprintf(os.Stderr, "kg: started for peer %q, store %s (%d records)\n", peer, storePath, st.head())

	s := mcp.New("meshmcp-kg", "0.1.0")
	registerKG(s, st, peer)

	if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "kg:", err)
		os.Exit(1)
	}
}

func registerKG(s *mcp.Server, st *store, peer string) {
	s.AddTool(mcp.Tool{
		Name:        "kg_assert",
		Description: "Assert a (subject, predicate, object) triple. Stamped with the caller's mesh identity and hash-chained (non-repudiable).",
		InputSchema: obj(map[string]any{
			"subject":   str("the entity the fact is about"),
			"predicate": str("the relationship / attribute"),
			"object":    str("the value / related entity"),
		}, "subject", "predicate", "object"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct{ Subject, Predicate, Object string }
			if err := json.Unmarshal(args, &a); err != nil {
				return mcp.ToolResult{}, fmt.Errorf("invalid arguments: %w", err)
			}
			r, err := st.assert(a.Subject, a.Predicate, a.Object, peer)
			if err != nil {
				return errText("%v", err), nil
			}
			return jsonResult(map[string]any{"id": r.ID, "seq": r.Seq, "hash": r.Hash}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "kg_query",
		Description: "Query triples by pattern (empty fields are wildcards). Optional as_of replays the graph at a past sequence number (time-travel).",
		InputSchema: obj(map[string]any{
			"subject":   str("match subject (optional)"),
			"predicate": str("match predicate (optional)"),
			"object":    str("match object (optional)"),
			"as_of":     num("sequence number to query the graph as of (optional; 0 = now)"),
		}),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Subject, Predicate, Object string
				AsOf                       int `json:"as_of"`
			}
			_ = json.Unmarshal(args, &a)
			return jsonResult(triplesOut(st.query(a.Subject, a.Predicate, a.Object, a.AsOf))), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "kg_neighbors",
		Description: "Return triples where the given node appears as subject or object (entity-centric expansion for GraphRAG).",
		InputSchema: obj(map[string]any{
			"node":  str("the node to expand"),
			"as_of": num("sequence number to query as of (optional)"),
		}, "node"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Node string
				AsOf int `json:"as_of"`
			}
			if err := json.Unmarshal(args, &a); err != nil || a.Node == "" {
				return errText("node is required"), nil
			}
			return jsonResult(triplesOut(st.neighbors(a.Node, a.AsOf))), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "kg_delete",
		Description: "Tombstone a triple by id. The deletion is itself an audited, hash-chained record (nothing is erased from history).",
		InputSchema: obj(map[string]any{"id": str("the triple id to delete")}, "id"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct{ ID string }
			if err := json.Unmarshal(args, &a); err != nil || a.ID == "" {
				return errText("id is required"), nil
			}
			r, err := st.del(a.ID, peer)
			if err != nil {
				return errText("%v", err), nil
			}
			return jsonResult(map[string]any{"deleted": a.ID, "seq": r.Seq}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "kg_verify",
		Description: "Verify the graph's hash chain — proves no fact was edited, reordered, or deleted from history. Returns the head sequence.",
		InputSchema: obj(map[string]any{}),
		Handler: func(_ context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
			if err := st.verify(); err != nil {
				return errText("VERIFY FAILED: %v", err), nil
			}
			return jsonResult(map[string]any{"ok": true, "head": st.head()}), nil
		},
	})

	s.AddResource(mcp.Resource{
		URI: "kg://head", Name: "kg-head", Description: "Current sequence number of the knowledge graph.", MimeType: "text/plain",
		Read: func(_ context.Context) (mcp.ResourceContents, error) {
			return mcp.ResourceContents{URI: "kg://head", MimeType: "text/plain", Text: fmt.Sprintf("%d", st.head())}, nil
		},
	})
}

// triplesOut renders records for a tool result.
func triplesOut(recs []record) map[string]any {
	items := make([]map[string]any, 0, len(recs))
	for _, r := range recs {
		items = append(items, map[string]any{
			"id": r.ID, "s": r.S, "p": r.P, "o": r.O, "seq": r.Seq, "peer": r.Peer,
		})
	}
	return map[string]any{"count": len(items), "triples": items}
}

func jsonResult(v any) mcp.ToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return mcp.ToolResult{Content: []mcp.Content{mcp.Text(string(b))}}
}

func errText(format string, a ...any) mcp.ToolResult {
	return mcp.ToolResult{Content: []mcp.Content{mcp.Text(fmt.Sprintf(format, a...))}, IsError: true}
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func num(desc string) map[string]any { return map[string]any{"type": "number", "description": desc} }
