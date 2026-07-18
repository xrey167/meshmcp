// vectors is a zero-exposure RAG (retrieval) MCP server built on the
// meshmcp/mcp framework (F3). It embeds and searches documents locally — no
// external model, no network — so a corpus can be served over the mesh and
// reached only by authorized peers (the gateway supplies identity, policy, and
// audit). Every search result carries a provenance ref (the document's content
// hash + the identity that upserted it), the substrate for verifiable answers
// (F6) and taint-contained retrieval (F7).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"meshmcp/mcp"
)

func main() {
	indexPath, dim := "vectors.jsonl", 256
	for i, a := range os.Args {
		if a == "--index" && i+1 < len(os.Args) {
			indexPath = os.Args[i+1]
		}
		if a == "--dim" && i+1 < len(os.Args) {
			fmt.Sscanf(os.Args[i+1], "%d", &dim)
		}
	}
	ix, err := openIndex(indexPath, newHashingEmbedder(dim))
	if err != nil {
		fmt.Fprintln(os.Stderr, "vectors:", err)
		os.Exit(1)
	}
	peer := os.Getenv("MESHMCP_PEER_KEY")
	if peer == "" {
		peer = os.Getenv("MESHMCP_PEER")
	}
	fmt.Fprintf(os.Stderr, "vectors: started for peer %q, index %s (%d docs, dim %d)\n", peer, indexPath, ix.count(), dim)

	s := mcp.New("meshmcp-vectors", "0.1.0")
	registerVectors(s, ix, peer)

	if err := s.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "vectors:", err)
		os.Exit(1)
	}
}

func registerVectors(s *mcp.Server, ix *index, peer string) {
	s.AddTool(mcp.Tool{
		Name:        "upsert",
		Description: "Add or replace a document in the corpus. Its embedding is computed and stored, stamped with the caller's mesh identity.",
		InputSchema: obj(map[string]any{
			"id":     str("stable document id (upsert replaces an existing id)"),
			"text":   str("the document text to index"),
			"corpus": str("optional corpus/collection name for scoped search"),
		}, "id", "text"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct{ ID, Text, Corpus string }
			if err := json.Unmarshal(args, &a); err != nil {
				return mcp.ToolResult{}, fmt.Errorf("invalid arguments: %w", err)
			}
			if a.ID == "" || a.Text == "" {
				return errText("id and text are required"), nil
			}
			d, err := ix.Upsert(a.ID, a.Text, a.Corpus, peer)
			if err != nil {
				return errText("%v", err), nil
			}
			return jsonResult(map[string]any{"id": d.ID, "hash": d.Hash, "corpus": d.Corpus}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "search",
		Description: "Retrieve the top-k documents most similar to the query. Each result includes a provenance ref (content hash + asserting identity) for verifiable answers.",
		InputSchema: obj(map[string]any{
			"query":  str("the search query"),
			"k":      num("how many results to return (default 5)"),
			"corpus": str("restrict search to this corpus (optional)"),
		}, "query"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Query, Corpus string
				K             int
			}
			if err := json.Unmarshal(args, &a); err != nil || a.Query == "" {
				return errText("query is required"), nil
			}
			hits := ix.Search(a.Query, a.K, a.Corpus)
			results := make([]map[string]any, 0, len(hits))
			refs := make([]string, 0, len(hits))
			for _, h := range hits {
				results = append(results, map[string]any{
					"id": h.Doc.ID, "score": round4(h.Score), "text": h.Doc.Text,
					"corpus": h.Doc.Corpus, "hash": h.Doc.Hash, "peer": h.Doc.Peer,
				})
				refs = append(refs, h.Doc.Hash)
			}
			// The provenance refs also ride the result _meta, so the gateway can
			// record which documents produced an answer (verifiable answers, F6).
			return jsonResultMeta(map[string]any{"count": len(results), "results": results},
				map[string]any{"meshmcp/retrieved": refs}), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "embed",
		Description: "Return the embedding vector for a text (diagnostic).",
		InputSchema: obj(map[string]any{"text": str("text to embed")}, "text"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct{ Text string }
			if err := json.Unmarshal(args, &a); err != nil || a.Text == "" {
				return errText("text is required"), nil
			}
			return jsonResult(map[string]any{"dim": ix.emb.Dim(), "vector": ix.emb.Embed(a.Text)}), nil
		},
	})

	s.AddResource(mcp.Resource{
		URI: "vectors://count", Name: "doc-count", Description: "Number of documents in the index.", MimeType: "text/plain",
		Read: func(_ context.Context) (mcp.ResourceContents, error) {
			return mcp.ResourceContents{URI: "vectors://count", MimeType: "text/plain", Text: fmt.Sprintf("%d", ix.count())}, nil
		},
	})
}

func round4(f float64) float64 { return float64(int64(f*10000+0.5)) / 10000 }

func jsonResult(v any) mcp.ToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return mcp.ToolResult{Content: []mcp.Content{mcp.Text(string(b))}}
}

// jsonResultMeta is like jsonResult but note: the mcp framework's ToolResult
// does not carry a top-level _meta, so we fold the provenance refs into the
// returned JSON body under "_meta" for the gateway/agent to read.
func jsonResultMeta(v map[string]any, meta map[string]any) mcp.ToolResult {
	v["_meta"] = meta
	return jsonResult(v)
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
