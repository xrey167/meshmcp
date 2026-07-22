package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/xrey167/meshmcp/mcp"
)

// searchToolReturning registers a vectors-style `search` tool that answers with
// a fixed hit set (score, text, corpus). The `peer` field in each result body
// is deliberately set to a bogus "upserter" identity so the test can prove
// Spotlight tags provenance from the dialed backend, not from the result body.
func searchToolReturning(hits []spotlightHit) mcp.Tool {
	return mcp.Tool{
		Name: "search",
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Query string `json:"query"`
			}
			_ = json.Unmarshal(args, &a)
			results := make([]map[string]any, 0, len(hits))
			for _, h := range hits {
				results = append(results, map[string]any{
					"id":     h.ID,
					"score":  h.Score,
					"text":   h.Text,
					"corpus": h.Corpus,
					"hash":   h.Hash,
					"peer":   "upserter-not-answerer", // must NOT appear as provenance
				})
			}
			body, _ := json.Marshal(map[string]any{"count": len(results), "results": results})
			return mcp.ToolResult{Content: []mcp.Content{mcp.Text(string(body))}}, nil
		},
	}
}

func TestMergeSpotlightRanksAndTags(t *testing.T) {
	perPeer := map[string]spotlightResult{}
	// peerB has the single highest score; peerA has two mid results.
	perPeer["peerA"] = mustResult(spotlightHit{ID: "a1", Score: 0.40, Text: "alpha"}, spotlightHit{ID: "a2", Score: 0.90, Text: "beta"})
	perPeer["peerB"] = mustResult(spotlightHit{ID: "b1", Score: 0.95, Text: "gamma"})

	hits := mergeSpotlight(perPeer, 2)
	if len(hits) != 2 {
		t.Fatalf("top-k=2 should keep 2 hits, got %d", len(hits))
	}
	// Ranking: b1 (0.95) then a2 (0.90).
	if hits[0].ID != "b1" || hits[1].ID != "a2" {
		t.Fatalf("wrong ranking: %+v", hits)
	}
	// Provenance is the peer key we merged under, never the result body's peer.
	if hits[0].Peer != "peerB" || hits[1].Peer != "peerA" {
		t.Fatalf("provenance mis-tagged: %+v", hits)
	}
}

func TestFanoutSpotlightMergesAcrossPeersAndDegrades(t *testing.T) {
	addrA, stopA := startLoopbackServer(t, func(s *mcp.Server) {
		s.AddTool(searchToolReturning([]spotlightHit{
			{ID: "doc-a", Score: 0.70, Text: "answer from A", Corpus: "wiki"},
		}))
	})
	defer stopA()
	addrB, stopB := startLoopbackServer(t, func(s *mcp.Server) {
		s.AddTool(searchToolReturning([]spotlightHit{
			{ID: "doc-b", Score: 0.88, Text: "answer from B", Corpus: "code"},
		}))
	})
	defer stopB()

	peers := map[string]string{
		"alpha": addrA,
		"bravo": addrB,
		"ghost": "127.0.0.1:1", // unreachable: must degrade, not fail the query
	}
	ctx := context.Background()
	perPeer := fanoutSpotlight(ctx, loopbackDial, peers, "search", "what is it", "", 5)

	// The unreachable peer contributes an empty result rather than an error.
	if len(perPeer) != 3 {
		t.Fatalf("expected an entry per peer (incl. empty ghost), got %d", len(perPeer))
	}
	if len(perPeer["ghost"].Results) != 0 {
		t.Fatalf("unreachable peer should contribute no results")
	}

	hits := mergeSpotlight(perPeer, 5)
	if len(hits) != 2 {
		t.Fatalf("expected 2 merged hits from the two reachable peers, got %d: %+v", len(hits), hits)
	}
	// bravo (0.88) ranks above alpha (0.70), each provenance-tagged by the peer
	// we dialed — not by the result body's "upserter" field.
	if hits[0].Peer != "bravo" || hits[0].ID != "doc-b" {
		t.Fatalf("top hit should be bravo/doc-b, got %+v", hits[0])
	}
	if hits[1].Peer != "alpha" || hits[1].ID != "doc-a" {
		t.Fatalf("second hit should be alpha/doc-a, got %+v", hits[1])
	}
	for _, h := range hits {
		if h.Peer == "upserter-not-answerer" {
			t.Fatalf("provenance leaked from result body: %+v", h)
		}
	}
}

// mustResult builds a spotlightResult from hits (test helper).
func mustResult(hits ...spotlightHit) spotlightResult {
	var r spotlightResult
	r.Count = len(hits)
	for _, h := range hits {
		r.Results = append(r.Results, struct {
			ID     string  `json:"id"`
			Score  float64 `json:"score"`
			Text   string  `json:"text"`
			Corpus string  `json:"corpus"`
			Hash   string  `json:"hash"`
		}{ID: h.ID, Score: h.Score, Text: h.Text, Corpus: h.Corpus, Hash: h.Hash})
	}
	return r
}
