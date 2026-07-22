package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMergeGraphRAG(t *testing.T) {
	docs := searchResult{Count: 2}
	docs.Results = append(docs.Results,
		struct {
			ID    string  `json:"id"`
			Score float64 `json:"score"`
			Text  string  `json:"text"`
		}{ID: "alice", Score: 0.91, Text: "Alice leads the payments team."},
		struct {
			ID    string  `json:"id"`
			Score float64 `json:"score"`
			Text  string  `json:"text"`
		}{ID: "bob", Score: 0.72, Text: "Bob maintains the ledger service."},
	)

	kg := map[string]json.RawMessage{
		"alice": json.RawMessage(`{"triples":[{"s":"alice","p":"knows","o":"bob"}]}`),
	}

	out := mergeGraphRAG("who leads payments", docs, kg)
	for _, want := range []string{"who leads payments", "alice", "bob", "0.910", "(alice knows bob)"} {
		if !strings.Contains(out, want) {
			t.Errorf("merged output missing %q\n%s", want, out)
		}
	}
}

func TestExtractEntitiesDedup(t *testing.T) {
	var r searchResult
	for _, id := range []string{"a", "b", "a", "c"} {
		r.Results = append(r.Results, struct {
			ID    string  `json:"id"`
			Score float64 `json:"score"`
			Text  string  `json:"text"`
		}{ID: id})
	}
	got := extractEntities(r)
	if len(got) != 3 {
		t.Fatalf("expected 3 unique entities, got %v", got)
	}
}
