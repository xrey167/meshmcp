package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/policy"
)

// TestShowRetrievals verifies the S10 provenance view: it surfaces only audit
// records that carry a retrieval receipt, newest first.
func TestShowRetrievals(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	f, err := os.Create(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	log := policy.NewAuditLog(f, func() string { return "t" })
	log.Append(policy.AuditRecord{Backend: "fs", Peer: "agent", Method: "tools/call", Tool: "read_file", Decision: "allow"})
	log.Append(policy.AuditRecord{Backend: "vectors", Peer: "agent", Method: "tools/call", Tool: "search",
		Decision: "allow", Provenance: []string{"docHashA", "docHashB"}})
	log.Append(policy.AuditRecord{Backend: "kg", Peer: "agent", Method: "tools/call", Tool: "kg_query",
		Decision: "allow", Provenance: []string{"tripleHashC"}})
	f.Close()

	app := &meshApp{auditPath: auditPath}
	res, err := app.toolShowRetrievals(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	body := res.Content[0].Text

	var out struct {
		Count    int `json:"count"`
		Receipts []struct {
			Tool      string   `json:"tool"`
			Retrieved []string `json:"retrieved"`
		} `json:"receipts"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("bad result json: %v\n%s", err, body)
	}
	// Only the two records with provenance, and the KG one (newest) first.
	if out.Count != 2 {
		t.Fatalf("expected 2 receipts, got %d:\n%s", out.Count, body)
	}
	if out.Receipts[0].Tool != "kg_query" {
		t.Errorf("expected newest (kg_query) first, got %q", out.Receipts[0].Tool)
	}
	if !strings.Contains(body, "docHashA") || !strings.Contains(body, "tripleHashC") {
		t.Errorf("receipts missing provenance refs:\n%s", body)
	}
	// The plain read_file record (no provenance) must be excluded.
	if strings.Contains(body, "read_file") {
		t.Errorf("non-retrieval record leaked into receipts:\n%s", body)
	}
}
