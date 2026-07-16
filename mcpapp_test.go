package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"meshmcp/mcp"
	"meshmcp/policy"
)

func writeAudit(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	a := policy.NewAuditLog(f, func() string { return "2026-07-16T10:00:00Z" })
	a.Append(policy.AuditRecord{Backend: "fs", Peer: "reader.mesh", Method: "tools/call", Tool: "read_file", Decision: "allow"})
	a.Append(policy.AuditRecord{Backend: "pay", Peer: "billing.mesh", Method: "tools/call", Tool: "transfer_funds", Decision: "cosign"})
}

func TestMCPAppRegistersControlTools(t *testing.T) {
	app := &meshApp{}
	s := mcp.New("t", "1")
	app.register(s)
	// The tools are registered on the server; exercising a handler proves wiring.
	res, _ := app.toolListTools(context.Background(), []byte(`{"target":"100.64.0.1:9101"}`))
	if !res.IsError || len(res.Content) == 0 {
		t.Fatalf("list_tools without mesh should error, got %+v", res)
	}
}

func TestMCPAppNetwork(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	writeAudit(t, audit)
	app := &meshApp{auditPath: audit}
	res, _ := app.toolNetwork(context.Background(), nil)
	if res.IsError {
		t.Fatalf("network errored: %+v", res)
	}
	body := res.Content[0].Text
	if !strings.Contains(body, "chain_ok") || !strings.Contains(body, "reader.mesh") {
		t.Fatalf("network summary missing expected data:\n%s", body)
	}
}

func TestMCPAppApprovalFlow(t *testing.T) {
	dir := t.TempDir()
	ps := &policy.FilePending{Dir: dir}
	_ = ps.Record(policy.Pending{Peer: "billing.mesh", Backend: "pay", Tool: "transfer_funds"})
	app := &meshApp{cosignDir: dir}

	// pending_approvals lists it.
	res, _ := app.toolPending(context.Background(), nil)
	if res.IsError || !strings.Contains(res.Content[0].Text, "transfer_funds") {
		t.Fatalf("pending should list the held call: %+v", res)
	}
	// approve writes a grant and clears it.
	app.toolApprove(context.Background(), []byte(`{"peer":"billing.mesh","tool":"transfer_funds"}`))
	cos := &policy.FileCosign{Dir: dir}
	if !cos.Approved(policy.CosignKey("billing.mesh", "transfer_funds")) {
		t.Fatalf("approve should have written a grant")
	}
	res2, _ := app.toolPending(context.Background(), nil)
	if strings.Contains(res2.Content[0].Text, "transfer_funds") {
		t.Fatalf("pending should be cleared after approve")
	}
}

func TestMCPAppVerify(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	writeAudit(t, audit)
	app := &meshApp{auditPath: audit}
	res, _ := app.toolVerify(context.Background(), []byte(`{}`))
	if res.IsError || !strings.Contains(res.Content[0].Text, `"OK": true`) {
		t.Fatalf("verify should report an intact chain: %+v", res.Content[0])
	}
}
