package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/xrey167/meshmcp/harness"
	"github.com/xrey167/meshmcp/mcpclient"
	"github.com/xrey167/meshmcp/policy"
)

// dialServed wires an orchestrator server to an mcpclient over an in-memory
// pipe and returns an initialized client. The audit buffer is returned so tests
// can verify the chain.
func dialServed(t *testing.T, caller harness.Identity) (*mcpclient.Client, *bytes.Buffer, func()) {
	t.Helper()
	var audit bytes.Buffer
	al := policy.NewAuditLog(&audit, func() string { return "2026-07-23T00:00:00Z" })
	eng := harness.NewEngine(harness.EngineOpts{Audit: al, Now: func() time.Time { return time.Unix(0, 0) }})
	srv := New(eng, "meshmcp-orchestrator", "0.1.0")
	if caller.Key != "" {
		srv.SetCaller(caller)
	}

	c1, c2 := net.Pipe()
	go func() { _ = srv.Serve(context.Background(), c1, c1) }()
	cli := mcpclient.New(c2, nil)
	if _, err := cli.Initialize(context.Background(), "test"); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	return cli, &audit, func() { cli.Close(); c1.Close() }
}

func callResult(t *testing.T, cli *mcpclient.Client, tool string, args any) (text string, isErr bool) {
	t.Helper()
	raw, err := cli.CallTool(context.Background(), tool, args, false)
	if err != nil {
		t.Fatalf("call %s: %v", tool, err)
	}
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("decode %s result: %v", tool, err)
	}
	if len(r.Content) > 0 {
		text = r.Content[0].Text
	}
	return text, r.IsError
}

// TestCatalogRegistered asserts the full tool catalog is advertised.
func TestCatalogRegistered(t *testing.T) {
	cli, _, done := dialServed(t, harness.Identity{})
	defer done()
	tools, err := cli.ListTools(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(tools) < 35 {
		t.Fatalf("expected the full catalog (>=35 tools), got %d", len(tools))
	}
}

// TestGovernedAllowDeny asserts the default orchestrator caller may grep (code.read)
// but not edit (code.write) — the firewall enforced at the MCP boundary.
func TestGovernedAllowDeny(t *testing.T) {
	cli, audit, done := dialServed(t, harness.Identity{})
	defer done()

	// grep is allowed for the orchestrator role.
	_, isErr := callResult(t, cli, "grep", map[string]any{"pattern": "package orchestrator", "glob": "*.go", "path": "."})
	if isErr {
		t.Fatalf("grep should be allowed for the orchestrator caller")
	}
	// edit is code.write — denied for the orchestrator (delegating, non-writing) role.
	txt, isErr := callResult(t, cli, "edit", map[string]any{"file": "server.go", "old": "x", "new": "y"})
	if !isErr {
		t.Fatalf("edit should be denied for the orchestrator caller, got %q", txt)
	}
	// The denial is audited; the chain must still verify.
	if res, _ := policy.VerifyChain(bytes.NewReader(audit.Bytes())); !res.OK {
		t.Fatalf("audit chain broke: %s", res.Reason)
	}
}

// TestExecutorMayEdit asserts an executor caller passes the code.write firewall
// (proving the role→policy mapping, not a blanket allow).
func TestExecutorMayEdit(t *testing.T) {
	cli, _, done := dialServed(t, harness.Identity{Key: "exec-key", FQDN: "executor--mcp--0", Role: harness.RoleExecutor})
	defer done()
	// The executor may call edit (it will fail on the missing file, but NOT with
	// a governance denial — that is the distinction under test).
	txt, isErr := callResult(t, cli, "edit", map[string]any{"file": "does-not-exist.txt", "old": "x", "new": "y"})
	if isErr && contains(txt, "denied") {
		t.Fatalf("executor edit must not be denied by policy, got %q", txt)
	}
}

// TestTaskDelegation asserts the task tool opens a governed run.
func TestTaskDelegation(t *testing.T) {
	cli, _, done := dialServed(t, harness.Identity{})
	defer done()
	txt, isErr := callResult(t, cli, "task", map[string]any{"description": "add a health endpoint", "mode": "quick"})
	if isErr {
		t.Fatalf("task should be allowed: %s", txt)
	}
	if !contains(txt, "task_id") {
		t.Fatalf("task should return a task_id, got %q", txt)
	}
}

// TestMalformedArgsNoPanic asserts a bad-args call fails cleanly (no panic).
func TestMalformedArgsNoPanic(t *testing.T) {
	cli, _, done := dialServed(t, harness.Identity{})
	defer done()
	_, isErr := callResult(t, cli, "grep", map[string]any{}) // missing required pattern
	if !isErr {
		t.Fatalf("grep with no pattern should error, not succeed")
	}
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }
