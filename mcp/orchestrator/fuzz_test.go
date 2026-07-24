package orchestrator

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xrey167/meshmcp/harness"
	"github.com/xrey167/meshmcp/mcpclient"
)

// malformedPayloads is a set of hostile argument shapes every tool handler must
// survive: empty, wrong-typed, oversized, null, non-object, and unicode.
func malformedPayloads() []any {
	huge := strings.Repeat("A", 200_000)
	return []any{
		map[string]any{}, // missing everything
		map[string]any{"pattern": 12345, "file": []int{1, 2}, "pos": true},   // wrong types
		map[string]any{"pattern": huge, "file": huge, "prompt": huge},        // oversized
		map[string]any{"description": "𝕦𝕟𝕚𝕔𝕠𝕕𝕖 \x00 \n\t 💥", "goal": "\x00"}, // control chars + unicode
		json.RawMessage(`null`),                           // null arguments
		json.RawMessage(`[1,2,3]`),                        // array, not object
		json.RawMessage(`{"nested":{"a":{"b":{"c":1}}}}`), // deep nesting
	}
}

// fuzzAllTools drives every advertised tool with every malformed payload as the
// given caller, asserting each call COMPLETES (the transport-level CallTool
// returns without error) — a panic in a handler would be caught by RecoverPanics
// and surface as an error result, and a hang would fail the test's context.
func fuzzAllTools(t *testing.T, cli *mcpclient.Client) {
	t.Helper()
	tools, err := cli.ListTools(context.Background())
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) == 0 {
		t.Fatal("no tools advertised")
	}
	for _, tool := range tools {
		for i, payload := range malformedPayloads() {
			// A synchronous call; RecoverPanics turns any handler panic into a
			// result, so a returned error here means the transport/dispatch broke.
			if _, err := cli.CallTool(context.Background(), tool.Name, payload, false); err != nil {
				t.Fatalf("tool %q payload #%d broke dispatch: %v", tool.Name, i, err)
			}
		}
	}
}

// TestFuzzToolsExecutor fuzzes every tool as an executor (exercises the code /
// task / exec handlers on the allow path).
func TestFuzzToolsExecutor(t *testing.T) {
	cli, _, done := dialServed(t, harness.Identity{Key: "x", FQDN: "executor--fuzz--0", Role: harness.RoleExecutor})
	defer done()
	fuzzAllTools(t, cli)
}

// TestFuzzToolsOrchestrator fuzzes every tool as the orchestrator (exercises the
// delegation / planning / verify handlers on the allow path, and the code/exec
// tools on the deny path).
func TestFuzzToolsOrchestrator(t *testing.T) {
	cli, _, done := dialServed(t, harness.Identity{})
	defer done()
	fuzzAllTools(t, cli)
}
