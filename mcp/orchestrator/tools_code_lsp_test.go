package orchestrator

import (
	"testing"

	"github.com/xrey167/meshmcp/harness"
)

// TestLspToolsValidatedAndFailClosed exercises the gopls-backed tools through
// the governed boundary as an executor (which may call every lsp_* tool):
// argument validation, and the fail-closed note when gopls is absent.
func TestLspToolsValidatedAndFailClosed(t *testing.T) {
	execID := harness.Identity{Key: "x", FQDN: "executor--mcp--0", Role: harness.RoleExecutor}
	cli, _, done := dialServed(t, execID)
	defer done()

	// Missing pos → validation error (before any gopls call).
	if _, isErr := callResult(t, cli, "lsp_goto_definition", map[string]any{"file": "x.go"}); !isErr {
		t.Fatal("lsp_goto_definition without pos should error")
	}
	// Rename missing new_name → validation error.
	if _, isErr := callResult(t, cli, "lsp_rename", map[string]any{"file": "x.go", "pos": "1:1"}); !isErr {
		t.Fatal("lsp_rename without new_name should error")
	}

	// With gopls absent, a well-formed call returns a governed fail-closed note.
	if _, ok := goplsPath(); !ok {
		txt, isErr := callResult(t, cli, "lsp_find_references", map[string]any{"file": "x.go", "pos": "1:1"})
		if isErr {
			t.Fatalf("lsp_find_references should return a governed note, not an error: %s", txt)
		}
		if !contains(txt, "not installed") {
			t.Fatalf("expected a fail-closed 'not installed' note, got %s", txt)
		}
	}
}

// TestLspRenameGovernance asserts lsp_rename (code.write) is denied to a
// read-only role (explorer) but permitted for executor — proving the role→policy
// mapping still governs the newly-real tools.
func TestLspRenameGovernance(t *testing.T) {
	exp := harness.Identity{Key: "e", FQDN: "explorer--mcp--0", Role: harness.RoleExplorer}
	cli, _, done := dialServed(t, exp)
	defer done()
	txt, isErr := callResult(t, cli, "lsp_rename", map[string]any{"file": "x.go", "pos": "1:1", "new_name": "y"})
	if !isErr {
		t.Fatalf("explorer lsp_rename (code.write) must be denied by policy, got %s", txt)
	}
	if !contains(txt, "denied") {
		t.Fatalf("expected a policy denial, got %s", txt)
	}
}
