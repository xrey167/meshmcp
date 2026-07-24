package orchestrator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xrey167/meshmcp/harness"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const sampleGo = `package x

import "fmt"

type T struct{}

func (t T) M() {}

func F() { fmt.Println("hi") }

var V = 1

const C = 2
`

func TestGoSymbols(t *testing.T) {
	f := writeTemp(t, "sample.go", sampleGo)
	syms, err := goSymbols(f)
	if err != nil {
		t.Fatalf("goSymbols: %v", err)
	}
	got := map[string]string{} // name -> kind
	for _, s := range syms {
		got[s.Name] = s.Kind
	}
	want := map[string]string{"T": "type", "M": "method", "F": "func", "V": "var", "C": "const"}
	for name, kind := range want {
		if got[name] != kind {
			t.Errorf("symbol %q: got kind %q, want %q (all: %+v)", name, got[name], kind, syms)
		}
	}
	// Imports must not appear as symbols.
	if _, ok := got["fmt"]; ok {
		t.Error("import should not be a symbol")
	}
}

func TestGoDiagnosticsCleanAndError(t *testing.T) {
	clean := writeTemp(t, "clean.go", sampleGo)
	diags, err := goDiagnostics(clean)
	if err != nil {
		t.Fatalf("diagnostics(clean): %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("clean file should have no diagnostics, got %+v", diags)
	}

	broken := writeTemp(t, "broken.go", "package x\n\nfunc F( {\n")
	diags, err = goDiagnostics(broken)
	if err != nil {
		t.Fatalf("diagnostics(broken): %v", err)
	}
	if len(diags) == 0 {
		t.Fatal("broken file should produce a diagnostic")
	}
	if diags[0].Line == 0 {
		t.Errorf("diagnostic should carry a position: %+v", diags[0])
	}
}

func TestGoDiagnosticsDirectory(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.go"), []byte(sampleGo), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "b.go"), []byte("package x\nfunc ("), 0o644)
	diags, err := goDiagnostics(dir)
	if err != nil {
		t.Fatalf("diagnostics(dir): %v", err)
	}
	if len(diags) == 0 {
		t.Fatal("directory with a broken file should produce a diagnostic")
	}
}

// TestLspSymbolsGoverned proves lsp_symbols works through the governed MCP
// boundary for a role that may call it (explorer), and is denied for one that
// may not (orchestrator).
func TestLspSymbolsGoverned(t *testing.T) {
	f := writeTemp(t, "sample.go", sampleGo)

	// explorer may call lsp_symbols (code.read).
	cli, _, done := dialServed(t, harness.Identity{Key: "e", FQDN: "explorer--mcp--0", Role: harness.RoleExplorer})
	defer done()
	txt, isErr := callResult(t, cli, "lsp_symbols", map[string]any{"file": f})
	if isErr {
		t.Fatalf("explorer lsp_symbols should be allowed: %s", txt)
	}
	if !contains(txt, "\"M\"") || !contains(txt, "method") {
		t.Fatalf("expected the outline to include method M, got %s", txt)
	}

	// orchestrator may NOT call lsp_symbols (not in its allowlist).
	cli2, _, done2 := dialServed(t, harness.Identity{})
	defer done2()
	_, isErr = callResult(t, cli2, "lsp_symbols", map[string]any{"file": f})
	if !isErr {
		t.Fatal("orchestrator lsp_symbols should be denied by policy")
	}
}

// TestAstGrepFailClosed asserts ast_grep_search fails closed with an actionable
// note when the binary is absent (deterministic on hosts without ast-grep).
func TestAstGrepFailClosed(t *testing.T) {
	if _, ok := astGrepPath(); ok {
		t.Skip("ast-grep is installed; skipping the fail-closed path")
	}
	cli, _, done := dialServed(t, harness.Identity{Key: "e", FQDN: "explorer--mcp--0", Role: harness.RoleExplorer})
	defer done()
	txt, isErr := callResult(t, cli, "ast_grep_search", map[string]any{"pattern": "fmt.Println($A)"})
	if isErr {
		t.Fatalf("ast_grep_search should return a governed note, not an error: %s", txt)
	}
	if !contains(txt, "not installed") {
		t.Fatalf("expected a fail-closed 'not installed' note, got %s", txt)
	}
}
