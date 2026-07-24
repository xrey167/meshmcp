package orchestrator

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/xrey167/meshmcp/mcp"
)

// Real code-intelligence backends. lsp_symbols and lsp_diagnostics are wired for
// Go via the standard library's go/parser (self-contained, no external process).
// ast_grep_search/ast_grep_replace shell out to the `ast-grep` binary when it is
// on PATH, and fail closed with an actionable note when it is not — never a
// silent success. The remaining lsp_* tools stay governed-pending until a
// language server is wired.

// symbol is one declaration in a file outline.
type symbol struct {
	Kind string `json:"kind"` // func | method | type | var | const
	Name string `json:"name"`
	Line int    `json:"line"`
}

// goSymbols returns the top-level declaration outline of a Go source file.
func goSymbols(file string) ([]symbol, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []symbol
	line := func(p token.Pos) int { return fset.Position(p).Line }
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			kind := "func"
			if d.Recv != nil {
				kind = "method"
			}
			out = append(out, symbol{Kind: kind, Name: d.Name.Name, Line: line(d.Pos())})
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch sp := spec.(type) {
				case *ast.TypeSpec:
					out = append(out, symbol{Kind: "type", Name: sp.Name.Name, Line: line(sp.Pos())})
				case *ast.ValueSpec:
					for _, n := range sp.Names {
						if n.Name == "_" {
							continue
						}
						out = append(out, symbol{Kind: d.Tok.String(), Name: n.Name, Line: line(n.Pos())})
					}
				}
			}
		}
	}
	return out, nil
}

// diag is one parse diagnostic.
type diag struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Col  int    `json:"col"`
	Msg  string `json:"msg"`
}

// goDiagnostics parses a Go file (or every .go file under a directory) and
// returns syntax errors. A clean parse yields an empty slice.
func goDiagnostics(path string) ([]diag, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var files []string
	if info.IsDir() {
		_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				if d != nil && d.IsDir() && skipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(p, ".go") {
				files = append(files, p)
			}
			return nil
		})
	} else {
		files = []string{path}
	}
	var out []diag
	fset := token.NewFileSet()
	for _, f := range files {
		if _, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution); err != nil {
			if el, ok := err.(scanner.ErrorList); ok {
				for _, e := range el {
					out = append(out, diag{File: e.Pos.Filename, Line: e.Pos.Line, Col: e.Pos.Column, Msg: e.Msg})
				}
			} else {
				out = append(out, diag{File: f, Msg: err.Error()})
			}
		}
	}
	return out, nil
}

// astGrepPath returns the ast-grep binary path if it is on PATH.
func astGrepPath() (string, bool) {
	for _, name := range []string{"ast-grep", "sg"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, true
		}
	}
	return "", false
}

// astGrepUnavailable is the fail-closed result when the binary is absent.
func astGrepUnavailable(tool string) mcp.ToolResult {
	return jsonText(map[string]any{
		"tool":   tool,
		"status": "authorized; the ast-grep binary is not installed on this host",
		"note":   "install ast-grep (https://ast-grep.github.io) to enable structural search/rewrite; the call passed the firewall and was audited",
	})
}

func (s *Server) toolLspSymbols(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.File == "" {
		return errText("file is required"), nil
	}
	if !strings.HasSuffix(p.File, ".go") {
		return jsonText(map[string]any{
			"file":   p.File,
			"status": "the built-in outline supports Go; other languages need the LSP backend (pending)",
		}), nil
	}
	syms, err := goSymbols(p.File)
	if err != nil {
		return errText("lsp_symbols: %v", err), nil
	}
	return jsonText(map[string]any{"file": p.File, "symbols": syms, "count": len(syms)}), nil
}

func (s *Server) toolLspDiagnostics(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.File == "" {
		return errText("file (or workspace path) is required"), nil
	}
	diags, err := goDiagnostics(p.File)
	if err != nil {
		return errText("lsp_diagnostics: %v", err), nil
	}
	return jsonText(map[string]any{"path": p.File, "diagnostics": diags, "count": len(diags), "clean": len(diags) == 0}), nil
}

func (s *Server) toolAstGrepSearch(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Pattern string `json:"pattern"`
		Lang    string `json:"lang"`
		Path    string `json:"path"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Pattern == "" {
		return errText("pattern is required"), nil
	}
	bin, ok := astGrepPath()
	if !ok {
		return astGrepUnavailable("ast_grep_search"), nil
	}
	root := p.Path
	if root == "" {
		root = "."
	}
	cmdArgs := []string{"run", "--pattern", p.Pattern}
	if p.Lang != "" {
		cmdArgs = append(cmdArgs, "--lang", p.Lang)
	}
	cmdArgs = append(cmdArgs, root)
	out, err := runCmd(ctx, bin, cmdArgs)
	if err != nil {
		return errText("ast_grep_search: %v", err), nil
	}
	return text(out), nil
}

func (s *Server) toolAstGrepReplace(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Pattern string `json:"pattern"`
		Rewrite string `json:"rewrite"`
		Lang    string `json:"lang"`
		Path    string `json:"path"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Pattern == "" || p.Rewrite == "" {
		return errText("pattern and rewrite are required"), nil
	}
	bin, ok := astGrepPath()
	if !ok {
		return astGrepUnavailable("ast_grep_replace"), nil
	}
	root := p.Path
	if root == "" {
		root = "."
	}
	cmdArgs := []string{"run", "--pattern", p.Pattern, "--rewrite", p.Rewrite, "--update-all"}
	if p.Lang != "" {
		cmdArgs = append(cmdArgs, "--lang", p.Lang)
	}
	cmdArgs = append(cmdArgs, root)
	out, err := runCmd(ctx, bin, cmdArgs)
	if err != nil {
		return errText("ast_grep_replace: %v", err), nil
	}
	return text(out), nil
}

// runCmd runs bin with args and returns combined stdout+stderr, capped.
func runCmd(ctx context.Context, bin string, args []string) (string, error) {
	c := exec.CommandContext(ctx, bin, args...)
	out, err := c.CombinedOutput()
	s := string(out)
	if len(s) > 64*1024 {
		s = s[:64*1024] + "\n…(truncated)"
	}
	if err != nil && s == "" {
		return "", err
	}
	return s, nil
}
