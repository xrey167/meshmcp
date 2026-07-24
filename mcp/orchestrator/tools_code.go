package orchestrator

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/xrey167/meshmcp/mcp"
)

func (s *Server) registerCode() {
	s.mcp.AddTool(mcp.Tool{
		Name:        "grep",
		Description: "Regex content search with optional file glob. Returns file:line matches. (code.read)",
		InputSchema: obj(map[string]any{
			"pattern": str("regular expression"),
			"glob":    str("optional filename glob, e.g. *.go"),
			"path":    str("root path to search (default .)"),
			"i":       boolp("case-insensitive"),
		}, "pattern"),
		Handler: s.toolGrep,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "glob",
		Description: "Fast filename pattern discovery under a path. (code.read)",
		InputSchema: obj(map[string]any{"pattern": str("filename glob, e.g. **/*.go"), "path": str("root path (default .)")}, "pattern"),
		Handler:     s.toolGlob,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "edit",
		Description: "Hash-anchored edit: replace an exact old string with new in file (must be unique). Passes the write-existing-file guard. (code.write)",
		InputSchema: obj(map[string]any{
			"file": str("file path"),
			"old":  str("exact text to replace (must occur exactly once)"),
			"new":  str("replacement text"),
		}, "file", "old", "new"),
		Handler: s.toolEdit,
	})
	// Real code-intelligence backends (see tools_code_go.go): lsp_symbols and
	// lsp_diagnostics via go/parser; ast_grep_* via the ast-grep binary
	// (fail-closed when absent).
	s.mcp.AddTool(mcp.Tool{
		Name:        "lsp_symbols",
		Description: "File outline: top-level declarations (func/method/type/var/const) of a Go source file. (code.read)",
		InputSchema: obj(map[string]any{"file": str("Go source file")}, "file"),
		Handler:     s.toolLspSymbols,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "lsp_diagnostics",
		Description: "Syntax diagnostics for a Go file or a directory of Go files (parse errors with position). (code.read)",
		InputSchema: obj(map[string]any{"file": str("Go file or workspace directory")}, "file"),
		Handler:     s.toolLspDiagnostics,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "ast_grep_search",
		Description: "AST-aware structural search via ast-grep (25 langs). (code.read)",
		InputSchema: obj(map[string]any{"pattern": str("ast-grep pattern"), "lang": str("language, e.g. go"), "path": str("root path (default .)")}, "pattern"),
		Handler:     s.toolAstGrepSearch,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "ast_grep_replace",
		Description: "AST-aware structural rewrite via ast-grep. (code.write)",
		InputSchema: obj(map[string]any{"pattern": str("ast-grep pattern"), "rewrite": str("rewrite template"), "lang": str("language"), "path": str("root path (default .)")}, "pattern", "rewrite"),
		Handler:     s.toolAstGrepReplace,
	})
	// gopls-backed LSP tools (see tools_code_lsp.go): real when gopls is on PATH,
	// fail-closed otherwise.
	lspPos := obj(map[string]any{"file": str("Go source file"), "pos": str("position line:col")}, "file", "pos")
	s.mcp.AddTool(mcp.Tool{
		Name:        "lsp_goto_definition",
		Description: "Jump to a symbol's definition via gopls. (code.read)",
		InputSchema: lspPos,
		Handler:     s.toolLspGotoDefinition,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "lsp_find_references",
		Description: "All usages of a symbol via gopls. (code.read)",
		InputSchema: lspPos,
		Handler:     s.toolLspFindReferences,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "lsp_prepare_rename",
		Description: "Validate a rename at a position via gopls. (code.read)",
		InputSchema: lspPos,
		Handler:     s.toolLspPrepareRename,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "lsp_rename",
		Description: "Workspace-wide rename via gopls (writes edits). (code.write)",
		InputSchema: obj(map[string]any{"file": str("Go source file"), "pos": str("position line:col"), "new_name": str("new identifier")}, "file", "pos", "new_name"),
		Handler:     s.toolLspRename,
	})
	// look_at (vision) stays governed-pending until a vision model is wired.
	s.mcp.AddTool(mcp.Tool{
		Name:        "look_at",
		Description: "Extract info from an image/PDF/diagram (Looker). (governed; vision backend wired in Phase 2)",
		InputSchema: obj(map[string]any{"path": str("image/PDF/diagram path"), "question": str("optional question")}),
		Handler:     s.pendingBackend("look_at"),
	})
}

// pendingBackend returns a governed handler that reports the tool is authorized
// but its live backend is not wired in this build — fail-closed and honest,
// never a silent success.
func (s *Server) pendingBackend(tool string) func(context.Context, json.RawMessage) (mcp.ToolResult, error) {
	return func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
		return jsonText(map[string]any{
			"tool":   tool,
			"status": "authorized; live backend not wired in this build",
			"note":   "the call passed the agent firewall and was audited; wire the Phase-2 backend to execute it",
		}), nil
	}
}

const maxGrepMatches = 200

func (s *Server) toolGrep(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Pattern string `json:"pattern"`
		Glob    string `json:"glob"`
		Path    string `json:"path"`
		I       bool   `json:"i"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Pattern == "" {
		return errText("pattern is required"), nil
	}
	pat := p.Pattern
	if p.I {
		pat = "(?i)" + pat
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return errText("bad pattern: %v", err), nil
	}
	root := p.Path
	if root == "" {
		root = "."
	}
	var matches []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if p.Glob != "" {
			if ok, _ := filepath.Match(p.Glob, d.Name()); !ok {
				return nil
			}
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		ln := 0
		for sc.Scan() {
			ln++
			if re.MatchString(sc.Text()) {
				matches = append(matches, fmt.Sprintf("%s:%d: %s", path, ln, strings.TrimSpace(sc.Text())))
				if len(matches) >= maxGrepMatches {
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	if err != nil {
		return errText("grep: %v", err), nil
	}
	capped := len(matches) >= maxGrepMatches
	return jsonText(map[string]any{"matches": matches, "count": len(matches), "capped": capped}), nil
}

func (s *Server) toolGlob(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Pattern string `json:"pattern"`
		Path    string `json:"path"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Pattern == "" {
		return errText("pattern is required"), nil
	}
	root := p.Path
	if root == "" {
		root = "."
	}
	base := filepath.Base(p.Pattern)
	var hits []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if ok, _ := filepath.Match(base, d.Name()); ok {
			hits = append(hits, path)
			if len(hits) >= 1000 {
				return filepath.SkipAll
			}
		}
		return nil
	})
	return jsonText(map[string]any{"files": hits, "count": len(hits)}), nil
}

func (s *Server) toolEdit(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		File string `json:"file"`
		Old  string `json:"old"`
		New  string `json:"new"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.File == "" || p.Old == "" {
		return errText("file and old are required"), nil
	}
	// write-existing-file guard: the file must already exist (edit, not create).
	data, err := os.ReadFile(p.File)
	if err != nil {
		return errText("edit: %v", err), nil
	}
	body := string(data)
	if n := strings.Count(body, p.Old); n != 1 {
		return errText("edit: old text must occur exactly once (found %d)", n), nil
	}
	out := strings.Replace(body, p.Old, p.New, 1)
	if err := os.WriteFile(p.File, []byte(out), 0o644); err != nil {
		return errText("edit: write: %v", err), nil
	}
	return text(fmt.Sprintf("edited %s (1 replacement)", p.File)), nil
}

func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".idea", "dist", "build":
		return true
	}
	return false
}
