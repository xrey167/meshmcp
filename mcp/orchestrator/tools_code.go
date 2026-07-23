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
	// LSP / AST / vision tools: registered and governed; their live backends
	// (a language server, an ast-grep binary, a vision model) are Phase-2 wiring.
	for _, t := range []struct{ name, desc, label string }{
		{"lsp_diagnostics", "Errors/warnings for a file or workspace.", "code.read"},
		{"lsp_prepare_rename", "Validate a rename at a position.", "code.read"},
		{"lsp_rename", "Workspace-wide rename.", "code.write"},
		{"lsp_goto_definition", "Jump to a symbol's definition.", "code.read"},
		{"lsp_find_references", "All usages of a symbol.", "code.read"},
		{"lsp_symbols", "File outline / workspace symbol search.", "code.read"},
		{"ast_grep_search", "AST-aware structural search (25 langs).", "code.read"},
		{"ast_grep_replace", "AST-aware structural rewrite.", "code.write"},
		{"look_at", "Extract info from an image/PDF/diagram (Looker).", "media.read"},
	} {
		name, desc := t.name, t.desc
		s.mcp.AddTool(mcp.Tool{
			Name:        name,
			Description: desc + " (governed; live backend wired in Phase 2)",
			InputSchema: obj(map[string]any{
				"file":    str("target file"),
				"pattern": str("pattern (for search/replace tools)"),
				"pos":     str("position line:col (for lsp tools)"),
			}),
			Handler: s.pendingBackend(name),
		})
	}
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
