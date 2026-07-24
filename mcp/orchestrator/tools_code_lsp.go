package orchestrator

import (
	"context"
	"encoding/json"
	"os/exec"

	"github.com/xrey167/meshmcp/mcp"
)

// gopls-backed LSP tools. gopls ships a command-line mode
// (`gopls definition|references|rename|prepare_rename <file>:<line>:<col>`), so
// these tools drive it as a subprocess. When gopls is not installed they fail
// closed with an actionable note — never a silent success — matching the
// ast-grep pattern. Together with the go/parser-backed lsp_symbols/diagnostics,
// this makes every lsp_* tool real; only look_at (vision) stays pending.

func goplsPath() (string, bool) {
	if p, err := exec.LookPath("gopls"); err == nil {
		return p, true
	}
	return "", false
}

func goplsUnavailable(tool string) mcp.ToolResult {
	return jsonText(map[string]any{
		"tool":   tool,
		"status": "authorized; the gopls language server is not installed on this host",
		"note":   "install gopls (go install golang.org/x/tools/gopls@latest) to enable this tool; the call passed the firewall and was audited",
	})
}

// lspPos parses the shared {file, pos} arguments into gopls's file:line:col
// spec. pos is "line:col".
type lspArgs struct {
	File    string `json:"file"`
	Pos     string `json:"pos"`
	NewName string `json:"new_name"`
}

func (a lspArgs) spec() string { return a.File + ":" + a.Pos }

func (s *Server) toolLspGotoDefinition(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	return s.goplsPositional(ctx, args, "lsp_goto_definition", "definition")
}

func (s *Server) toolLspFindReferences(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	return s.goplsPositional(ctx, args, "lsp_find_references", "references")
}

func (s *Server) toolLspPrepareRename(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	return s.goplsPositional(ctx, args, "lsp_prepare_rename", "prepare_rename")
}

// goplsPositional runs a gopls subcommand that takes a single file:line:col.
func (s *Server) goplsPositional(ctx context.Context, args json.RawMessage, tool, sub string) (mcp.ToolResult, error) {
	var p lspArgs
	if err := json.Unmarshal(args, &p); err != nil || p.File == "" || p.Pos == "" {
		return errText("file and pos (line:col) are required"), nil
	}
	bin, ok := goplsPath()
	if !ok {
		return goplsUnavailable(tool), nil
	}
	out, err := runCmd(ctx, bin, []string{sub, p.spec()})
	if err != nil {
		return errText("%s: %v", tool, err), nil
	}
	return text(out), nil
}

func (s *Server) toolLspRename(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p lspArgs
	if err := json.Unmarshal(args, &p); err != nil || p.File == "" || p.Pos == "" || p.NewName == "" {
		return errText("file, pos (line:col) and new_name are required"), nil
	}
	bin, ok := goplsPath()
	if !ok {
		return goplsUnavailable("lsp_rename"), nil
	}
	// -w writes the edits to disk (this tool is code.write).
	out, err := runCmd(ctx, bin, []string{"rename", "-w", p.spec(), p.NewName})
	if err != nil {
		return errText("lsp_rename: %v", err), nil
	}
	return text(out + "\nrenamed to " + p.NewName), nil
}
