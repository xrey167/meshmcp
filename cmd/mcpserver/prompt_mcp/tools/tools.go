// Package tools holds one file per tool, each exposing a registerX(s)
// function, aggregated by Register — the Go equivalent of the tools/index.ts
// + server.registerTool(...) pattern.
package tools

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/xrey167/meshmcp/mcp"
)

// Config carries per-server settings the tool handlers need.
type Config struct {
	Root            string   // filesystem sandbox root
	AllowedCommands []string // allow-list for the run_command tool
}

// Register registers every tool on the server.
func Register(s *mcp.Server, cfg Config) {
	registerEcho(s)
	registerAdd(s)
	registerFS(s, cfg.Root)
	registerSlowCount(s)
	registerRunCommand(s, cfg.AllowedCommands)
	registerDemo(s)
}

// --- shared helpers ---

func textResult(s string) mcp.ToolResult {
	return mcp.ToolResult{Content: []mcp.Content{mcp.Text(s)}}
}

func errResult(format string, a ...any) mcp.ToolResult {
	return mcp.ToolResult{Content: []mcp.Content{mcp.Text(fmt.Sprintf(format, a...))}, IsError: true}
}

// sandbox resolves rel against root and rejects any path escaping it — both
// lexical traversal (../, absolute paths) AND symlink escape. A lexical-only
// check is not enough: a symlink that already exists inside root (a checked-out
// repo link, a `logs -> /var/log` convenience link) points outside it, and
// os.ReadFile/os.WriteFile follow it, so `link/passwd` where `link -> /etc`
// would read /etc/passwd while passing a lexical HasPrefix(root) test. After the
// lexical check, the real (symlink-resolved) path of the longest existing prefix
// is re-verified to stay within the real root; the prefix (not the whole path)
// is resolved so write_file to a not-yet-existing file is still checked via its
// parent directory.
func sandbox(root, rel string) (string, error) {
	clean := filepath.Clean(filepath.Join(root, rel))
	relToRoot, err := filepath.Rel(root, clean)
	if err != nil || relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the sandbox root", rel)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("sandbox root %q is not resolvable: %w", root, err)
	}
	realPath, err := resolveExistingPrefix(clean)
	if err != nil {
		return "", err
	}
	rel2, err := filepath.Rel(realRoot, realPath)
	if err != nil || rel2 == ".." || strings.HasPrefix(rel2, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the sandbox root via a symlink", rel)
	}
	return clean, nil
}

// resolveExistingPrefix returns p with symlinks resolved on its longest existing
// ancestor, re-appending any trailing components that do not exist yet (so a
// write to a new file resolves via its parent directory). It lets sandbox check
// containment of the REAL path even when the final component is absent.
func resolveExistingPrefix(p string) (string, error) {
	cur := p
	var tail []string
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			full := resolved
			for i := len(tail) - 1; i >= 0; i-- {
				full = filepath.Join(full, tail[i])
			}
			return full, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p, nil // no existing ancestor resolved (degenerate); fall back
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

func objSchema(props map[string]any, required ...string) map[string]any {
	schema := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
func numProp(desc string) map[string]any {
	return map[string]any{"type": "number", "description": desc}
}

func formatNum(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}
