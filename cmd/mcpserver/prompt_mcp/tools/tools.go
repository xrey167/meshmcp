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

// sandbox resolves rel against root and rejects any path escaping it.
func sandbox(root, rel string) (string, error) {
	clean := filepath.Clean(filepath.Join(root, rel))
	relToRoot, err := filepath.Rel(root, clean)
	if err != nil || relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the sandbox root", rel)
	}
	return clean, nil
}

func objSchema(props map[string]any, required ...string) map[string]any {
	schema := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func strProp(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func numProp(desc string) map[string]any { return map[string]any{"type": "number", "description": desc} }

func formatNum(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%g", f)
}
