package orchestrator

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/xrey167/meshmcp/mcp"
)

// shortID returns a short random hex id for background jobs.
func shortID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Schema/result helpers mirror cmd/meshmcp's mcpapp helpers (which are package
// main, so not importable). They keep tool registration terse and consistent.

func obj(props map[string]any, req ...string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	m := map[string]any{"type": "object", "properties": props}
	if len(req) > 0 {
		m["required"] = req
	}
	return m
}

func str(d string) map[string]any    { return map[string]any{"type": "string", "description": d} }
func num(d string) map[string]any    { return map[string]any{"type": "number", "description": d} }
func boolp(d string) map[string]any  { return map[string]any{"type": "boolean", "description": d} }
func anyObj(d string) map[string]any { return map[string]any{"type": "object", "description": d} }
func strArr(d string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": d}
}

func text(s string) mcp.ToolResult { return mcp.ToolResult{Content: []mcp.Content{mcp.Text(s)}} }

func jsonText(v any) mcp.ToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return text(string(b))
}

func errText(format string, a ...any) mcp.ToolResult {
	return mcp.ToolResult{Content: []mcp.Content{mcp.Text(fmt.Sprintf(format, a...))}, IsError: true}
}
