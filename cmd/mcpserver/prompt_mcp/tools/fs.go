package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/xrey167/meshmcp/mcp"
)

// registerFS registers the filesystem tools, all sandboxed to root.
func registerFS(s *mcp.Server, root string) {
	s.AddTool(mcp.Tool{
		Name:        "read_file",
		Description: "Read a UTF-8 text file within the server's sandbox root.",
		InputSchema: objSchema(map[string]any{"path": strProp("path relative to root")}, "path"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal(args, &a); err != nil {
				return mcp.ToolResult{}, fmt.Errorf("invalid arguments: %w", err)
			}
			p, err := sandbox(root, a.Path)
			if err != nil {
				return errResult("%v", err), nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return errResult("%v", err), nil
			}
			return textResult(string(b)), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "write_file",
		Description: "Write a UTF-8 text file within the server's sandbox root.",
		InputSchema: objSchema(map[string]any{
			"path":    strProp("path relative to root"),
			"content": strProp("file content"),
		}, "path", "content"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Path    string `json:"path"`
				Content string `json:"content"`
			}
			if err := json.Unmarshal(args, &a); err != nil {
				return mcp.ToolResult{}, fmt.Errorf("invalid arguments: %w", err)
			}
			p, err := sandbox(root, a.Path)
			if err != nil {
				return errResult("%v", err), nil
			}
			if err := os.WriteFile(p, []byte(a.Content), 0o644); err != nil {
				return errResult("%v", err), nil
			}
			return textResult(fmt.Sprintf("wrote %d bytes to %s", len(a.Content), a.Path)), nil
		},
	})

	s.AddTool(mcp.Tool{
		Name:        "list_dir",
		Description: "List entries of a directory within the server's sandbox root.",
		InputSchema: objSchema(map[string]any{"path": strProp("directory relative to root (default '.')")}),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Path string `json:"path"`
			}
			_ = json.Unmarshal(args, &a)
			if a.Path == "" {
				a.Path = "."
			}
			p, err := sandbox(root, a.Path)
			if err != nil {
				return errResult("%v", err), nil
			}
			entries, err := os.ReadDir(p)
			if err != nil {
				return errResult("%v", err), nil
			}
			var sb strings.Builder
			for _, e := range entries {
				kind := "file"
				if e.IsDir() {
					kind = "dir"
				}
				fmt.Fprintf(&sb, "%s\t%s\n", kind, e.Name())
			}
			return textResult(sb.String()), nil
		},
	})
}
