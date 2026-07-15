package resources

import (
	"context"
	"fmt"

	"meshmcp/mcp"
)

func registerInfo(s *mcp.Server, root string) {
	s.AddResource(mcp.Resource{
		URI:         "info://server",
		Name:        "server-info",
		Description: "Human-readable description of this server and its sandbox root.",
		MimeType:    "text/plain",
		Read: func(_ context.Context) (mcp.ResourceContents, error) {
			return mcp.ResourceContents{Text: fmt.Sprintf(
				"meshmcp-demo MCP server\nsandbox root: %s\ntools: echo, add, read_file, write_file, list_dir, slow_count, run_command\n", root)}, nil
		},
	})
}
