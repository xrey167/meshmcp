package resources

import (
	"context"
	"time"

	"meshmcp/mcp"
)

func registerTime(s *mcp.Server) {
	s.AddResource(mcp.Resource{
		URI:         "time://now",
		Name:        "current-time",
		Description: "The server's current time in RFC3339.",
		MimeType:    "text/plain",
		Read: func(_ context.Context) (mcp.ResourceContents, error) {
			return mcp.ResourceContents{Text: time.Now().Format(time.RFC3339)}, nil
		},
	})
}
