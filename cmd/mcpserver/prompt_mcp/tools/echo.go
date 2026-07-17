package tools

import (
	"context"
	"encoding/json"

	"meshmcp/mcp"
)

func registerEcho(s *mcp.Server) {
	s.AddTool(mcp.Tool{
		Name:        "echo",
		Description: "Echo the provided text back.",
		InputSchema: objSchema(map[string]any{"text": strProp("text to echo")}, "text"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(args, &a)
			return textResult(a.Text), nil
		},
	})
}
