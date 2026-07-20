package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xrey167/meshmcp/mcp"
)

func registerAdd(s *mcp.Server) {
	s.AddTool(mcp.Tool{
		Name:        "add",
		Description: "Add two numbers and return the sum.",
		InputSchema: objSchema(map[string]any{
			"a": numProp("first addend"),
			"b": numProp("second addend"),
		}, "a", "b"),
		Handler: func(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				A float64 `json:"a"`
				B float64 `json:"b"`
			}
			if err := json.Unmarshal(args, &a); err != nil {
				return mcp.ToolResult{}, fmt.Errorf("invalid arguments: %w", err)
			}
			return textResult(formatNum(a.A + a.B)), nil
		},
	})
}
