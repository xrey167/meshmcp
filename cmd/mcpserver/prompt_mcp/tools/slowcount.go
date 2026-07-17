package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"meshmcp/mcp"
)

// registerSlowCount registers a long-running tool best invoked as a task
// ("task": true); it streams progress and honors cancellation.
func registerSlowCount(s *mcp.Server) {
	s.AddTool(mcp.Tool{
		Name:        "slow_count",
		Description: `Count to n slowly, emitting progress. Best run as a task ("task": true); honors cancellation.`,
		InputSchema: objSchema(map[string]any{"n": numProp("how high to count")}, "n"),
		Handler: func(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				N int `json:"n"`
			}
			_ = json.Unmarshal(args, &a)
			if a.N <= 0 {
				a.N = 5
			}
			sess := mcp.SessionFrom(ctx)
			for i := 1; i <= a.N; i++ {
				select {
				case <-ctx.Done():
					return mcp.ToolResult{}, ctx.Err()
				case <-time.After(200 * time.Millisecond):
				}
				if sess != nil {
					sess.Progress("slow_count", float64(i), float64(a.N), fmt.Sprintf("counted %d/%d", i, a.N))
				}
			}
			return textResult(fmt.Sprintf("done: counted to %d", a.N)), nil
		},
	})
}
