package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/mcp"
)

// registerRunCommand registers a guarded shell tool. Only command names in
// the allow-list may run, arguments are passed directly to exec (no shell,
// so no injection), and each run has a timeout. With an empty allow-list the
// tool is registered but refuses everything — a policy rule can also gate it.
func registerRunCommand(s *mcp.Server, allowed []string) {
	allow := map[string]bool{}
	for _, c := range allowed {
		allow[c] = true
	}
	s.AddTool(mcp.Tool{
		Name: "run_command",
		Description: fmt.Sprintf(
			"Run an allow-listed command (no shell). Allowed: %s. Returns combined stdout+stderr.",
			strings.Join(allowed, ", ")),
		InputSchema: objSchema(map[string]any{
			"command": strProp("command name (must be allow-listed)"),
			"args":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "arguments"},
		}, "command"),
		Handler: func(ctx context.Context, raw json.RawMessage) (mcp.ToolResult, error) {
			var a struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return mcp.ToolResult{}, fmt.Errorf("invalid arguments: %w", err)
			}
			if !allow[a.Command] {
				return errResult("command %q is not allow-listed", a.Command), nil
			}
			runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			out, err := exec.CommandContext(runCtx, a.Command, a.Args...).CombinedOutput()
			text := string(out)
			if err != nil {
				return errResult("%s\n(exit: %v)", text, err), nil
			}
			return textResult(text), nil
		},
	})
}
