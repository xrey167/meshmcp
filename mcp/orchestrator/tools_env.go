package orchestrator

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xrey167/meshmcp/harness/sandbox"
	"github.com/xrey167/meshmcp/mcp"
)

func (s *Server) registerEnv() {
	s.mcp.AddTool(mcp.Tool{
		Name:        "interactive_bash",
		Description: "Run a command in the worker's sandbox (never the host for non-main identities). Governed by exec.shell — denied to read-only roles. (exec.shell)",
		InputSchema: obj(map[string]any{
			"cmd":       str("command line to run"),
			"timeout_s": num("timeout seconds (default 30)"),
		}, "cmd"),
		Handler: s.toolInteractiveBash,
	})
	// browser/canvas/nodes/cron: first-class openclaw tools; live drivers are
	// Phase-2/4 wiring. Registered and governed.
	for _, t := range []struct{ name, desc string }{
		{"browser", "Navigate/snapshot/script a browser."},
		{"canvas", "Drive an agent-visible Live Canvas (A2UI)."},
		{"nodes", "Manage compute/tool nodes for a session."},
		{"cron", "Schedule recurring governed agent tasks (each firing is a fresh audited run)."},
	} {
		name, desc := t.name, t.desc
		s.mcp.AddTool(mcp.Tool{
			Name:        name,
			Description: desc + " (governed; live driver wired in Phase 2/4)",
			InputSchema: obj(map[string]any{
				"action":   str("operation"),
				"op":       str("operation"),
				"schedule": str("cron schedule (cron tool)"),
				"prompt":   str("prompt (cron tool)"),
			}),
			Handler: s.pendingBackend(name),
		})
	}
}

func (s *Server) toolInteractiveBash(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Cmd      string `json:"cmd"`
		TimeoutS int    `json:"timeout_s"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Cmd == "" {
		return errText("cmd is required"), nil
	}
	to := time.Duration(p.TimeoutS) * time.Second
	if to <= 0 {
		to = 30 * time.Second
	}
	sb := sandbox.NewLocal(".")
	res, err := sb.Exec(ctx, sandbox.Command{Args: []string{"sh", "-c", p.Cmd}, Timeout: to})
	if err != nil {
		return errText("interactive_bash: %v", err), nil
	}
	return jsonText(map[string]any{"output": res.Stdout, "stderr": res.Stderr, "exit": res.ExitCode}), nil
}
