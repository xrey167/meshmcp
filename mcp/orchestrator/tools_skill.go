package orchestrator

import (
	"context"
	"encoding/json"

	"github.com/xrey167/meshmcp/mcp"
)

func (s *Server) registerSkill() {
	s.mcp.AddTool(mcp.Tool{
		Name:        "skill",
		Description: "Load & execute a built-in skill or slash-command by name (git-master, playwright, review-work, …). (skill.run)",
		InputSchema: obj(map[string]any{"name": str("skill name"), "args": anyObj("skill args"), "context": str("optional context")}, "name"),
		Handler:     s.toolSkill,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "skill_mcp",
		Description: "Invoke an MCP operation embedded in a skill (broker-credentialed, mesh-only). (skill.mcp)",
		InputSchema: obj(map[string]any{"skill": str("skill name"), "tool": str("embedded tool"), "args": anyObj("tool args")}, "skill", "tool"),
		Handler:     s.pendingBackend("skill_mcp"),
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "market",
		Description: "Browse/install governed skills & plugins (bridges meshmcp market; installs are co-sign-gated + audited). (market)",
		InputSchema: obj(map[string]any{"op": str("search|install|info"), "query": str("search query"), "ref": str("skill/plugin ref")}, "op"),
		Handler:     s.toolMarket,
	})
}

// builtinSkills is the built-in skill registry (from omo), advertised by the
// skill tool. Their bodies load from SKILL.md in Phase 2.
var builtinSkills = []string{
	"git-master", "playwright", "agent-browser", "dev-browser",
	"frontend-ui-ux", "review-work", "ai-slop-remover", "skillify",
}

func (s *Server) toolSkill(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Name == "" {
		return errText("name is required"), nil
	}
	known := false
	for _, k := range builtinSkills {
		if k == p.Name {
			known = true
			break
		}
	}
	return jsonText(map[string]any{
		"skill":  p.Name,
		"known":  known,
		"status": "authorized; SKILL.md loader wired in Phase 2",
	}), nil
}

func (s *Server) toolMarket(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Op    string `json:"op"`
		Query string `json:"query"`
		Ref   string `json:"ref"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Op == "" {
		return errText("op is required"), nil
	}
	return jsonText(map[string]any{
		"op":     p.Op,
		"status": "authorized; governed marketplace bridge (meshmcp market) wired in Phase 2",
		"note":   "installs are policy-gated with signed provenance",
	}), nil
}
