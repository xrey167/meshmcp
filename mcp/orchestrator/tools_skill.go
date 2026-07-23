package orchestrator

import (
	"context"
	"encoding/json"
	"os"

	"github.com/xrey167/meshmcp/harness/skills"
	"github.com/xrey167/meshmcp/mcp"
)

// loadSkills builds the skill registry from the built-ins plus the project
// (.harness/skills) and user (~/.harness/skills) scopes.
func loadSkills() *skills.Registry {
	reg, err := skills.LoadScopes(".harness/skills", userSkillsDir())
	if err != nil || reg == nil {
		reg = skills.NewRegistry()
		for _, s := range skills.BuiltinSkills() {
			reg.Add(s)
		}
	}
	return reg
}

func userSkillsDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h + "/.harness/skills"
	}
	return ""
}

func (s *Server) registerSkill() {
	s.mcp.AddTool(mcp.Tool{
		Name:        "skill",
		Description: "Load & execute a skill or slash-command by name (git-master, playwright, review-work, …). Returns the skill's instructions and declared embedded MCP. (skill.run)",
		InputSchema: obj(map[string]any{"name": str("skill name (or empty to list)"), "args": anyObj("skill args"), "context": str("optional context to auto-match a skill")}),
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

func (s *Server) toolSkill(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Name    string `json:"name"`
		Context string `json:"context"`
	}
	_ = json.Unmarshal(args, &p)

	// No name: either auto-match by context, or list the registry.
	if p.Name == "" {
		if p.Context != "" {
			matched := s.skills.Match(p.Context)
			names := make([]string, len(matched))
			for i, m := range matched {
				names[i] = m.Name
			}
			return jsonText(map[string]any{"matched": names}), nil
		}
		list := s.skills.List()
		out := make([]map[string]any, len(list))
		for i, sk := range list {
			out[i] = map[string]any{"name": sk.Name, "scope": sk.Scope, "description": sk.Description, "embedded_mcp": sk.EmbeddedMCP}
		}
		return jsonText(map[string]any{"skills": out}), nil
	}

	sk, ok := s.skills.Get(p.Name)
	if !ok {
		return errText("no such skill %q", p.Name), nil
	}
	return jsonText(map[string]any{
		"name":         sk.Name,
		"scope":        sk.Scope,
		"description":  sk.Description,
		"triggers":     sk.Triggers,
		"embedded_mcp": sk.EmbeddedMCP,
		"provenance":   sk.Provenance,
		"instructions": sk.Body,
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
