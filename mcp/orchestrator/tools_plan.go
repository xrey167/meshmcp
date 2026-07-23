package orchestrator

import (
	"context"
	"encoding/json"

	"github.com/xrey167/meshmcp/harness"
	"github.com/xrey167/meshmcp/mcp"
)

func (s *Server) registerPlan() {
	s.mcp.AddTool(mcp.Tool{
		Name:        "plan",
		Description: "Produce/refine a plan (Prometheus/ralplan/team-plan) plus a Metis+Momus review verdict. Plan artifacts are governed via air.",
		InputSchema: obj(map[string]any{
			"goal":  str("what to plan"),
			"style": str("prometheus|ralplan|team (default team)"),
		}, "goal"),
		Handler: s.toolPlan,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "plan_review",
		Description: "Metis (gap/ambiguity) + Momus/critic (validation) review of a goal's plan. Emits a pass/revise verdict.",
		InputSchema: obj(map[string]any{"goal": str("goal whose plan to review")}, "goal"),
		Handler:     s.toolPlanReview,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "interview",
		Description: "Socratic requirement clarification (deep-interview). Produces a requirements artifact.",
		InputSchema: obj(map[string]any{"goal": str("the goal"), "rounds": num("question rounds (default 3)")}, "goal"),
		Handler:     s.toolInterview,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "start_work",
		Description: "Begin Atlas-style execution for a goal through the full pipeline (co-sign per risk). Returns a run id.",
		InputSchema: obj(map[string]any{"goal": str("the goal"), "mode": str("optional mode")}, "goal"),
		Handler:     s.toolStartWork,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "review_work",
		Description: "Post-implementation N-reviewer fan-out (default 5). Returns findings + summary.",
		InputSchema: obj(map[string]any{
			"scope":     str("diff description or path scope to review"),
			"reviewers": num("reviewer count (default 5)"),
		}, "scope"),
		Handler: s.toolReviewWork,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "ultragoal_check",
		Description: "Durable verify: confirm the stated goal is actually met, with evidence.",
		InputSchema: obj(map[string]any{
			"goal":     str("the goal to confirm"),
			"evidence": strArr("evidence that the goal was met"),
		}, "goal"),
		Handler: s.toolUltragoal,
	})
}

func (s *Server) toolPlan(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Goal  string `json:"goal"`
		Style string `json:"style"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Goal == "" {
		return errText("goal is required"), nil
	}
	plan, _, err := s.eng.MakePlan(ctx, p.Goal, p.Style)
	if err != nil {
		return errText("plan: %v", err), nil
	}
	return jsonText(plan), nil
}

func (s *Server) toolPlanReview(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Goal string `json:"goal"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Goal == "" {
		return errText("goal is required"), nil
	}
	_, verdict, err := s.eng.MakePlan(ctx, p.Goal, "team")
	if err != nil {
		return errText("plan_review: %v", err), nil
	}
	return jsonText(verdict), nil
}

func (s *Server) toolInterview(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Goal   string `json:"goal"`
		Rounds int    `json:"rounds"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Goal == "" {
		return errText("goal is required"), nil
	}
	req, err := s.eng.DoInterview(ctx, p.Goal, p.Rounds)
	if err != nil {
		return errText("interview: %v", err), nil
	}
	return jsonText(req), nil
}

func (s *Server) toolStartWork(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Goal string `json:"goal"`
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Goal == "" {
		return errText("goal is required"), nil
	}
	id, err := s.eng.Start(ctx, harness.RunRequest{Goal: p.Goal, Mode: harness.Mode(p.Mode), Actor: s.caller})
	if err != nil {
		return errText("start_work: %v", err), nil
	}
	go func() { _, _ = s.eng.Advance(context.Background(), id) }()
	return jsonText(map[string]any{"run_id": string(id)}), nil
}

func (s *Server) toolReviewWork(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Scope     string `json:"scope"`
		Reviewers int    `json:"reviewers"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Scope == "" {
		return errText("scope is required"), nil
	}
	findings, summary, err := s.eng.DoReviewWork(ctx, p.Scope, p.Reviewers)
	if err != nil {
		return errText("review_work: %v", err), nil
	}
	return jsonText(map[string]any{"findings": findings, "summary": summary}), nil
}

func (s *Server) toolUltragoal(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Goal     string   `json:"goal"`
		Evidence []string `json:"evidence"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Goal == "" {
		return errText("goal is required"), nil
	}
	met, gaps, err := s.eng.DoUltragoal(ctx, p.Goal, p.Evidence)
	if err != nil {
		return errText("ultragoal_check: %v", err), nil
	}
	return jsonText(map[string]any{"met": met, "residual_gaps": gaps}), nil
}
