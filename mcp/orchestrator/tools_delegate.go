package orchestrator

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/xrey167/meshmcp/harness"
	"github.com/xrey167/meshmcp/mcp"
)

// bgJobs tracks background call_agent jobs (runs are tracked by the engine itself
// and queried by run id). Safe for concurrent use.
type bgJobs struct {
	mu   sync.Mutex
	jobs map[string]*bgJob
}

type bgJob struct {
	done   bool
	result harness.JobResult
	err    string
}

func newBgJobs() *bgJobs { return &bgJobs{jobs: map[string]*bgJob{}} }

func (b *bgJobs) start(id string) *bgJob {
	b.mu.Lock()
	defer b.mu.Unlock()
	j := &bgJob{}
	b.jobs[id] = j
	return j
}
func (b *bgJobs) get(id string) (*bgJob, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	j, ok := b.jobs[id]
	return j, ok
}
func (b *bgJobs) finish(id string, res harness.JobResult, err string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if j := b.jobs[id]; j != nil {
		j.done, j.result, j.err = true, res, err
	}
}

func (s *Server) registerDelegate() {
	if s.bg == nil {
		s.bg = newBgJobs()
	}
	s.mcp.AddTool(mcp.Tool{
		Name:        "task",
		Description: "Category-based task delegation with automatic model selection. Opens a governed run through the merged pipeline and returns its id; poll status with background_output.",
		InputSchema: obj(map[string]any{
			"description": str("what to do"),
			"category":    str("optional category: deep|ultrabrain|quick|writing|visual-engineering|artistry|unspecified-low|unspecified-high"),
			"mode":        str("optional mode: quick|team|autopilot|ralph|ultrawork|synthesize|interview-only|plan-only"),
			"files":       strArr("optional context files"),
		}, "description"),
		Handler: s.toolTask,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "call_agent",
		Description: "Spawn a named role agent (explorer/librarian/architect/executor/…) directly, optionally in the background. Each worker runs under its own role policy.",
		InputSchema: obj(map[string]any{
			"role":       str("role name (see list): orchestrator|deep-worker|executor|planner|pre-analyst|plan-reviewer|architect|librarian|explorer|looker|junior"),
			"prompt":     str("the task for the agent"),
			"background": boolp("run in the background and return a job_id"),
		}, "role", "prompt"),
		Handler: s.toolCallAgent,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "background_output",
		Description: "Retrieve the status/output of a background job or run by id.",
		InputSchema: obj(map[string]any{"job_id": str("run id or job id")}, "job_id"),
		Handler:     s.toolBackgroundOutput,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "background_cancel",
		Description: "Cancel a running background run (stop-continuation; the stop is audited and cannot silently resume).",
		InputSchema: obj(map[string]any{"job_id": str("run id"), "reason": str("optional reason")}, "job_id"),
		Handler:     s.toolBackgroundCancel,
	})
	s.mcp.AddTool(mcp.Tool{
		Name:        "synthesize",
		Description: "Run the same prompt across multiple provider classes and merge the answers (tri-model synthesis / ccg). Remote providers cross federation.",
		InputSchema: obj(map[string]any{
			"prompt":  str("the task"),
			"classes": strArr("optional model classes; default gpt-medium,opus-class,gemini-class"),
		}, "prompt"),
		Handler: s.toolSynthesize,
	})
}

func (s *Server) toolTask(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Description string   `json:"description"`
		Category    string   `json:"category"`
		Mode        string   `json:"mode"`
		Files       []string `json:"files"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Description == "" {
		return errText("description is required"), nil
	}
	req := harness.RunRequest{
		Goal:     p.Description,
		Mode:     harness.Mode(p.Mode),
		Category: harness.Category(p.Category),
		Actor:    s.caller,
		Scope:    harness.RepoScope{Paths: p.Files},
	}
	id, err := s.eng.Start(ctx, req)
	if err != nil {
		return errText("task: %v", err), nil
	}
	// Advance in the background so the tool returns promptly with a handle.
	go func() { _, _ = s.eng.Advance(context.Background(), id) }()
	st, _ := s.eng.State(id)
	return jsonText(map[string]any{
		"task_id":       string(id),
		"assigned_role": string(harness.RoleExecutor),
		"category":      string(st.Category),
		"mode":          string(st.Mode),
		"status":        string(st.Status),
	}), nil
}

func (s *Server) toolCallAgent(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Role       string `json:"role"`
		Prompt     string `json:"prompt"`
		Background bool   `json:"background"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Role == "" || p.Prompt == "" {
		return errText("role and prompt are required"), nil
	}
	role := harness.Role(p.Role)
	if p.Background {
		jobID := "job-" + shortID()
		s.bg.start(jobID)
		go func() {
			res, err := s.eng.CallAgent(context.Background(), s.caller, role, p.Prompt)
			es := ""
			if err != nil {
				es = err.Error()
			}
			s.bg.finish(jobID, res, es)
		}()
		return jsonText(map[string]any{"job_id": jobID, "status": "running"}), nil
	}
	res, err := s.eng.CallAgent(ctx, s.caller, role, p.Prompt)
	if err != nil {
		return errText("call_agent: %v", err), nil
	}
	return jsonText(map[string]any{
		"result": res.Output,
		"usage":  map[string]int{"in": res.TokensIn, "out": res.TokensOut},
	}), nil
}

func (s *Server) toolBackgroundOutput(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.JobID == "" {
		return errText("job_id is required"), nil
	}
	// A background call_agent job?
	if j, ok := s.bg.get(p.JobID); ok {
		status := "running"
		if j.done {
			status = "done"
			if j.err != "" {
				status = "error"
			}
		}
		return jsonText(map[string]any{"status": status, "result": j.result.Output, "err": j.err}), nil
	}
	// Otherwise treat it as a run id.
	st, err := s.eng.State(harness.RunID(p.JobID))
	if err != nil {
		return errText("background_output: %v", err), nil
	}
	return jsonText(map[string]any{
		"status": string(st.Status), "stage": string(st.Stage),
		"goal_met": st.GoalMet, "rounds": st.Rounds, "findings": len(st.Findings),
	}), nil
}

func (s *Server) toolBackgroundCancel(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		JobID  string `json:"job_id"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.JobID == "" {
		return errText("job_id is required"), nil
	}
	if err := s.eng.Cancel(ctx, harness.RunID(p.JobID), p.Reason); err != nil {
		return errText("background_cancel: %v", err), nil
	}
	return jsonText(map[string]any{"cancelled": true}), nil
}

func (s *Server) toolSynthesize(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Prompt  string   `json:"prompt"`
		Classes []string `json:"classes"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Prompt == "" {
		return errText("prompt is required"), nil
	}
	merged, per, err := s.eng.DoSynthesize(ctx, p.Prompt, p.Classes)
	if err != nil {
		return errText("synthesize: %v", err), nil
	}
	return jsonText(map[string]any{"merged": merged, "per_provider": per}), nil
}
