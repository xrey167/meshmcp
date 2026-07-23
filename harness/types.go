package harness

import "time"

// RunID identifies one orchestration run. It is the air/checkpoint storage key,
// so it must be a single safe path element (no separators) — newRunID enforces.
type RunID string

// RunStatus is a run's lifecycle state.
type RunStatus string

const (
	RunPending   RunStatus = "pending"
	RunRunning   RunStatus = "running"
	RunBlocked   RunStatus = "blocked" // parked on a co-sign approval
	RunDone      RunStatus = "done"
	RunFailed    RunStatus = "failed"
	RunCancelled RunStatus = "cancelled"
)

// RunRequest starts a run through the merged pipeline.
type RunRequest struct {
	Goal     string
	Mode     Mode
	Category Category  // optional; IntentGate fills if empty
	Scope    RepoScope // paths / worktree / repo
	Actor    Identity  // requesting mesh identity (the principal)
	Budget   Budget
}

// RepoScope bounds a run to a set of paths and an optional worktree/repo.
type RepoScope struct {
	Repo     string
	Paths    []string
	Worktree string
}

// RunState is the persisted, resumable state machine position of a run. It is
// the payload serialized into an air/checkpoint Checkpoint.State — the literal
// "run state lives in air" (§12).
type RunState struct {
	ID           RunID         `json:"id"`
	Goal         string        `json:"goal"`
	Mode         Mode          `json:"mode"`
	Category     Category      `json:"category"`
	Risk         string        `json:"risk,omitempty"`
	Scope        RepoScope     `json:"scope"`
	Actor        Identity      `json:"actor"`
	Budget       Budget        `json:"budget"`
	Status       RunStatus     `json:"status"`
	Stage        Stage         `json:"stage"`
	Labels       []string      `json:"labels,omitempty"` // accumulated data-flow labels
	Requirements *Requirements `json:"requirements,omitempty"`
	Plan         *Plan         `json:"plan,omitempty"`
	Findings     []Finding     `json:"findings,omitempty"`
	GoalMet      bool          `json:"goal_met"`
	Rounds       int           `json:"rounds,omitempty"`
	StopReason   StopCond      `json:"stop_reason,omitempty"`
	Workers      []Worker      `json:"workers,omitempty"` // retired workers (for the audit seal)
	Error        string        `json:"error,omitempty"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

// Requirements is the interview phase output (deep-interview).
type Requirements struct {
	ID          string   `json:"id"`
	QA          []QA     `json:"qa"`
	Assumptions []string `json:"assumptions"`
}

// QA is one interview question/answer pair.
type QA struct {
	Q string `json:"q"`
	A string `json:"a"`
}

// Plan is a plan artifact (Prometheus/ralplan/team-plan).
type Plan struct {
	ID            string       `json:"id"`
	RunID         RunID        `json:"run_id"`
	Style         string       `json:"style"` // prometheus | ralplan | team
	Steps         []PlanStep   `json:"steps"`
	OpenQuestions []string     `json:"open_questions,omitempty"`
	Verdict       *PlanVerdict `json:"verdict,omitempty"`
}

// PlanStep is one step of a plan.
type PlanStep struct {
	ID     string   `json:"id"`
	Intent string   `json:"intent"`
	Files  []string `json:"files,omitempty"`
	Risk   string   `json:"risk,omitempty"`
	Verify string   `json:"verify,omitempty"`
}

// PlanVerdict is the plan-review outcome (Metis gaps + Momus/critic validation).
type PlanVerdict struct {
	Verdict         string   `json:"verdict"` // "pass" | "revise"
	Gaps            []string `json:"gaps,omitempty"`
	Risks           []string `json:"risks,omitempty"`
	RequiredChanges []string `json:"required_changes,omitempty"`
}

// Task is a unit of delegated work (the task store, backed by air).
type Task struct {
	ID     string     `json:"id"`
	RunID  RunID      `json:"run_id"`
	Parent string     `json:"parent,omitempty"`
	Title  string     `json:"title"`
	Body   string     `json:"body,omitempty"`
	Status TaskStatus `json:"status"`
	Worker string     `json:"worker,omitempty"` // worker identity FQDN
}

// TaskStatus is a task's state.
type TaskStatus string

const (
	TaskOpen       TaskStatus = "open"
	TaskInProgress TaskStatus = "in_progress"
	TaskDone       TaskStatus = "done"
	TaskFailed     TaskStatus = "failed"
)

// Job is one scheduled worker execution.
type Job struct {
	ID         string    `json:"id"`
	RunID      RunID     `json:"run_id"`
	Role       Role      `json:"role"`
	ModelClass string    `json:"model_class"`
	Provider   string    `json:"provider,omitempty"`
	Sandbox    string    `json:"sandbox,omitempty"`
	Task       Task      `json:"task"`
	Status     JobStatus `json:"status"`
}

// JobStatus is a job's state.
type JobStatus string

const (
	JobQueued   JobStatus = "queued"
	JobRunning  JobStatus = "running"
	JobDone     JobStatus = "done"
	JobError    JobStatus = "error"
	JobCanceled JobStatus = "canceled"
)

// JobResult is a worker execution's result.
type JobResult struct {
	JobID        string `json:"job_id"`
	Role         Role   `json:"role"`
	Provider     string `json:"provider,omitempty"`
	Output       string `json:"output"`
	Changed      bool   `json:"changed"` // produced a diff / side effect
	TokensIn     int    `json:"tokens_in"`
	TokensOut    int    `json:"tokens_out"`
	ResultDigest string `json:"result_digest,omitempty"`
	Err          string `json:"err,omitempty"`
}

// Worker is one role-bound execution's identity record (for the audit seal).
type Worker struct {
	Identity    Identity  `json:"identity"`
	Role        Role      `json:"role"`
	RunID       RunID     `json:"run_id"`
	SandboxKind string    `json:"sandbox_kind"`
	RetiredAt   time.Time `json:"retired_at,omitempty"`
}

// Finding is one review_work reviewer finding.
type Finding struct {
	RunID    RunID  `json:"run_id"`
	Reviewer int    `json:"reviewer"`
	Severity string `json:"severity"` // info | warn | error
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Note     string `json:"note"`
}

// RunEvent is an observable run event (for HUD/statusline via Observe).
type RunEvent struct {
	RunID RunID     `json:"run_id"`
	Time  time.Time `json:"time"`
	Stage Stage     `json:"stage,omitempty"`
	Kind  string    `json:"kind"`
	Msg   string    `json:"msg"`
}
