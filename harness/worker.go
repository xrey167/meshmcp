package harness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xrey167/meshmcp/harness/provider"
	"github.com/xrey167/meshmcp/harness/sandbox"
)

// WorkerRunner is one role-bound agent execution with its own mesh identity and
// sandbox. It is the unit the scheduler fans out. (The persisted Worker record
// in types.go is its audit-seal artifact; this is the live executor.)
type WorkerRunner interface {
	Identity() Identity
	Role() Role
	Run(ctx context.Context, task Task) (JobResult, error)
}

// roleWorker drives a provider for a class on behalf of a role, within a
// sandbox. It performs no privileged action itself beyond invoking the model;
// any tool the model would call is separately governed by the MCP server.
type roleWorker struct {
	id    Identity
	role  Role
	class string
	reg   *provider.Registry
	sb    sandbox.Sandbox
	jobID string
}

func (w *roleWorker) Identity() Identity { return w.id }
func (w *roleWorker) Role() Role         { return w.role }

// Run invokes the class provider with the task as the prompt and returns a
// structured JobResult. Whether the run "changed" anything is derived from the
// role (writing roles produce diffs), which drives loop convergence.
func (w *roleWorker) Run(ctx context.Context, task Task) (JobResult, error) {
	prov, err := w.reg.Resolve(ctx, w.class)
	if err != nil {
		return JobResult{JobID: w.jobID, Role: w.role, Err: err.Error()}, err
	}
	comp, err := prov.Invoke(ctx, provider.Prompt{
		System: fmt.Sprintf("You are a %s worker. Complete the task precisely and report what you did.", w.role),
		User:   task.Title + "\n" + task.Body,
	})
	if err != nil {
		return JobResult{JobID: w.jobID, Role: w.role, Provider: prov.Name(), Err: err.Error()}, err
	}
	res := JobResult{
		JobID:        w.jobID,
		Role:         w.role,
		Output:       comp.Text,
		Changed:      writesCode(w.role),
		TokensIn:     comp.TokensIn,
		TokensOut:    comp.TokensOut,
		ResultDigest: digest(comp.Text),
	}
	return res, nil
}

// writesCode reports whether a role produces diffs, used for loop convergence
// (a round of only read-only roles produces no diff → the loop settles).
func writesCode(r Role) bool {
	switch r {
	case RoleExecutor, RoleJunior, RoleDeepWorker:
		return true
	default:
		return false
	}
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}
