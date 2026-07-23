package harness

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/xrey167/meshmcp/harness/provider"
	"github.com/xrey167/meshmcp/harness/sandbox"
)

// Scheduler runs governed role workers with bounded concurrency. Each spawn is a
// governed action (KindSpawn) authorized by the Governor before a worker
// identity is minted, and each worker gets its own mesh identity + sandbox.
// Concurrency is min(policyCap, config.fanOut, cpu-based cap); excess jobs queue.
type Scheduler struct {
	gov    *Governor
	minter Minter
	reg    *provider.Registry
	sbSpec sandbox.Spec // template sandbox spec (kind/min/repo)

	mu       sync.Mutex
	inflight map[string]JobStatus
	minted   []Worker // workers minted this run, for the settle/retire seal
}

// NewScheduler builds a scheduler.
func NewScheduler(gov *Governor, minter Minter, reg *provider.Registry, sb sandbox.Spec) *Scheduler {
	return &Scheduler{
		gov:      gov,
		minter:   minter,
		reg:      reg,
		sbSpec:   sb,
		inflight: map[string]JobStatus{},
	}
}

// cpuCap is the CPU-based concurrency backstop.
func cpuCap() int {
	n := runtime.NumCPU() - 1
	if n < 1 {
		n = 1
	}
	if n > 16 {
		n = 16
	}
	return n
}

// Fan mints a worker per task (governed spawn), runs them with bounded
// concurrency, and returns their results in task order. width is the requested
// parallelism; it is clamped to min(width, policyCap, cpuCap). sessionLabels is
// the run's accumulated data-flow label set (consulted by the spawn authorization).
//
// A spawn the Governor denies drops that task's result (recorded as an error
// JobResult) rather than minting an unauthorized worker — default-deny.
func (s *Scheduler) Fan(ctx context.Context, run RunState, tasks []Task, role Role, class string, width int, sessionLabels map[string]bool) ([]JobResult, error) {
	if width <= 0 {
		width = 1
	}
	if cap := cpuCap(); width > cap {
		width = cap
	}
	results := make([]JobResult, len(tasks))
	sem := make(chan struct{}, width)
	var wg sync.WaitGroup

	for i := range tasks {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = s.runOne(ctx, run, tasks[idx], role, class, sessionLabels)
		}(i)
	}
	wg.Wait()
	return results, nil
}

// runOne governs the spawn, mints the worker identity, builds its sandbox, runs
// it, and retires the identity.
func (s *Scheduler) runOne(ctx context.Context, run RunState, task Task, role Role, class string, sessionLabels map[string]bool) JobResult {
	jobID := fmt.Sprintf("%s-%s", run.ID, shortHash(task.ID+string(role)))

	// Governed spawn: authorize minting a worker of this role for this run.
	spawn := GovernedAction{
		Actor:    run.Actor,
		Kind:     KindSpawn,
		Target:   "delegate.spawn",
		Labels:   []string{LabelDelegateSpawn},
		RunID:    string(run.ID),
		JobID:    jobID,
		Category: run.Category,
		Mode:     run.Mode,
	}
	if _, err := s.gov.Allowed(spawn, sessionLabels); err != nil {
		return JobResult{JobID: jobID, Role: role, Err: err.Error()}
	}

	n := s.nextOrdinal()
	id, err := s.minter.Mint(string(run.ID), role, n)
	if err != nil {
		return JobResult{JobID: jobID, Role: role, Err: err.Error()}
	}

	// Build the worker's sandbox. A worktree spec gets a per-worker branch so
	// parallel writers never collide.
	spec := s.sbSpec
	if spec.Kind == "worktree" {
		spec.Branch = fmt.Sprintf("%s-%s", run.ID, id.FQDN)
	}
	sb, err := sandbox.New(ctx, spec)
	if err != nil {
		_ = s.minter.Retire(id)
		return JobResult{JobID: jobID, Role: role, Err: "sandbox: " + err.Error()}
	}

	w := &roleWorker{id: id, role: role, class: class, reg: s.reg, sb: sb, jobID: jobID}
	res, _ := w.Run(ctx, task)

	// Retire the worker identity and record it for the run's audit seal.
	_ = sb.Close()
	_ = s.minter.Retire(id)
	s.recordWorker(Worker{Identity: id, Role: role, RunID: run.ID, SandboxKind: sb.Kind()})
	res.JobID = jobID
	return res
}

func (s *Scheduler) nextOrdinal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.minted)
}

func (s *Scheduler) recordWorker(w Worker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.minted = append(s.minted, w)
}

// Minted returns the workers minted this run (for the settle seal).
func (s *Scheduler) Minted() []Worker {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Worker(nil), s.minted...)
}
