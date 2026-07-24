package harness

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"strings"
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

	// Optional subprocess-worker execution: when both are set, a job runs as an
	// external worker PROCESS (ExecSpawner) instead of an in-process roleWorker.
	spawner   Spawner
	workerCmd []string

	mu       sync.Mutex
	inflight map[string]JobStatus
	minted   []Worker // workers minted this run, for the settle/retire seal
	ordinal  int      // monotonic worker-ordinal counter (unique FQDNs across concurrent spawns)
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

// WithSubprocessWorkers switches execution to spawn an external worker PROCESS
// per job (via sp, running cmd) instead of an in-process provider worker: the
// worker joins the mesh as its minted identity and its stdout is captured as the
// job result. With either argument empty the scheduler keeps in-process workers.
// The task is passed to the process via the MESHMCP_TASK/RUN/JOB environment.
func (s *Scheduler) WithSubprocessWorkers(sp Spawner, cmd []string) *Scheduler {
	s.spawner = sp
	s.workerCmd = append([]string(nil), cmd...)
	return s
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

	var canceled error
	for i := range tasks {
		select {
		case <-ctx.Done():
			canceled = ctx.Err()
		case sem <- struct{}{}:
		}
		if canceled != nil {
			break
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = s.runOne(ctx, run, tasks[idx], role, class, sessionLabels)
		}(i)
	}
	// Always wait for in-flight workers before returning — returning while a
	// spawned goroutine still writes results[idx] would be a data race.
	wg.Wait()
	return results, canceled
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

	// Subprocess-worker mode: run the job as an external worker process as the
	// minted identity, capture its output, then retire the identity.
	if s.spawner != nil && len(s.workerCmd) > 0 {
		res := s.runSubprocessJob(ctx, run, task, role, id, jobID)
		s.recordWorker(Worker{Identity: id, Role: role, RunID: run.ID, SandboxKind: "process"})
		_ = s.minter.Retire(id)
		return res
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

// runSubprocessJob spawns an external worker process for the minted identity and
// captures its stdout as the job result. When the minter is an EnrollMinter, the
// worker's real mesh-join credentials are injected so it joins as its identity;
// otherwise it runs with just its identity markers. The spawner already builds a
// curated, secret-safe environment (never the parent's).
func (s *Scheduler) runSubprocessJob(ctx context.Context, run RunState, task Task, role Role, id Identity, jobID string) JobResult {
	var buf bytes.Buffer
	spec := SpawnSpec{
		Identity: id,
		Command:  append([]string(nil), s.workerCmd...),
		ExtraEnv: []string{
			"MESHMCP_TASK=" + task.Title,
			"MESHMCP_RUN=" + string(run.ID),
			"MESHMCP_JOB=" + jobID,
		},
		Stdout: &buf,
		Stderr: &buf,
	}
	if em, ok := s.minter.(*EnrollMinter); ok {
		if creds, ok := em.Creds(id.Key); ok {
			spec.Creds = creds
		}
	}
	h, err := s.spawner.Spawn(ctx, spec)
	if err != nil {
		return JobResult{JobID: jobID, Role: role, Err: "spawn: " + err.Error()}
	}
	waitErr := h.Wait()
	out := strings.TrimSpace(buf.String())
	res := JobResult{JobID: jobID, Role: role, Output: out, Changed: writesCode(role), ResultDigest: digest(out)}
	if waitErr != nil {
		res.Err = waitErr.Error()
	}
	return res
}

// nextOrdinal reserves a unique, monotonic worker ordinal. It must NOT derive
// from len(minted): minted is appended only after a worker finishes, so
// concurrent spawns would otherwise read the same length and mint colliding
// FQDNs.
func (s *Scheduler) nextOrdinal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.ordinal
	s.ordinal++
	return n
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
