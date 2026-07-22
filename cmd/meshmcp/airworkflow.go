package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/mcpclient"
)

// The workflow schema, validation, and ${var.field} expansion live in the air
// package (air/workflow.go); this file is the mesh-coupled runner that executes
// a parsed workflow against a live membership. The step types and expand
// helpers are aliased in airalias.go so the runner reads the same names.

// stepDefaultTimeout bounds a steer/call step when it sets no timeout.
const stepDefaultTimeout = 30 * time.Second

// connRetryCap is how long a steer/call step keeps retrying connection-level
// failures — long enough to absorb a just-launched agent that hasn't finished
// joining the mesh, so a launch→steer sequence doesn't race.
const connRetryCap = 10 * time.Second

// loadAirWorkflow reads a workflow file; parsing and validation live in air.
func loadAirWorkflow(path string) (*airWorkflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read workflow: %w", err)
	}
	return air.ParseWorkflow(data)
}

// stepResult is one executed step's outcome, for the --json run summary.
type stepResult struct {
	Kind       string `json:"kind"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Output     string `json:"output,omitempty"`
}

// maxWorkflowLaunches caps the agents one workflow run may spawn — a backstop
// against a mis-generated or malicious YAML fanning out unbounded processes.
const maxWorkflowLaunches = 32

// wfRun carries the mesh membership and the variable store shared across a
// workflow's steps, plus the pids of agents it launched (for cleanup: stop).
type wfRun struct {
	client   *embed.Client
	mu       sync.Mutex
	vars     map[string]any
	pids     []int
	reserved int // launch slots reserved (>= len(pids)); the spawn backstop
}

// reserveLaunch claims a launch slot BEFORE the process is spawned, so the cap
// actually prevents a fan-out (a parallel block spawning N children) rather
// than only relabelling the step after N processes already exist. The caller
// must pair a successful reservation with either recordLaunch(pid) on a
// successful spawn or releaseLaunch() on a spawn failure.
func (r *wfRun) reserveLaunch() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.reserved >= maxWorkflowLaunches {
		return fmt.Errorf("workflow launch cap reached (%d agents)", maxWorkflowLaunches)
	}
	r.reserved++
	return nil
}

func (r *wfRun) releaseLaunch() {
	r.mu.Lock()
	if r.reserved > 0 {
		r.reserved--
	}
	r.mu.Unlock()
}

// recordLaunch records a successfully spawned child's pid so cleanup: stop can
// reach it. The slot was already reserved by reserveLaunch.
func (r *wfRun) recordLaunch(pid int) {
	r.mu.Lock()
	r.pids = append(r.pids, pid)
	r.mu.Unlock()
}

// stopLaunched kills every agent this run spawned (cleanup: stop). Best-effort:
// an already-exited child is not an error.
func (r *wfRun) stopLaunched() {
	r.mu.Lock()
	pids := append([]int(nil), r.pids...)
	r.mu.Unlock()
	for _, pid := range pids {
		p, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		if err := p.Kill(); err != nil {
			log.Printf("  cleanup: stop agent pid=%d: %v", pid, err)
		} else {
			log.Printf("  cleanup: stopped agent pid=%d", pid)
		}
	}
}

func (r *wfRun) setVar(name string, v map[string]any) {
	if name == "" {
		return
	}
	r.mu.Lock()
	r.vars[name] = v
	r.mu.Unlock()
}

func (r *wfRun) snapshot() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]any, len(r.vars))
	for k, v := range r.vars {
		out[k] = v
	}
	return out
}

// cmdAirWorkflow runs a declarative workflow. --dry-run parses and prints the
// plan without joining the mesh; --json prints a machine-readable run summary.
func cmdAirWorkflow(args []string) error {
	fs := flag.NewFlagSet("air workflow", flag.ExitOnError)
	o := meshFlags(fs)
	dryRun := fs.Bool("dry-run", false, "parse and validate without joining the mesh or running steps")
	jsonOut := fs.Bool("json", false, "print a machine-readable run summary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air workflow [flags] <file.yaml>")
	}
	wf, err := loadAirWorkflow(fs.Arg(0))
	if err != nil {
		return err
	}
	log.Printf("workflow %q: %d step(s)", wf.Name, len(wf.Steps))
	if *dryRun {
		kinds := make([]string, len(wf.Steps))
		for i, s := range wf.Steps {
			kinds[i] = s.Kind()
			if !*jsonOut {
				fmt.Printf("  step %d: %s\n", i+1, s.Kind())
			}
		}
		if *jsonOut {
			b, err := json.MarshalIndent(map[string]any{"name": wf.Name, "plan": kinds}, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(b))
		}
		return nil
	}

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	run := &wfRun{client: client, vars: map[string]any{}}
	results, runErr := run.runSteps(context.Background(), wf.Name, wf.Steps, wf.OnError)
	if wf.Cleanup == "stop" {
		run.stopLaunched()
	}
	if *jsonOut {
		if err := printWorkflowJSON(wf.Name, results); err != nil {
			return err
		}
	}
	if runErr != nil {
		return runErr
	}
	log.Printf("workflow %q complete", wf.Name)
	return nil
}

func printWorkflowJSON(name string, steps []stepResult) error {
	b, err := json.MarshalIndent(map[string]any{"name": name, "steps": steps}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// runSteps runs a sequence, honouring on_error. It returns the per-step results
// and the first fatal error (nil when every step succeeded or on_error=continue).
func (r *wfRun) runSteps(ctx context.Context, name string, steps []airWorkflowStep, onError string) ([]stepResult, error) {
	var results []stepResult
	var firstErr error
	for i, s := range steps {
		log.Printf("workflow %q step %d/%d: %s", name, i+1, len(steps), s.Kind())
		res := r.runOne(ctx, s)
		results = append(results, res...)
		failed := false
		for _, rr := range res {
			if !rr.OK {
				failed = true
			}
		}
		if failed {
			if firstErr == nil {
				firstErr = fmt.Errorf("workflow %q step %d (%s) failed", name, i+1, s.Kind())
			}
			if onError != "continue" {
				return results, firstErr
			}
		}
	}
	return results, firstErr
}

// runOne executes one step (a parallel block yields several results) and returns
// their stepResults. Captured output is stored under step.As.
func (r *wfRun) runOne(ctx context.Context, s airWorkflowStep) []stepResult {
	if s.Parallel != nil {
		return r.runParallel(ctx, s.Parallel)
	}
	start := time.Now()
	out, captured, err := r.execStep(ctx, s)
	res := stepResult{Kind: s.Kind(), OK: err == nil, DurationMS: time.Since(start).Milliseconds(), Output: out}
	if err != nil {
		res.Error = err.Error()
	} else {
		r.setVar(s.As, captured)
	}
	return []stepResult{res}
}

func (r *wfRun) runParallel(ctx context.Context, children []airWorkflowStep) []stepResult {
	out := make([]stepResult, len(children))
	var wg sync.WaitGroup
	for i, child := range children {
		wg.Add(1)
		go func(i int, child airWorkflowStep) {
			defer wg.Done()
			out[i] = r.runOne(ctx, child)[0]
		}(i, child)
	}
	wg.Wait()
	return out
}

// execStep runs a single non-parallel step: it expands ${var.field} references
// against the current variables, applies the step timeout, and dispatches.
func (r *wfRun) execStep(ctx context.Context, s airWorkflowStep) (output string, captured map[string]any, err error) {
	vars := r.snapshot()
	stepCtx, cancel := r.stepContext(ctx, s.Timeout)
	defer cancel()
	switch {
	case s.Launch != nil:
		extra := workflowLaunchArgs(s.Launch)
		// Reserve the launch slot BEFORE spawning, so the cap prevents the
		// fork rather than relabelling a process that already exists.
		if err := r.reserveLaunch(); err != nil {
			return "", nil, err
		}
		pid, identity, err := spawnAgent(s.Launch.Role, s.Launch.NBConfig, s.Launch.Gateway, extra...)
		if err != nil {
			r.releaseLaunch()
			return "", nil, err
		}
		r.recordLaunch(pid)
		log.Printf("  launched agent role=%s pid=%d identity=%s", s.Launch.Role, pid, identity)
		return identity, map[string]any{"identity": identity, "pid": pid}, nil
	case s.AgentSteer != nil:
		st := expandAgentSteer(*s.AgentSteer, vars)
		env := steerEnvelope{Type: st.Type, Tool: st.Tool, Text: st.Text, ID: st.ID}
		if len(st.Args) > 0 {
			b, _ := json.Marshal(st.Args)
			env.Args = b
		}
		// Retried like steer/call: a just-launched agent's inbox may not be
		// listening yet.
		err := retryConn(stepCtx, connRetryCap, func() error {
			return sendSteerEnvelope(stepCtx, r.client, st.Target, env)
		})
		if err != nil {
			return "", nil, err
		}
		return "steered", map[string]any{"status": "steered", "target": st.Target}, nil
	case s.Steer != nil:
		st := expandSteer(*s.Steer, vars)
		if err := workflowSteer(stepCtx, r.client, &st); err != nil {
			return "", nil, err
		}
		return "steered", map[string]any{"status": "steered"}, nil
	case s.Call != nil:
		c := expandCall(*s.Call, vars)
		out, err := workflowCall(stepCtx, r.client, &c)
		if err != nil {
			return "", nil, err
		}
		return out, map[string]any{"result": out}, nil
	default:
		return "", nil, errors.New("empty step")
	}
}

// workflowLaunchArgs converts declarative launch options to the child agent's
// CLI. Each steer identity remains a separate repeatable flag so no escaping or
// delimiter convention can change the ACL entry.
func workflowLaunchArgs(launch *launchStep) []string {
	var args []string
	if launch.SteerPort > 0 {
		args = append(args, "--steer-port", fmt.Sprint(launch.SteerPort))
	}
	for _, identity := range launch.SteerAllow {
		args = append(args, "--steer-allow", identity)
	}
	if launch.Interval != "" {
		args = append(args, "--interval", launch.Interval)
	}
	return args
}

func (r *wfRun) stepContext(ctx context.Context, timeout string) (context.Context, context.CancelFunc) {
	d := stepDefaultTimeout
	if timeout != "" {
		if parsed, err := time.ParseDuration(timeout); err == nil {
			d = parsed
		}
	}
	return context.WithTimeout(ctx, d)
}

// retryConn retries fn while it returns a connection-level error, up to cap. It
// absorbs the window where a just-launched agent isn't listening on the mesh yet.
func retryConn(ctx context.Context, cap time.Duration, fn func() error) error {
	backoff := 200 * time.Millisecond
	start := time.Now()
	for {
		err := fn()
		if err == nil || !isConnError(err) || time.Since(start) >= cap {
			return err
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		if backoff *= 2; backoff > 2*time.Second {
			backoff = 2 * time.Second
		}
	}
}

// isConnError reports whether err looks like a not-yet-listening / dial failure
// worth retrying (as opposed to a 4xx the peer deliberately returned).
func isConnError(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	var oe *net.OpError
	return errors.As(err, &oe)
}

// workflowSteer POSTs to a gateway control endpoint over the mesh.
func workflowSteer(ctx context.Context, client *embed.Client, st *steerStep) error {
	hc := &http.Client{
		Timeout: stepDefaultTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return client.Dial(ctx, "tcp", st.Control)
			},
		},
	}
	method := st.Method
	if method == "" {
		method = "notifications/air/steer"
	}
	body, _ := json.Marshal(map[string]any{"backend": st.Backend, "id": st.Session, "method": method, "params": st.Params})
	return retryConn(ctx, connRetryCap, func() error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://air-control/v1/steer", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != http.StatusOK {
			// A non-200 is a decision by the peer, not a transport failure: don't retry.
			return &httpStatusError{status: resp.Status, body: string(bytes.TrimSpace(out))}
		}
		return nil
	})
}

// httpStatusError is a non-2xx response — a deliberate peer decision, so
// retryConn treats it as terminal (it is not a net.Error).
type httpStatusError struct {
	status, body string
}

func (e *httpStatusError) Error() string { return e.status + ": " + e.body }

// workflowCall dials a backend over the mesh and calls one tool, returning the
// tool result text. The dial+initialize is retried to absorb a launch race.
func workflowCall(ctx context.Context, client *embed.Client, c *callStep) (string, error) {
	var uc *mcpclient.Client
	if err := retryConn(ctx, connRetryCap, func() error {
		conn, err := client.Dial(ctx, "tcp", c.Target)
		if err != nil {
			return fmt.Errorf("dial %s: %w", c.Target, err)
		}
		u := mcpclient.New(conn, nil)
		if _, err := u.Initialize(ctx, "meshmcp-air-workflow"); err != nil {
			u.Close()
			return fmt.Errorf("initialize %s: %w", c.Target, err)
		}
		uc = u
		return nil
	}); err != nil {
		return "", err
	}
	defer uc.Close()
	args := any(c.Args)
	if args == nil {
		args = map[string]any{}
	}
	res, err := uc.CallTool(ctx, c.Tool, args, false)
	if err != nil {
		return "", fmt.Errorf("call %s: %w", c.Tool, err)
	}
	out := string(bytes.TrimSpace(res))
	log.Printf("  call %s -> %s", c.Tool, out)
	return out, nil
}
