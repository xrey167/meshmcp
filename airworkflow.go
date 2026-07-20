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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/embed"
	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/mcpclient"
)

// airWorkflow is a declarative sequence of Air steps (P4): launch an agent,
// steer a session, or call a tool — run in order over one mesh membership.
// OnError controls whether a failed step stops the run ("stop", the default) or
// lets the remaining steps run ("continue").
type airWorkflow struct {
	Name    string            `yaml:"name"`
	OnError string            `yaml:"on_error"` // "stop" (default) | "continue"
	Steps   []airWorkflowStep `yaml:"steps"`
}

// airWorkflowStep is one step: exactly one of launch/steer/call/parallel must be
// set. As names a variable that captures the step's output (a launch's identity,
// a call's result) for later ${as.field} references. Timeout bounds a network
// step (steer/call); Parallel runs its children concurrently.
type airWorkflowStep struct {
	Launch   *launchStep       `yaml:"launch"`
	Steer    *steerStep        `yaml:"steer"`
	Call     *callStep         `yaml:"call"`
	Parallel []airWorkflowStep `yaml:"parallel"`
	As       string            `yaml:"as"`
	Timeout  string            `yaml:"timeout"` // e.g. "30s"; default stepDefaultTimeout
}

type launchStep struct {
	Role     string `yaml:"role"`
	Gateway  string `yaml:"gateway"`
	NBConfig string `yaml:"nb_config"`
}

type steerStep struct {
	Control string         `yaml:"control"` // gateway control endpoint (ip:port)
	Backend string         `yaml:"backend"`
	Session string         `yaml:"session"`
	Method  string         `yaml:"method"`
	Params  map[string]any `yaml:"params"`
}

type callStep struct {
	Target string         `yaml:"target"` // backend mesh address (ip:port)
	Tool   string         `yaml:"tool"`
	Args   map[string]any `yaml:"args"`
}

// stepDefaultTimeout bounds a steer/call step when it sets no timeout.
const stepDefaultTimeout = 30 * time.Second

// connRetryCap is how long a steer/call step keeps retrying connection-level
// failures — long enough to absorb a just-launched agent that hasn't finished
// joining the mesh, so a launch→steer sequence doesn't race.
const connRetryCap = 10 * time.Second

func (s airWorkflowStep) kind() string {
	switch {
	case s.Launch != nil:
		return "launch " + s.Launch.Role
	case s.Steer != nil:
		return "steer " + s.Steer.Backend + "/" + s.Steer.Session
	case s.Call != nil:
		return "call " + s.Call.Tool + "@" + s.Call.Target
	case s.Parallel != nil:
		return fmt.Sprintf("parallel (%d)", len(s.Parallel))
	default:
		return "empty"
	}
}

func (s airWorkflowStep) validate(i int) error {
	n := 0
	if s.Launch != nil {
		n++
		if s.Launch.Role == "" || s.Launch.Gateway == "" {
			return fmt.Errorf("step %d launch: role and gateway are required", i+1)
		}
	}
	if s.Steer != nil {
		n++
		if s.Steer.Control == "" || s.Steer.Backend == "" || s.Steer.Session == "" {
			return fmt.Errorf("step %d steer: control, backend and session are required", i+1)
		}
	}
	if s.Call != nil {
		n++
		if s.Call.Target == "" || s.Call.Tool == "" {
			return fmt.Errorf("step %d call: target and tool are required", i+1)
		}
	}
	if s.Parallel != nil {
		n++
		if len(s.Parallel) == 0 {
			return fmt.Errorf("step %d parallel: no children", i+1)
		}
		for j, child := range s.Parallel {
			if child.Parallel != nil {
				return fmt.Errorf("step %d parallel child %d: nested parallel is not allowed", i+1, j+1)
			}
			if err := child.validate(j); err != nil {
				return fmt.Errorf("step %d %w", i+1, err)
			}
		}
	}
	if n != 1 {
		return fmt.Errorf("step %d: exactly one of launch, steer, call, parallel must be set (got %d)", i+1, n)
	}
	if s.Timeout != "" {
		if _, err := time.ParseDuration(s.Timeout); err != nil {
			return fmt.Errorf("step %d: bad timeout %q: %w", i+1, s.Timeout, err)
		}
	}
	return nil
}

func loadAirWorkflow(path string) (*airWorkflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read workflow: %w", err)
	}
	var wf airWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("parse workflow %s: %w", path, err)
	}
	if len(wf.Steps) == 0 {
		return nil, fmt.Errorf("workflow %s: no steps", path)
	}
	if wf.OnError != "" && wf.OnError != "stop" && wf.OnError != "continue" {
		return nil, fmt.Errorf("workflow %s: on_error must be stop or continue (got %q)", path, wf.OnError)
	}
	for i, s := range wf.Steps {
		if err := s.validate(i); err != nil {
			return nil, err
		}
	}
	return &wf, nil
}

// stepResult is one executed step's outcome, for the --json run summary.
type stepResult struct {
	Kind       string `json:"kind"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Output     string `json:"output,omitempty"`
}

// wfRun carries the mesh membership and the variable store shared across a
// workflow's steps.
type wfRun struct {
	client *embed.Client
	mu     sync.Mutex
	vars   map[string]any
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
			kinds[i] = s.kind()
			if !*jsonOut {
				fmt.Printf("  step %d: %s\n", i+1, s.kind())
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
		log.Printf("workflow %q step %d/%d: %s", name, i+1, len(steps), s.kind())
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
				firstErr = fmt.Errorf("workflow %q step %d (%s) failed", name, i+1, s.kind())
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
	res := stepResult{Kind: s.kind(), OK: err == nil, DurationMS: time.Since(start).Milliseconds(), Output: out}
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
		pid, identity, err := spawnAgent(s.Launch.Role, s.Launch.NBConfig, s.Launch.Gateway)
		if err != nil {
			return "", nil, err
		}
		log.Printf("  launched agent role=%s pid=%d identity=%s", s.Launch.Role, pid, identity)
		return identity, map[string]any{"identity": identity, "pid": pid}, nil
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

func (r *wfRun) stepContext(ctx context.Context, timeout string) (context.Context, context.CancelFunc) {
	d := stepDefaultTimeout
	if timeout != "" {
		if parsed, err := time.ParseDuration(timeout); err == nil {
			d = parsed
		}
	}
	return context.WithTimeout(ctx, d)
}

// wfVarRe matches ${name.field} variable references.
var wfVarRe = regexp.MustCompile(`\$\{([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)\}`)

// expand substitutes ${name.field} tokens from vars; unknown tokens are left as-is.
func expand(s string, vars map[string]any) string {
	if !strings.Contains(s, "${") {
		return s
	}
	return wfVarRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := wfVarRe.FindStringSubmatch(m)
		if v, ok := vars[sub[1]]; ok {
			if fields, ok := v.(map[string]any); ok {
				if fv, ok := fields[sub[2]]; ok {
					return fmt.Sprint(fv)
				}
			}
		}
		return m
	})
}

// expandMap returns a copy of m with ${var} references expanded in string values.
func expandMap(m map[string]any, vars map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if sv, ok := v.(string); ok {
			out[k] = expand(sv, vars)
		} else {
			out[k] = v
		}
	}
	return out
}

func expandSteer(s steerStep, vars map[string]any) steerStep {
	s.Control = expand(s.Control, vars)
	s.Backend = expand(s.Backend, vars)
	s.Session = expand(s.Session, vars)
	s.Method = expand(s.Method, vars)
	s.Params = expandMap(s.Params, vars)
	return s
}

func expandCall(c callStep, vars map[string]any) callStep {
	c.Target = expand(c.Target, vars)
	c.Tool = expand(c.Tool, vars)
	c.Args = expandMap(c.Args, vars)
	return c
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
