package air

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// A Workflow is a declarative sequence of Air steps (P4): launch an agent, steer
// a session, steer an agent's inbox, or call a tool — run in order. This package
// owns the format: the schema, its validation, and the ${var.field} expansion.
// The runner that executes it against a live mesh lives in the main package.
//
// OnError controls whether a failed step stops the run ("stop", the default) or
// lets the remaining steps run ("continue"). Cleanup decides what happens to
// launched agents when the run ends: "leave" (default — they keep running) or
// "stop" (kill them).
type Workflow struct {
	Name    string         `yaml:"name"`
	OnError string         `yaml:"on_error"` // "stop" (default) | "continue"
	Cleanup string         `yaml:"cleanup"`  // "leave" (default) | "stop"
	Steps   []WorkflowStep `yaml:"steps"`
}

// WorkflowStep is one step: exactly one of launch/steer/agent_steer/call/
// parallel must be set. As names a variable that captures the step's output for
// later ${as.field} references. Timeout bounds a network step; Parallel runs its
// children concurrently.
type WorkflowStep struct {
	Launch     *LaunchStep     `yaml:"launch"`
	Steer      *SteerStep      `yaml:"steer"`
	AgentSteer *AgentSteerStep `yaml:"agent_steer"`
	Call       *CallStep       `yaml:"call"`
	Parallel   []WorkflowStep  `yaml:"parallel"`
	As         string          `yaml:"as"`
	Timeout    string          `yaml:"timeout"` // e.g. "30s"
}

// LaunchStep spawns a new agent identity against a gateway.
type LaunchStep struct {
	Role       string   `yaml:"role" json:"role"`
	Gateway    string   `yaml:"gateway" json:"gateway"`
	NBConfig   string   `yaml:"nb_config" json:"nb_config,omitempty"`
	SteerPort  int      `yaml:"steer_port" json:"steer_port,omitempty"`   // if >0, launch with a P1 steer inbox on this mesh port
	SteerAllow []string `yaml:"steer_allow" json:"steer_allow,omitempty"` // identities allowed to use the steer inbox; passed as repeatable flags
	Interval   string   `yaml:"interval" json:"interval,omitempty"`       // agent's delay between calls (passed through)
}

// AgentSteerStep sends one steer envelope to a launched agent's P1 inbox.
type AgentSteerStep struct {
	Target string         `yaml:"target"` // agent steer inbox (mesh-ip:port)
	Type   string         `yaml:"type"`   // task | nudge | cancel
	Tool   string         `yaml:"tool"`   // type=task: tool to call
	Args   map[string]any `yaml:"args"`   // type=task: tool args
	Text   string         `yaml:"text"`   // type=nudge: guidance
	ID     string         `yaml:"id"`     // caller correlation id (audited)
}

// SteerStep steers one live session via a gateway control endpoint.
type SteerStep struct {
	Control string         `yaml:"control"` // gateway control endpoint (ip:port)
	Backend string         `yaml:"backend"`
	Session string         `yaml:"session"`
	Method  string         `yaml:"method"`
	Params  map[string]any `yaml:"params"`
}

// CallStep calls one tool on a backend over the mesh.
type CallStep struct {
	Target string         `yaml:"target"` // backend mesh address (ip:port)
	Tool   string         `yaml:"tool"`
	Args   map[string]any `yaml:"args"`
}

// MaxParallelWidth caps how many children a single parallel: block may hold, so
// a workflow cannot request thousands of concurrent steps at once.
const MaxParallelWidth = 64

// Kind renders a one-line description of the step, for dry-run plans and logs.
func (s WorkflowStep) Kind() string {
	switch {
	case s.Launch != nil:
		return "launch " + s.Launch.Role
	case s.Steer != nil:
		return "steer " + s.Steer.Backend + "/" + s.Steer.Session
	case s.AgentSteer != nil:
		return "agent-steer " + s.AgentSteer.Type + "@" + s.AgentSteer.Target
	case s.Call != nil:
		return "call " + s.Call.Tool + "@" + s.Call.Target
	case s.Parallel != nil:
		return fmt.Sprintf("parallel (%d)", len(s.Parallel))
	default:
		return "empty"
	}
}

// Validate checks one step (i is its 0-based index, for messages): exactly one
// action, required fields present, durations parseable, parallel width bounded,
// and no nested parallel.
func (s WorkflowStep) Validate(i int) error {
	n := 0
	if s.Launch != nil {
		n++
		if s.Launch.Role == "" || s.Launch.Gateway == "" {
			return fmt.Errorf("step %d launch: role and gateway are required", i+1)
		}
		if s.Launch.SteerPort < 0 || s.Launch.SteerPort > 65535 {
			return fmt.Errorf("step %d launch: steer_port must be between 1 and 65535 when enabled", i+1)
		}
		if s.Launch.SteerPort > 0 && len(s.Launch.SteerAllow) == 0 {
			return fmt.Errorf("step %d launch: steer_port requires at least one steer_allow identity", i+1)
		}
		if s.Launch.SteerPort == 0 && len(s.Launch.SteerAllow) > 0 {
			return fmt.Errorf("step %d launch: steer_allow requires steer_port", i+1)
		}
		for _, identity := range s.Launch.SteerAllow {
			if strings.TrimSpace(identity) == "" || identity != strings.TrimSpace(identity) || len(identity) > 512 || steerHasControl(identity) {
				return fmt.Errorf("step %d launch: steer_allow identities must be bounded and have no surrounding whitespace or control characters", i+1)
			}
		}
		if s.Launch.Interval != "" {
			if _, err := time.ParseDuration(s.Launch.Interval); err != nil {
				return fmt.Errorf("step %d launch: bad interval %q: %w", i+1, s.Launch.Interval, err)
			}
		}
	}
	if s.Steer != nil {
		n++
		if s.Steer.Control == "" || s.Steer.Backend == "" || s.Steer.Session == "" {
			return fmt.Errorf("step %d steer: control, backend and session are required", i+1)
		}
	}
	if s.AgentSteer != nil {
		n++
		if s.AgentSteer.Target == "" {
			return fmt.Errorf("step %d agent_steer: target is required", i+1)
		}
		env := SteerEnvelope{Type: s.AgentSteer.Type, Tool: s.AgentSteer.Tool, Text: s.AgentSteer.Text, ID: s.AgentSteer.ID}
		if len(s.AgentSteer.Args) > 0 {
			env.Args, _ = json.Marshal(s.AgentSteer.Args)
		}
		if err := env.Validate(); err != nil {
			return fmt.Errorf("step %d agent_steer: %w", i+1, err)
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
		if len(s.Parallel) > MaxParallelWidth {
			return fmt.Errorf("step %d parallel: %d children exceeds the cap of %d", i+1, len(s.Parallel), MaxParallelWidth)
		}
		for j, child := range s.Parallel {
			if child.Parallel != nil {
				return fmt.Errorf("step %d parallel child %d: nested parallel is not allowed", i+1, j+1)
			}
			if err := child.Validate(j); err != nil {
				return fmt.Errorf("step %d %w", i+1, err)
			}
		}
	}
	if n != 1 {
		return fmt.Errorf("step %d: exactly one of launch, steer, agent_steer, call, parallel must be set (got %d)", i+1, n)
	}
	if s.Timeout != "" {
		if _, err := time.ParseDuration(s.Timeout); err != nil {
			return fmt.Errorf("step %d: bad timeout %q: %w", i+1, s.Timeout, err)
		}
	}
	return nil
}

// Validate checks the whole workflow: at least one step, valid on_error/cleanup,
// every step valid, and every ${name.field} reference resolves to a variable a
// PRIOR step captured with `as:` — so a typo or forward reference is caught at
// load, not silently left unexpanded at run time.
func (w *Workflow) Validate() error {
	if len(w.Steps) == 0 {
		return fmt.Errorf("workflow %q: no steps", w.Name)
	}
	if w.OnError != "" && w.OnError != "stop" && w.OnError != "continue" {
		return fmt.Errorf("workflow %q: on_error must be stop or continue (got %q)", w.Name, w.OnError)
	}
	if w.Cleanup != "" && w.Cleanup != "leave" && w.Cleanup != "stop" {
		return fmt.Errorf("workflow %q: cleanup must be leave or stop (got %q)", w.Name, w.Cleanup)
	}
	defined := map[string]bool{}
	for i, s := range w.Steps {
		if err := s.Validate(i); err != nil {
			return err
		}
		// A step may only reference variables captured by earlier steps
		// (parallel children run concurrently, so they can't reference a
		// sibling either — they are checked against `defined` as it stands
		// before this step, and their own `as` is added after the block).
		for _, ref := range s.varRefs() {
			if !defined[ref] {
				return fmt.Errorf("step %d references ${%s.…} but no earlier step captured it with `as: %s`", i+1, ref, ref)
			}
		}
		if s.As != "" {
			defined[s.As] = true
		}
		for _, child := range s.Parallel {
			if child.As != "" {
				defined[child.As] = true
			}
		}
	}
	return nil
}

// varRefs returns the distinct variable names a step references via
// ${name.field}, across all its expandable string fields (including a parallel
// block's children).
func (s WorkflowStep) varRefs() []string {
	seen := map[string]bool{}
	var names []string
	add := func(ss ...string) {
		for _, str := range ss {
			for _, m := range varRe.FindAllStringSubmatch(str, -1) {
				if !seen[m[1]] {
					seen[m[1]] = true
					names = append(names, m[1])
				}
			}
		}
	}
	addMap := func(m map[string]any) {
		for _, v := range m {
			if str, ok := v.(string); ok {
				add(str)
			}
		}
	}
	if s.Steer != nil {
		add(s.Steer.Control, s.Steer.Backend, s.Steer.Session, s.Steer.Method)
		addMap(s.Steer.Params)
	}
	if s.Call != nil {
		add(s.Call.Target, s.Call.Tool)
		addMap(s.Call.Args)
	}
	if s.AgentSteer != nil {
		add(s.AgentSteer.Target, s.AgentSteer.Tool, s.AgentSteer.Text)
		addMap(s.AgentSteer.Args)
	}
	for _, child := range s.Parallel {
		for _, r := range child.varRefs() { // already-extracted names, merge directly
			if !seen[r] {
				seen[r] = true
				names = append(names, r)
			}
		}
	}
	return names
}

// Plan returns the one-line Kind of each step, for a --dry-run summary.
func (w *Workflow) Plan() []string {
	kinds := make([]string, len(w.Steps))
	for i, s := range w.Steps {
		kinds[i] = s.Kind()
	}
	return kinds
}

// ParseWorkflow parses and validates a workflow from YAML bytes.
func ParseWorkflow(data []byte) (*Workflow, error) {
	var wf Workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("parse workflow: %w", err)
	}
	if err := wf.Validate(); err != nil {
		return nil, err
	}
	return &wf, nil
}

// varRe matches ${name.field} variable references.
var varRe = regexp.MustCompile(`\$\{([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)\}`)

// Expand substitutes ${name.field} tokens from vars; unknown tokens are left
// as-is (so a typo surfaces in the executed step rather than silently blanking).
func Expand(s string, vars map[string]any) string {
	if !strings.Contains(s, "${") {
		return s
	}
	return varRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := varRe.FindStringSubmatch(m)
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

// ExpandMap returns a copy of m with ${var} references expanded in string values.
func ExpandMap(m map[string]any, vars map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if sv, ok := v.(string); ok {
			out[k] = Expand(sv, vars)
		} else {
			out[k] = v
		}
	}
	return out
}

// ExpandSteer returns a copy of s with ${var} references expanded.
func ExpandSteer(s SteerStep, vars map[string]any) SteerStep {
	s.Control = Expand(s.Control, vars)
	s.Backend = Expand(s.Backend, vars)
	s.Session = Expand(s.Session, vars)
	s.Method = Expand(s.Method, vars)
	s.Params = ExpandMap(s.Params, vars)
	return s
}

// ExpandCall returns a copy of c with ${var} references expanded.
func ExpandCall(c CallStep, vars map[string]any) CallStep {
	c.Target = Expand(c.Target, vars)
	c.Tool = Expand(c.Tool, vars)
	c.Args = ExpandMap(c.Args, vars)
	return c
}

// ExpandAgentSteer returns a copy of s with ${var} references expanded.
func ExpandAgentSteer(s AgentSteerStep, vars map[string]any) AgentSteerStep {
	s.Target = Expand(s.Target, vars)
	s.Tool = Expand(s.Tool, vars)
	s.Text = Expand(s.Text, vars)
	s.Args = ExpandMap(s.Args, vars)
	return s
}
