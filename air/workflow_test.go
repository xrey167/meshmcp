package air

import (
	"strings"
	"testing"
)

func TestParseWorkflowValid(t *testing.T) {
	wf, err := ParseWorkflow([]byte(`
name: demo
steps:
  - launch: { role: reader, gateway: 1.2.3.4:9101 }
  - steer:  { control: 1.2.3.4:9600, backend: fs, session: 9f2a, params: { text: hi } }
  - call:   { target: 1.2.3.4:9101, tool: summarize }
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if wf.Name != "demo" || len(wf.Steps) != 3 {
		t.Fatalf("unexpected workflow: %+v", wf)
	}
	want := []string{"launch reader", "steer fs/9f2a", "call summarize@1.2.3.4:9101"}
	if got := wf.Plan(); len(got) != 3 {
		t.Fatalf("plan len %d", len(got))
	}
	for i, w := range want {
		if wf.Steps[i].Kind() != w {
			t.Fatalf("step %d kind = %q, want %q", i, wf.Steps[i].Kind(), w)
		}
	}
}

func TestParseWorkflowRejects(t *testing.T) {
	cases := map[string]string{
		"two-actions":              "name: bad\nsteps:\n  - launch: { role: r, gateway: g:1 }\n    call: { target: t:1, tool: x }\n",
		"empty-step":               "name: bad\nsteps:\n  - {}\n",
		"no-steps":                 "name: bad\nsteps: []\n",
		"launch-missing-gateway":   "name: bad\nsteps:\n  - launch: { role: reader }\n",
		"steer-missing-session":    "name: bad\nsteps:\n  - steer: { control: c:1, backend: fs }\n",
		"nested-parallel":          "name: bad\nsteps:\n  - parallel:\n      - parallel:\n          - call: { target: x, tool: y }\n",
		"empty-parallel":           "name: bad\nsteps:\n  - parallel: []\n",
		"bad-timeout":              "name: bad\nsteps:\n  - call: { target: t:1, tool: a }\n    timeout: nope\n",
		"bad-on-error":             "name: bad\non_error: maybe\nsteps:\n  - call: { target: x, tool: y }\n",
		"bad-cleanup":              "name: bad\ncleanup: nuke\nsteps:\n  - call: { target: x, tool: y }\n",
		"agent_steer-no-target":    "name: bad\nsteps:\n  - agent_steer: { type: task, tool: t }\n",
		"agent_steer-task-notool":  "name: bad\nsteps:\n  - agent_steer: { target: a:1, type: task }\n",
		"agent_steer-bad-type":     "name: bad\nsteps:\n  - agent_steer: { target: a:1, type: pause }\n",
		"launch-bad-interval":      "name: bad\nsteps:\n  - launch: { role: r, gateway: g:1, interval: soon }\n",
		"launch-steer-no-allow":    "name: bad\nsteps:\n  - launch: { role: r, gateway: g:1, steer_port: 9120 }\n",
		"launch-empty-steer-allow": "name: bad\nsteps:\n  - launch: { role: r, gateway: g:1, steer_port: 9120, steer_allow: [''] }\n",
		"launch-allow-no-port":     "name: bad\nsteps:\n  - launch: { role: r, gateway: g:1, steer_allow: [operator] }\n",
		"launch-invalid-port":      "name: bad\nsteps:\n  - launch: { role: r, gateway: g:1, steer_port: 70000, steer_allow: [operator] }\n",
		"launch-spaced-allow":      "name: bad\nsteps:\n  - launch: { role: r, gateway: g:1, steer_port: 9120, steer_allow: [' operator'] }\n",
	}
	for name, body := range cases {
		if _, err := ParseWorkflow([]byte(body)); err == nil {
			t.Fatalf("expected error for %s", name)
		}
	}
}

func TestParseWorkflowAgentSteerAndOptions(t *testing.T) {
	wf, err := ParseWorkflow([]byte(`
name: demo
cleanup: stop
steps:
  - launch:
      role: reader
      gateway: 1.2.3.4:9101
      steer_port: 9120
      steer_allow: [operator.example.net, "pubkey:controller-key"]
      interval: 1s
    as: reader
  - agent_steer: { target: 1.2.3.4:9120, type: task, tool: read_file, args: { path: README.md } }
  - agent_steer: { target: 1.2.3.4:9120, type: nudge, text: focus }
  - agent_steer: { target: 1.2.3.4:9120, type: cancel }
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if wf.Cleanup != "stop" {
		t.Fatalf("cleanup = %q", wf.Cleanup)
	}
	if wf.Steps[1].Kind() != "agent-steer task@1.2.3.4:9120" {
		t.Fatalf("kind = %q", wf.Steps[1].Kind())
	}
	if wf.Steps[0].Launch.SteerPort != 9120 || wf.Steps[0].Launch.Interval != "1s" {
		t.Fatalf("launch options not parsed: %+v", wf.Steps[0].Launch)
	}
	if got := wf.Steps[0].Launch.SteerAllow; len(got) != 2 || got[0] != "operator.example.net" || got[1] != "pubkey:controller-key" {
		t.Fatalf("launch steer_allow not parsed: %#v", got)
	}
}

func TestParseWorkflowJSONSteerAllow(t *testing.T) {
	wf, err := ParseWorkflow([]byte(`{
  "name": "json-workflow",
  "steps": [{
    "launch": {
      "role": "reader",
      "gateway": "1.2.3.4:9101",
      "steer_port": 9120,
      "steer_allow": ["operator.example.net"]
    }
  }]
}`))
	if err != nil {
		t.Fatalf("parse JSON workflow: %v", err)
	}
	if got := wf.Steps[0].Launch.SteerAllow; len(got) != 1 || got[0] != "operator.example.net" {
		t.Fatalf("JSON steer_allow not parsed: %#v", got)
	}
}

func TestParseWorkflowRejectsWideParallel(t *testing.T) {
	var b strings.Builder
	b.WriteString("name: wide\nsteps:\n  - parallel:\n")
	for i := 0; i < MaxParallelWidth+1; i++ {
		b.WriteString("      - call: { target: 1.2.3.4:9101, tool: t }\n")
	}
	if _, err := ParseWorkflow([]byte(b.String())); err == nil {
		t.Fatal("a parallel block wider than the cap must be rejected")
	}
}

func TestExpand(t *testing.T) {
	vars := map[string]any{"worker": map[string]any{"identity": "/tmp/nb.json", "pid": 4242}}
	cases := map[string]string{
		"${worker.identity}":               "/tmp/nb.json",
		"pid=${worker.pid}":                "pid=4242",
		"${missing.field} stays":           "${missing.field} stays",
		"no vars here":                     "no vars here",
		"${worker.identity}@${worker.pid}": "/tmp/nb.json@4242",
	}
	for in, want := range cases {
		if got := Expand(in, vars); got != want {
			t.Errorf("Expand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExpandStepFields(t *testing.T) {
	vars := map[string]any{"w": map[string]any{"identity": "id-9"}}
	st := ExpandSteer(SteerStep{Backend: "fs", Session: "${w.identity}", Params: map[string]any{"note": "for ${w.identity}"}}, vars)
	if st.Session != "id-9" || st.Params["note"] != "for id-9" {
		t.Fatalf("steer not expanded: %+v", st)
	}
	c := ExpandCall(CallStep{Target: "${w.identity}:9101", Tool: "t", Args: map[string]any{"k": "${w.identity}"}}, vars)
	if c.Target != "id-9:9101" || c.Args["k"] != "id-9" {
		t.Fatalf("call not expanded: %+v", c)
	}
	a := ExpandAgentSteer(AgentSteerStep{Target: "${w.identity}", Text: "for ${w.identity}"}, vars)
	if a.Target != "id-9" || a.Text != "for id-9" {
		t.Fatalf("agent_steer not expanded: %+v", a)
	}
}

// TestWorkflowVarRefValidation proves a ${name.field} reference to a variable no
// earlier step captured with `as:` is rejected at load, while a valid backward
// reference (including from after a parallel block) passes.
func TestWorkflowVarRefValidation(t *testing.T) {
	// Valid: step 2 references the `as: worker` captured by step 1.
	if _, err := ParseWorkflow([]byte(`
name: ok
steps:
  - launch: { role: reader, gateway: 1.2.3.4:9101 }
    as: worker
  - call: { target: 1.2.3.4:9101, tool: t, args: { note: "by ${worker.identity}" } }
`)); err != nil {
		t.Fatalf("valid backward reference rejected: %v", err)
	}
	// Valid: reference a var captured inside an earlier parallel block.
	if _, err := ParseWorkflow([]byte(`
name: okpar
steps:
  - parallel:
      - launch: { role: reader, gateway: g:1 }
        as: r
  - call: { target: "${r.identity}", tool: t }
`)); err != nil {
		t.Fatalf("reference to parallel-captured var rejected: %v", err)
	}
	// Invalid: reference to an undefined var.
	if _, err := ParseWorkflow([]byte(`
name: bad
steps:
  - call: { target: 1.2.3.4:9101, tool: t, args: { note: "${ghost.identity}" } }
`)); err == nil {
		t.Fatal("reference to an undefined var must be rejected")
	}
	// Invalid: forward reference (var defined by a LATER step).
	if _, err := ParseWorkflow([]byte(`
name: fwd
steps:
  - call: { target: "${later.result}", tool: t }
  - launch: { role: reader, gateway: g:1 }
    as: later
`)); err == nil {
		t.Fatal("forward reference must be rejected")
	}
}
