package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeWF(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wf.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAirWorkflowValid(t *testing.T) {
	wf, err := loadAirWorkflow(writeWF(t, `
name: demo
steps:
  - launch: { role: reader, gateway: 1.2.3.4:9101 }
  - steer:  { control: 1.2.3.4:9600, backend: fs, session: 9f2a, params: { text: hi } }
  - call:   { target: 1.2.3.4:9101, tool: summarize }
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if wf.Name != "demo" || len(wf.Steps) != 3 {
		t.Fatalf("unexpected workflow: %+v", wf)
	}
	wants := []string{"launch reader", "steer fs/9f2a", "call summarize@1.2.3.4:9101"}
	for i, w := range wants {
		if got := wf.Steps[i].kind(); got != w {
			t.Fatalf("step %d kind = %q, want %q", i, got, w)
		}
	}
}

func TestLoadAirWorkflowRejectsBadSteps(t *testing.T) {
	cases := map[string]string{
		"two-actions": `
name: bad
steps:
  - launch: { role: reader, gateway: 1.2.3.4:9101 }
    call:   { target: 1.2.3.4:9101, tool: x }
`,
		"empty-step": "name: bad\nsteps:\n  - {}\n",
		"no-steps":   "name: bad\nsteps: []\n",
		"launch-missing-gateway": `
name: bad
steps:
  - launch: { role: reader }
`,
		"steer-missing-session": `
name: bad
steps:
  - steer: { control: 1.2.3.4:9600, backend: fs }
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadAirWorkflow(writeWF(t, body)); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestLoadAirWorkflowParallel(t *testing.T) {
	wf, err := loadAirWorkflow(writeWF(t, `
name: fan
on_error: continue
steps:
  - parallel:
      - call: { target: 1.2.3.4:9101, tool: a }
      - call: { target: 1.2.3.4:9102, tool: b }
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if wf.OnError != "continue" {
		t.Fatalf("on_error = %q", wf.OnError)
	}
	if got := wf.Steps[0].kind(); got != "parallel (2)" {
		t.Fatalf("kind = %q, want parallel (2)", got)
	}
}

func TestLoadAirWorkflowRejectsNestedParallelAndBadTimeout(t *testing.T) {
	cases := map[string]string{
		"nested-parallel": `
name: bad
steps:
  - parallel:
      - parallel:
          - call: { target: x, tool: y }
`,
		"empty-parallel": "name: bad\nsteps:\n  - parallel: []\n",
		"bad-timeout": `
name: bad
steps:
  - call: { target: 1.2.3.4:9101, tool: a }
    timeout: "not-a-duration"
`,
		"bad-on-error": "name: bad\non_error: maybe\nsteps:\n  - call: { target: x, tool: y }\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadAirWorkflow(writeWF(t, body)); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestExpandVars(t *testing.T) {
	vars := map[string]any{"worker": map[string]any{"identity": "/tmp/nb.json", "pid": 4242}}
	cases := map[string]string{
		"${worker.identity}":               "/tmp/nb.json",
		"pid=${worker.pid}":                "pid=4242",
		"${missing.field} stays":           "${missing.field} stays",
		"no vars here":                     "no vars here",
		"${worker.identity}@${worker.pid}": "/tmp/nb.json@4242",
	}
	for in, want := range cases {
		if got := expand(in, vars); got != want {
			t.Errorf("expand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExpandStepFields(t *testing.T) {
	vars := map[string]any{"w": map[string]any{"identity": "id-9"}}
	st := expandSteer(steerStep{Backend: "fs", Session: "${w.identity}", Params: map[string]any{"note": "for ${w.identity}"}}, vars)
	if st.Session != "id-9" || st.Params["note"] != "for id-9" {
		t.Fatalf("steer not expanded: %+v", st)
	}
	c := expandCall(callStep{Target: "${w.identity}:9101", Tool: "t", Args: map[string]any{"k": "${w.identity}"}}, vars)
	if c.Target != "id-9:9101" || c.Args["k"] != "id-9" {
		t.Fatalf("call not expanded: %+v", c)
	}
}

func TestIsConnError(t *testing.T) {
	if isConnError(nil) {
		t.Fatal("nil is not a conn error")
	}
	if !isConnError(&net.OpError{Op: "dial", Err: errors.New("refused")}) {
		t.Fatal("net.OpError should be a conn error")
	}
	if isConnError(&httpStatusError{status: "403 Forbidden"}) {
		t.Fatal("a 4xx is a peer decision, not retryable")
	}
}

func TestRetryConnStopsOnTerminalError(t *testing.T) {
	calls := 0
	err := retryConn(context.Background(), time.Second, func() error {
		calls++
		return &httpStatusError{status: "404 Not Found"}
	})
	if calls != 1 {
		t.Fatalf("terminal error retried %d times, want 1", calls)
	}
	if err == nil {
		t.Fatal("expected the terminal error back")
	}
}

func TestRetryConnRetriesThenSucceeds(t *testing.T) {
	calls := 0
	err := retryConn(context.Background(), 5*time.Second, func() error {
		calls++
		if calls < 3 {
			return &net.OpError{Op: "dial", Err: errors.New("connection refused")}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}
