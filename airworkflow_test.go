package main

import (
	"os"
	"path/filepath"
	"testing"
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
