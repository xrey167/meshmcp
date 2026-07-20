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

	"github.com/netbirdio/netbird/client/embed"
	"gopkg.in/yaml.v3"

	"github.com/xrey167/meshmcp/mcpclient"
)

// airWorkflow is a declarative sequence of Air steps (P4): launch an agent,
// steer a session, or call a tool — run in order over one mesh membership.
type airWorkflow struct {
	Name  string            `yaml:"name"`
	Steps []airWorkflowStep `yaml:"steps"`
}

// airWorkflowStep is one step: exactly one of launch/steer/call must be set.
type airWorkflowStep struct {
	Launch *launchStep `yaml:"launch"`
	Steer  *steerStep  `yaml:"steer"`
	Call   *callStep   `yaml:"call"`
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

func (s airWorkflowStep) kind() string {
	switch {
	case s.Launch != nil:
		return "launch " + s.Launch.Role
	case s.Steer != nil:
		return "steer " + s.Steer.Backend + "/" + s.Steer.Session
	case s.Call != nil:
		return "call " + s.Call.Tool + "@" + s.Call.Target
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
	if n != 1 {
		return fmt.Errorf("step %d: exactly one of launch, steer, call must be set (got %d)", i+1, n)
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
	for i, s := range wf.Steps {
		if err := s.validate(i); err != nil {
			return nil, err
		}
	}
	return &wf, nil
}

// cmdAirWorkflow runs a declarative workflow. --dry-run parses and prints the
// plan without joining the mesh.
func cmdAirWorkflow(args []string) error {
	fs := flag.NewFlagSet("air workflow", flag.ExitOnError)
	o := meshFlags(fs)
	dryRun := fs.Bool("dry-run", false, "parse and validate without joining the mesh or running steps")
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
		for i, s := range wf.Steps {
			fmt.Printf("  step %d: %s\n", i+1, s.kind())
		}
		return nil
	}

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	ctx := context.Background()
	for i, s := range wf.Steps {
		log.Printf("workflow %q step %d/%d: %s", wf.Name, i+1, len(wf.Steps), s.kind())
		if err := runWorkflowStep(ctx, client, s); err != nil {
			return fmt.Errorf("workflow %q step %d (%s): %w", wf.Name, i+1, s.kind(), err)
		}
	}
	log.Printf("workflow %q complete", wf.Name)
	return nil
}

func runWorkflowStep(ctx context.Context, client *embed.Client, s airWorkflowStep) error {
	switch {
	case s.Launch != nil:
		pid, identity, err := spawnAgent(s.Launch.Role, s.Launch.NBConfig, s.Launch.Gateway)
		if err != nil {
			return err
		}
		log.Printf("  launched agent role=%s pid=%d identity=%s", s.Launch.Role, pid, identity)
		return nil
	case s.Steer != nil:
		return workflowSteer(ctx, client, s.Steer)
	case s.Call != nil:
		return workflowCall(ctx, client, s.Call)
	default:
		return errors.New("empty step")
	}
}

// workflowSteer POSTs to a gateway control endpoint over the mesh.
func workflowSteer(ctx context.Context, client *embed.Client, st *steerStep) error {
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return client.Dial(ctx, "tcp", st.Control)
		},
	}}
	method := st.Method
	if method == "" {
		method = "notifications/air/steer"
	}
	body, _ := json.Marshal(map[string]any{"backend": st.Backend, "id": st.Session, "method": method, "params": st.Params})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://air-control/v1/steer", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(out))
	}
	return nil
}

// workflowCall dials a backend over the mesh and calls one tool.
func workflowCall(ctx context.Context, client *embed.Client, c *callStep) error {
	conn, err := client.Dial(ctx, "tcp", c.Target)
	if err != nil {
		return fmt.Errorf("dial %s: %w", c.Target, err)
	}
	uc := mcpclient.New(conn, nil)
	defer uc.Close()
	if _, err := uc.Initialize(ctx, "meshmcp-air-workflow"); err != nil {
		return fmt.Errorf("initialize %s: %w", c.Target, err)
	}
	args := any(c.Args)
	if args == nil {
		args = map[string]any{}
	}
	res, err := uc.CallTool(ctx, c.Tool, args, false)
	if err != nil {
		return fmt.Errorf("call %s: %w", c.Tool, err)
	}
	log.Printf("  call %s -> %s", c.Tool, bytes.TrimSpace(res))
	return nil
}
