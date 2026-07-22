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
	"os/exec"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"github.com/xrey167/meshmcp/session"
)

// cmdAir is the umbrella for Air's live-work verbs: list and steer sessions on
// a gateway's control endpoint, and launch a new agent.
//
//	meshmcp air sessions <control-ip:port>
//	meshmcp air steer    <control-ip:port> --backend b --session id [--param k=v]
//	meshmcp air launch   --role reader [--nb-config dir] <gateway-ip:port>
func cmdAir(args []string) error {
	if len(args) == 0 {
		return airUsage()
	}
	switch args[0] {
	case "sessions":
		return cmdAirSessions(args[1:])
	case "steer":
		return cmdAirSteer(args[1:])
	case "launch":
		return cmdAirLaunch(args[1:])
	case "agent-steer":
		return cmdAirAgentSteer(args[1:])
	case "tasks":
		return cmdAirTasks(args[1:])
	case "task-steer":
		return cmdAirTaskSteer(args[1:])
	case "workflow":
		return cmdAirWorkflow(args[1:])
	case "serve":
		return cmdAirServe(args[1:])
	case "-h", "--help", "help":
		return airUsage()
	default:
		return fmt.Errorf("meshmcp air: unknown subcommand %q (want sessions | steer | launch | agent-steer | tasks | task-steer | workflow | serve)", args[0])
	}
}

func airUsage() error {
	fmt.Fprint(os.Stderr, `meshmcp air — drive live work over the mesh

  air sessions <control-ip:port>                         list live sessions on a gateway
  air steer    <control-ip:port> --backend b --session id [--method m] [--param k=v]
                                                          steer a live session
  air launch   --role <role> [--nb-config dir] <gateway-ip:port>
                                                          spawn a new agent identity
  air agent-steer <agent-ip:port> --type task|nudge|cancel [--tool t --arg k=v | --text s]
                                                          send an instruction to an agent's steer inbox
  air tasks    <backend-ip:port>                         list a backend's async tasks
  air task-steer <backend-ip:port> --task id [--text s | --payload json | --cancel]
                                                          steer (or cancel) one running task
  air workflow [--dry-run] <file.yaml>                   run a declarative launch/steer/call workflow
  air serve    [--port N] [--control ip:port] [--approvals ip:port] [--audit file] [--allow id]
                                                          serve the live Air web page over the mesh

Shared mesh flags apply (see "meshmcp air <sub> -h").
`)
	return nil
}

// airControlHTTP joins the mesh and returns an http.Client that dials the
// gateway's Air control endpoint over the mesh (the URL host is ignored), plus
// a cleanup that leaves the mesh.
func airControlHTTP(o *meshOptions, control string) (*http.Client, func(), error) {
	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return nil, nil, err
	}
	hc := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return client.Dial(ctx, "tcp", control)
			},
		},
	}
	return hc, func() { stopMesh(client) }, nil
}

// cmdAirSessions lists a gateway's live resumable sessions.
func cmdAirSessions(args []string) error {
	fs := flag.NewFlagSet("air sessions", flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "print the raw JSON response instead of a table")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air sessions [flags] <control-ip:port>")
	}
	hc, cleanup, err := airControlHTTP(o, fs.Arg(0))
	if err != nil {
		return err
	}
	defer cleanup()

	resp, err := hc.Get("http://air-control/v1/sessions")
	if err != nil {
		return fmt.Errorf("air sessions: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("air sessions: %s: %s", resp.Status, body)
	}
	if *asJSON {
		fmt.Println(string(bytes.TrimSpace(body)))
		return nil
	}
	var out struct {
		Sessions []AirSession `json:"sessions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("air sessions: bad response: %w", err)
	}
	if len(out.Sessions) == 0 {
		fmt.Fprintln(os.Stderr, "no live sessions")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "BACKEND\tSESSION\tPEER\tAGE")
	for _, s := range out.Sessions {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%ds\n", s.Backend, s.ID, s.Peer, s.AgeSec)
	}
	return tw.Flush()
}

// cmdAirSteer steers one live session via the gateway control endpoint.
func cmdAirSteer(args []string) error {
	fs := flag.NewFlagSet("air steer", flag.ExitOnError)
	o := meshFlags(fs)
	backend := fs.String("backend", "", "backend name the session belongs to (from air sessions)")
	sessionID := fs.String("session", "", "session id to steer")
	method := fs.String("method", "notifications/air/steer", "server->client notification method")
	params := argFlags{}
	fs.Var(&params, "param", "steer param key=value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air steer [flags] <control-ip:port> --backend <b> --session <id>")
	}
	if *backend == "" || *sessionID == "" {
		return errors.New("air steer: --backend and --session are required")
	}
	hc, cleanup, err := airControlHTTP(o, fs.Arg(0))
	if err != nil {
		return err
	}
	defer cleanup()

	reqBody, _ := json.Marshal(map[string]any{
		"backend": *backend, "id": *sessionID, "method": *method, "params": map[string]any(params),
	})
	resp, err := hc.Post("http://air-control/v1/steer", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("air steer: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("air steer: %s: %s", resp.Status, body)
	}
	fmt.Println(string(bytes.TrimSpace(body)))
	return nil
}

// cmdAirLaunch spawns a new agent as a child process with its own mesh
// identity (a fresh --nb-config), reusing the existing `meshmcp agent` command.
func cmdAirLaunch(args []string) error {
	fs := flag.NewFlagSet("air launch", flag.ExitOnError)
	role := fs.String("role", "", "agent role: "+roleNames())
	nbConfig := fs.String("nb-config", "", "identity dir for the launched agent (default: a fresh temp dir)")
	interval := fs.String("interval", "", "delay between the agent's calls (passed through)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp air launch --role <%s> [--nb-config dir] <gateway-ip:port>", roleNames())
	}
	var extra []string
	if *interval != "" {
		extra = append(extra, "--interval", *interval)
	}
	pid, identity, err := spawnAgent(*role, *nbConfig, fs.Arg(0), extra...)
	if err != nil {
		return fmt.Errorf("air launch: %w", err)
	}
	fmt.Printf("launched agent role=%s pid=%d identity=%s -> %s\n", *role, pid, identity, fs.Arg(0))
	return nil
}

// spawnAgent starts `meshmcp agent` as a child process with its own mesh
// identity (a fresh --nb-config when none is given), returning its pid and the
// identity path. Reused by `air launch` and workflow launch steps.
func spawnAgent(role, nbConfig, gateway string, extra ...string) (pid int, identity string, err error) {
	if _, ok := roleScripts[role]; !ok {
		return 0, "", fmt.Errorf("--role must be one of: %s", roleNames())
	}
	if gateway == "" {
		return 0, "", fmt.Errorf("gateway is required")
	}
	identity = nbConfig
	if identity == "" {
		dir, err := os.MkdirTemp("", "air-agent-*")
		if err != nil {
			return 0, "", fmt.Errorf("temp identity dir: %w", err)
		}
		identity = filepath.Join(dir, "nb.json")
	}
	exe, err := os.Executable()
	if err != nil {
		return 0, "", fmt.Errorf("locate meshmcp binary: %w", err)
	}
	childArgs := append([]string{"agent", "--role", role, "--nb-config", identity}, extra...)
	childArgs = append(childArgs, gateway)
	cmd := exec.Command(exe, childArgs...)
	cmd.Env = os.Environ() // inherits NB_SETUP_KEY / NB_MANAGEMENT_URL
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, "", fmt.Errorf("start agent: %w", err)
	}
	return cmd.Process.Pid, identity, nil
}

// cmdAirTasks lists a backend's async MCP tasks (tasks/list) over the mesh —
// the CLI counterpart to the assistant's air_tasks tool.
func cmdAirTasks(args []string) error {
	fs := flag.NewFlagSet("air tasks", flag.ExitOnError)
	o := meshFlags(fs)
	asJSON := fs.Bool("json", false, "print the raw task list as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air tasks [flags] <backend-ip:port>")
	}
	mc, cleanup, err := dialMCP(o, fs.Arg(0))
	if err != nil {
		return err
	}
	defer cleanup()

	tasks, err := mc.ListTasks(context.Background())
	if err != nil {
		return fmt.Errorf("air tasks: %w", err)
	}
	if *asJSON {
		b, err := json.MarshalIndent(map[string]any{"tasks": tasks}, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	if len(tasks) == 0 {
		fmt.Fprintln(os.Stderr, "no tasks")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TASK\tSTATUS\tERROR")
	for _, t := range tasks {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", t.TaskID, t.Status, t.Error)
	}
	return tw.Flush()
}

// cmdAirTaskSteer steers (tasks/steer) or cancels (tasks/cancel) one running
// task on a backend — the CLI counterpart to air_task_steer. Both are governed
// MCP methods: a policy methods: rule can deny either.
func cmdAirTaskSteer(args []string) error {
	fs := flag.NewFlagSet("air task-steer", flag.ExitOnError)
	o := meshFlags(fs)
	taskID := fs.String("task", "", "task id (from air tasks)")
	text := fs.String("text", "", "free-form guidance, sent as {\"text\": ...}")
	payload := fs.String("payload", "", "raw JSON payload (overrides --text)")
	cancel := fs.Bool("cancel", false, "cancel the task instead of steering it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air task-steer [flags] <backend-ip:port> --task <id>")
	}
	if *taskID == "" {
		return errors.New("air task-steer: --task is required")
	}
	var body json.RawMessage
	switch {
	case *cancel:
	case *payload != "":
		if !json.Valid([]byte(*payload)) {
			return fmt.Errorf("air task-steer: --payload is not valid JSON")
		}
		body = json.RawMessage(*payload)
	case *text != "":
		body, _ = json.Marshal(map[string]string{"text": *text})
	default:
		return errors.New("air task-steer: one of --text, --payload, or --cancel is required")
	}
	mc, cleanup, err := dialMCP(o, fs.Arg(0))
	if err != nil {
		return err
	}
	defer cleanup()

	if *cancel {
		t, err := mc.CancelTask(context.Background(), *taskID)
		if err != nil {
			return fmt.Errorf("air task-steer: cancel: %w", err)
		}
		fmt.Printf("cancelled task %s (status %s)\n", t.TaskID, t.Status)
		return nil
	}
	t, err := mc.SteerTask(context.Background(), *taskID, body)
	if err != nil {
		return fmt.Errorf("air task-steer: %w", err)
	}
	fmt.Printf("steered task %s (status %s)\n", t.TaskID, t.Status)
	return nil
}

// cmdAirAgentSteer sends one steer envelope to an agent's steer inbox (P1),
// over the same resumable mesh channel as a drop but framed as newline JSON.
func cmdAirAgentSteer(args []string) error {
	fs := flag.NewFlagSet("air agent-steer", flag.ExitOnError)
	o := meshFlags(fs)
	typ := fs.String("type", "task", "steer type: task | nudge | cancel")
	tool := fs.String("tool", "", "type=task: tool to call")
	text := fs.String("text", "", "type=nudge: guidance text")
	target := fs.String("target", "", "optional sub-work address, e.g. task:9f2a")
	id := fs.String("id", "", "optional caller correlation id (audited)")
	steerArgs := argFlags{}
	fs.Var(&steerArgs, "arg", "type=task: tool arg key=value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp air agent-steer [flags] <agent-ip:port>")
	}
	switch *typ {
	case "task":
		if *tool == "" {
			return errors.New("air agent-steer --type task needs --tool")
		}
	case "nudge", "cancel":
	default:
		return fmt.Errorf("air agent-steer: unknown --type %q (want task | nudge | cancel)", *typ)
	}
	agentAddr := fs.Arg(0)

	env := steerEnvelope{Type: *typ, Tool: *tool, Text: *text, Target: *target, ID: *id}
	if len(steerArgs) > 0 {
		b, _ := json.Marshal(map[string]any(steerArgs))
		env.Args = b
	}

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	if err := sendSteerEnvelope(context.Background(), client, agentAddr, env); err != nil {
		return fmt.Errorf("air agent-steer: %w", err)
	}
	fmt.Printf("steered %s -> %s\n", *typ, agentAddr)
	return nil
}

// sendSteerEnvelope delivers one steer envelope to an agent's steer inbox over
// an existing mesh membership — the same resumable, line-framed channel as a
// push. Shared by `air agent-steer` and the workflow runner's agent_steer step.
func sendSteerEnvelope(ctx context.Context, client *embed.Client, addr string, env steerEnvelope) error {
	line, _ := json.Marshal(env)
	line = append(line, '\n')
	pr, pw := io.Pipe()
	go func() { _, werr := pw.Write(line); pw.CloseWithError(werr) }()
	dial := func(ctx context.Context) (net.Conn, error) { return client.Dial(ctx, "tcp", addr) }
	return session.NewClient(dial, log.Printf).Run(ctx, sendStream{r: pr})
}
