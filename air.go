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
	case "catalog", "discover":
		return cmdAirCatalog(args[1:])
	case "dns":
		return cmdAirDNS(args[1:])
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
		return fmt.Errorf("meshmcp air: unknown subcommand %q (want catalog | dns | sessions | steer | launch | agent-steer | tasks | task-steer | workflow | serve)", args[0])
	}
}

func airUsage() error {
	b := func(s string) string { return bold(s) }
	fmt.Fprintln(os.Stderr, bold("meshmcp air")+dim(" — drive live work over the mesh"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, dim("DISCOVER & DRIVE"))
	fmt.Fprintln(os.Stderr, "  "+b("air catalog")+"     <control-ip:port> | --resolve <domain>  "+dim("what backends can I reach? (ARD)"))
	fmt.Fprintln(os.Stderr, "  "+b("air dns")+"         <domain> --control <mesh-ip:port>  "+dim("print DNS records for domain-name discovery"))
	fmt.Fprintln(os.Stderr, "  "+b("air sessions")+"    <control-ip:port>                 "+dim("list live sessions on a gateway"))
	fmt.Fprintln(os.Stderr, "  "+b("air steer")+"       <control-ip:port> --backend b --session id [--param k=v]")
	fmt.Fprintln(os.Stderr, "  "+b("air tasks")+"       <backend-ip:port>                 "+dim("list a backend's async tasks"))
	fmt.Fprintln(os.Stderr, "  "+b("air task-steer")+"  <backend-ip:port> --task id [--text s | --payload j | --cancel]")
	fmt.Fprintln(os.Stderr, "  "+b("air agent-steer")+" <agent-ip:port>   --type task|nudge|cancel [--tool t --arg k=v | --text s]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, dim("LAUNCH & AUTOMATE"))
	fmt.Fprintln(os.Stderr, "  "+b("air launch")+"      --role <role> [--nb-config dir] <gateway-ip:port>")
	fmt.Fprintln(os.Stderr, "  "+b("air workflow")+"    [--dry-run] <file.yaml>           "+dim("run a declarative launch/steer/call flow"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, dim("SERVE"))
	fmt.Fprintln(os.Stderr, "  "+b("air serve")+"       [--port N] [--control ip:port] [--approvals ip:port] [--audit f] [--allow id]")
	fmt.Fprintln(os.Stderr, "                  "+dim("serve the live, phone-first Air web page over the mesh"))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, dim(`Every action is identity-gated, firewalled, and audited. Add -h to any`))
	fmt.Fprintln(os.Stderr, dim(`subcommand for its flags; shared mesh flags apply throughout.`))
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
		fmt.Fprintln(os.Stderr, dim("no live sessions"))
		return nil
	}
	var rows [][]cell
	for _, s := range out.Sessions {
		rows = append(rows, []cell{
			styled(s.Backend, bold),
			styled(s.ID, cyan),
			plain(s.Peer),
			styled(humanAge(s.AgeSec), dim),
		})
	}
	renderTable(os.Stdout, []string{"backend", "session", "peer", "age"}, rows)
	fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("%d live session(s)", len(rows))))
	return nil
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
	var st struct{ Status, Backend, ID, By string }
	if json.Unmarshal(body, &st) == nil && st.Backend != "" {
		line := okLine("steered %s/%s", st.Backend, st.ID)
		if st.By != "" {
			line += dim(" by " + st.By)
		}
		fmt.Println(line)
	} else {
		fmt.Println(string(bytes.TrimSpace(body)))
	}
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
	fmt.Println(okLine("launched %s agent", *role) + dim(fmt.Sprintf(" · pid %d · %s → %s", pid, identity, fs.Arg(0))))
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
	// Pass only the variables the launched agent needs to join the mesh, not
	// the whole parent environment: an assistant that starts `meshmcp mcp
	// --allow-launch` may hold unrelated secrets in its env that a spawned
	// agent has no business inheriting.
	cmd.Env = agentChildEnv()
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
		fmt.Fprintln(os.Stderr, dim("no tasks"))
		return nil
	}
	var rows [][]cell
	for _, t := range tasks {
		rows = append(rows, []cell{
			styled(t.TaskID, cyan),
			taskStatusCell(t.Status),
			styled(t.Error, dim),
		})
	}
	renderTable(os.Stdout, []string{"task", "status", "error"}, rows)
	fmt.Fprintln(os.Stderr, dim(fmt.Sprintf("%d task(s)", len(rows))))
	return nil
}

// taskStatusCell colours a task status the way the page colours a decision.
func taskStatusCell(status string) cell {
	switch status {
	case "completed":
		return styled(status, green)
	case "failed":
		return styled(status, red)
	case "cancelled":
		return styled(status, amber)
	case "working":
		return styled(status, blue)
	default:
		return plain(status)
	}
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
		fmt.Println(okLine("cancelled task %s", t.TaskID) + dim(" ("+t.Status+")"))
		return nil
	}
	t, err := mc.SteerTask(context.Background(), *taskID, body)
	if err != nil {
		return fmt.Errorf("air task-steer: %w", err)
	}
	fmt.Println(okLine("steered task %s", t.TaskID) + dim(" ("+t.Status+")"))
	return nil
}

// agentChildEnv builds the environment for a launched agent: the mesh
// credentials it needs plus a minimal base (PATH/HOME/temp), not the parent's
// full os.Environ() which may carry unrelated secrets. NB_* covers the netbird
// setup key / management URL the child reads to join.
func agentChildEnv() []string {
	pass := []string{
		"NB_SETUP_KEY", "NB_MANAGEMENT_URL", "NB_CONFIG", "NB_LOG_LEVEL",
		"PATH", "HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP",
		"SystemRoot", "SystemDrive", "windir", "ComSpec", "PATHEXT",
	}
	var env []string
	for _, k := range pass {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
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
	fmt.Println(okLine("%s → %s", *typ, agentAddr))
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
