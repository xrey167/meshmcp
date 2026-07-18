package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"text/tabwriter"
	"time"
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
	case "-h", "--help", "help":
		return airUsage()
	default:
		return fmt.Errorf("meshmcp air: unknown subcommand %q (want sessions | steer | launch)", args[0])
	}
}

func airUsage() error {
	fmt.Fprint(os.Stderr, `meshmcp air — drive live work over the mesh

  air sessions <control-ip:port>                         list live sessions on a gateway
  air steer    <control-ip:port> --backend b --session id [--method m] [--param k=v]
                                                          steer a live session
  air launch   --role <role> [--nb-config dir] <gateway-ip:port>
                                                          spawn a new agent identity

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
	if _, ok := roleScripts[*role]; !ok {
		return fmt.Errorf("meshmcp air launch: --role must be one of: %s", roleNames())
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp air launch --role <%s> [--nb-config dir] <gateway-ip:port>", roleNames())
	}
	gateway := fs.Arg(0)

	cfgPath := *nbConfig
	if cfgPath == "" {
		dir, err := os.MkdirTemp("", "air-agent-*")
		if err != nil {
			return fmt.Errorf("air launch: temp identity dir: %w", err)
		}
		cfgPath = filepath.Join(dir, "nb.json")
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("air launch: locate meshmcp binary: %w", err)
	}
	childArgs := []string{"agent", "--role", *role, "--nb-config", cfgPath}
	if *interval != "" {
		childArgs = append(childArgs, "--interval", *interval)
	}
	childArgs = append(childArgs, gateway)

	cmd := exec.Command(exe, childArgs...)
	cmd.Env = os.Environ() // inherits NB_SETUP_KEY / NB_MANAGEMENT_URL
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("air launch: start agent: %w", err)
	}
	fmt.Printf("launched agent role=%s pid=%d identity=%s -> %s\n", *role, cmd.Process.Pid, cfgPath, gateway)
	return nil
}
