package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"github.com/xrey167/meshmcp/session"
)

// cmdProbe joins the mesh, opens a (resumable) session to a target backend,
// and runs a real MCP handshake (initialize, tools/list, tools/call),
// printing each response. It is the in-process end-to-end diagnostic for a
// meshmcp backend — no subprocess, no second binary.
func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	o := meshFlags(fs)
	plain := fs.Bool("plain", false, "use a plain (non-resumable) session")
	full := fs.Bool("full", false, "tour the full capability set (tools, resources, prompts) instead of just echo")
	taskMode := fs.Bool("task", false, "run an async task (slow_count) and stream its progress + result")
	perTimeout := fs.Duration("response-timeout", 90*time.Second, "per-response timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: meshmcp probe [flags] <peer-ip:port>")
	}
	target := fs.Arg(0)

	o.BlockInbound = true
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	// Programmatic local end: we push JSON-RPC requests into reqW (the
	// session reads them as "stdin") and read responses from respR (the
	// session writes backend output as "stdout").
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	local := &pipeLocal{r: reqR, w: respW}

	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(respR)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *plain {
		go runPlainBridge(ctx, client, target, local)
	} else {
		sc := session.NewClient(func(c context.Context) (net.Conn, error) {
			return client.Dial(c, "tcp", target)
		}, log.Printf)
		go func() { _ = sc.Run(ctx, local) }()
	}

	send := func(s string) {
		log.Printf(">> %s", s)
		_, _ = io.WriteString(reqW, s+"\n")
	}
	recv := func(what string) (string, error) {
		select {
		case l, ok := <-lines:
			if !ok {
				return "", fmt.Errorf("session closed before %s response", what)
			}
			log.Printf("<< %s", l)
			return l, nil
		case <-time.After(*perTimeout):
			return "", fmt.Errorf("timed out waiting for %s response", what)
		}
	}

	// step sends one request and pairs its label with the response.
	type result struct{ label, resp string }
	var results []result
	step := func(label, req string) error {
		send(req)
		r, err := recv(label)
		if err != nil {
			return err
		}
		results = append(results, result{label, r})
		return nil
	}

	log.Printf("probing %s (first response waits for mesh join)", target)
	if err := step("initialize", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"meshmcp-probe","version":"0.1"}}}`); err != nil {
		return err
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	if *taskMode {
		// Read the next line, classifying it as a response (has id) or a
		// notification (has method). Waits up to perTimeout.
		readMsg := func() (id, method, raw string, ok bool) {
			select {
			case l, more := <-lines:
				if !more {
					return "", "", "", false
				}
				var m struct {
					ID     json.RawMessage `json:"id"`
					Method string          `json:"method"`
				}
				_ = json.Unmarshal([]byte(l), &m)
				return string(m.ID), m.Method, l, true
			case <-time.After(*perTimeout):
				return "", "", "", false
			}
		}

		log.Printf("probing %s task lifecycle", target)
		send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"slow_count","arguments":{"n":3},"task":true}}`)

		var handle, status, result string
		var taskID string
		progress := 0
		// Read the working handle (id 3).
		for {
			id, _, raw, ok := readMsg()
			if !ok {
				return fmt.Errorf("no task handle")
			}
			if id == "3" {
				handle = raw
				var h struct {
					Result struct {
						Task struct {
							TaskID string `json:"taskId"`
						} `json:"task"`
					} `json:"result"`
				}
				_ = json.Unmarshal([]byte(raw), &h)
				taskID = h.Result.Task.TaskID
				break
			}
		}
		// Stream notifications until the terminal status arrives.
		for {
			_, method, raw, ok := readMsg()
			if !ok {
				return fmt.Errorf("no terminal task status")
			}
			switch method {
			case "notifications/progress":
				progress++
			case "notifications/tasks/status":
				status = raw
			}
			if status != "" {
				break
			}
		}
		// Fetch the result.
		send(fmt.Sprintf(`{"jsonrpc":"2.0","id":4,"method":"tasks/result","params":{"taskId":%q}}`, taskID))
		for {
			id, _, raw, ok := readMsg()
			if !ok {
				return fmt.Errorf("no task result")
			}
			if id == "4" {
				result = raw
				break
			}
		}
		_ = reqW.Close()

		fmt.Println("=== LIVE MCP TASK-OVER-MESH RESULT ===")
		fmt.Println("task handle    :", handle)
		fmt.Printf("progress notifs: %d received\n", progress)
		fmt.Println("status notif   :", status)
		fmt.Println("tasks/result   :", result)
		fmt.Println("=== OK: async task with progress notifications over a", sessionKind(*plain), "mesh session ===")
		return nil
	}

	if err := step("tools/list", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`); err != nil {
		return err
	}

	if *full {
		// Exercise every standard capability: tools, resources, prompts.
		reqs := []struct{ label, req string }{
			{"tools/call add", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add","arguments":{"a":2,"b":40}}}`},
			{"resources/list", `{"jsonrpc":"2.0","id":4,"method":"resources/list"}`},
			{"resources/read", `{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"meshmcp://peer"}}`},
			{"prompts/list", `{"jsonrpc":"2.0","id":6,"method":"prompts/list"}`},
			{"prompts/get", `{"jsonrpc":"2.0","id":7,"method":"prompts/get","params":{"name":"summarize","arguments":{"text":"the mesh carries MCP"}}}`},
		}
		for _, r := range reqs {
			if err := step(r.label, r.req); err != nil {
				return err
			}
		}
	} else {
		if err := step("tools/call echo", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello over the mesh"}}}`); err != nil {
			return err
		}
	}
	_ = reqW.Close()

	fmt.Println("=== LIVE MCP-OVER-MESH RESULT ===")
	for _, r := range results {
		fmt.Printf("%-16s: %s\n", r.label, r.resp)
	}
	fmt.Println("=== OK: real MCP round-trips over a", sessionKind(*plain), "mesh session ===")
	return nil
}

func sessionKind(plain bool) string {
	if plain {
		return "plain"
	}
	return "resumable"
}

// runPlainBridge dials the target once over the mesh and copies bytes both
// ways with no session layer — the non-resumable baseline.
func runPlainBridge(ctx context.Context, client *embed.Client, target string, local io.ReadWriteCloser) {
	conn, err := client.Dial(ctx, "tcp", target)
	if err != nil {
		log.Printf("probe: dial %s: %v", target, err)
		local.Close()
		return
	}
	defer conn.Close()
	go func() { _, _ = io.Copy(conn, local); conn.Close() }()
	_, _ = io.Copy(local, conn)
	local.Close()
}

// pipeLocal adapts a pipe pair to the io.ReadWriteCloser the session expects.
type pipeLocal struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p *pipeLocal) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeLocal) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeLocal) Close() error                { p.r.Close(); return p.w.Close() }
