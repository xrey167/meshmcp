package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"meshmcp/mcp"
	"meshmcp/mcpclient"
	"meshmcp/policy"
	"meshmcp/session"
)

// cmdMCP runs meshmcp itself as an MCP server, so Claude Code or Codex can add
// it as a tool and *operate the mesh*: see the live network, drive backends,
// run governed commands, and handle co-sign approvals — all as MCP tool calls.
// Add it to a client with, e.g.:
//
//	{ "mcpServers": { "meshmcp": {
//	    "command": "meshmcp",
//	    "args": ["mcp", "--audit", "audit.jsonl", "--cosign-store", "cosign"],
//	    "env": { "NB_SETUP_KEY": "<key>" } } } }
func cmdMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	o := meshFlags(fs)
	auditPath := fs.String("audit", "", "audit log to read for the network view / verify")
	cosignDir := fs.String("cosign-store", "", "co-sign store directory (for approvals)")
	control := fs.String("control", "", "gateway Air control endpoint (mesh-ip:port) for air_sessions / air_steer")
	allowLaunch := fs.Bool("allow-launch", false, "allow the air_launch tool to spawn agent processes (opt-in, like the Control Room's --local-shell)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	app := &meshApp{auditPath: *auditPath, cosignDir: *cosignDir, control: *control, allowLaunch: *allowLaunch, pool: map[string]*mcpclient.Client{}}
	// Join the mesh only if credentials are available; the read-only tools
	// (network, pending, verify) work without it.
	if o.SetupKey != "" {
		o.BlockInbound = true
		client, err := startMesh(o, os.Stderr)
		if err != nil {
			return err
		}
		defer stopMesh(client)
		app.mesh = client
	}

	s := mcp.New("meshmcp-control", version)
	app.register(s)
	// stdout is the MCP channel; all logs already go to stderr.
	return s.Serve(context.Background(), os.Stdin, os.Stdout)
}

// meshApp exposes mesh control operations as MCP tools.
type meshApp struct {
	mesh        *embed.Client
	auditPath   string
	cosignDir   string
	control     string // gateway Air control endpoint (mesh-ip:port), for air_sessions/air_steer
	allowLaunch bool   // opt-in: enable the air_launch tool to spawn agent processes

	mu     sync.Mutex
	pool   map[string]*mcpclient.Client
	hcOnce sync.Once
	hc     *http.Client // HTTP client that dials the control endpoint over the mesh
}

// controlClient returns an http.Client whose every request is dialed to the
// configured control endpoint over the mesh, regardless of the URL host.
func (a *meshApp) controlClient() (*http.Client, error) {
	if a.mesh == nil {
		return nil, fmt.Errorf("not joined to the mesh (set NB_SETUP_KEY)")
	}
	if a.control == "" {
		return nil, fmt.Errorf("no --control endpoint configured")
	}
	a.hcOnce.Do(func() {
		a.hc = &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return a.mesh.Dial(ctx, "tcp", a.control)
				},
			},
		}
	})
	return a.hc, nil
}

func (a *meshApp) client(target string) (*mcpclient.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.pool[target]; ok {
		return c, nil
	}
	if a.mesh == nil {
		return nil, fmt.Errorf("not connected to the mesh — start `meshmcp mcp` with NB_SETUP_KEY to drive backends")
	}
	if len(a.pool) >= maxTargets {
		return nil, fmt.Errorf("too many open targets (%d)", maxTargets)
	}
	conn, err := a.mesh.Dial(context.Background(), "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("dial %s over mesh: %w", target, err)
	}
	c := mcpclient.New(conn, nil)
	if _, err := c.Initialize(context.Background(), "meshmcp-mcp"); err != nil {
		c.Close()
		return nil, fmt.Errorf("initialize %s: %w", target, err)
	}
	a.pool[target] = c
	return c, nil
}

func (a *meshApp) drop(target string) {
	a.mu.Lock()
	if c, ok := a.pool[target]; ok {
		c.Close()
		delete(a.pool, target)
	}
	a.mu.Unlock()
}

// --- schema + result helpers ---

func appObj(props map[string]any, req ...string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	m := map[string]any{"type": "object", "properties": props}
	if len(req) > 0 {
		m["required"] = req
	}
	return m
}
func appStr(d string) map[string]any  { return map[string]any{"type": "string", "description": d} }
func appNum(d string) map[string]any  { return map[string]any{"type": "number", "description": d} }
func appBool(d string) map[string]any { return map[string]any{"type": "boolean", "description": d} }
func appAnyObj(d string) map[string]any {
	return map[string]any{"type": "object", "description": d}
}
func appStrArr(d string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": d}
}

func txt(s string) mcp.ToolResult { return mcp.ToolResult{Content: []mcp.Content{mcp.Text(s)}} }
func jsonTxt(v any) mcp.ToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return txt(string(b))
}
func errTxt(format string, a ...any) mcp.ToolResult {
	return mcp.ToolResult{Content: []mcp.Content{mcp.Text(fmt.Sprintf(format, a...))}, IsError: true}
}

// register adds the control tools to s.
func (a *meshApp) register(s *mcp.Server) {
	s.AddTool(mcp.Tool{
		Name:        "network",
		Description: "Show the live mesh: MCP servers, agent identities, recent policy decisions, and whether the audit chain is intact.",
		InputSchema: appObj(nil),
		Handler:     a.toolNetwork,
	})
	s.AddTool(mcp.Tool{
		Name:        "list_tools",
		Description: "List the tools/resources/prompts a mesh backend exposes. target is peer-ip:port.",
		InputSchema: appObj(map[string]any{"target": appStr("backend mesh address, e.g. 100.64.0.2:9101")}, "target"),
		Handler:     a.toolListTools,
	})
	s.AddTool(mcp.Tool{
		Name:        "call_tool",
		Description: "Call a tool on a mesh backend (routed through the gateway's policy + audit). Returns the tool result.",
		InputSchema: appObj(map[string]any{
			"target":    appStr("backend mesh address"),
			"tool":      appStr("tool name"),
			"arguments": appAnyObj("tool arguments object"),
		}, "target", "tool"),
		Handler: a.toolCallTool,
	})
	s.AddTool(mcp.Tool{
		Name:        "run",
		Description: "Run an allow-listed command on a backend via its run_command tool (policy-governed + audited).",
		InputSchema: appObj(map[string]any{
			"target":  appStr("backend mesh address"),
			"command": appStr("command name (must be allow-listed on the backend)"),
			"args":    appStrArr("command arguments"),
		}, "target", "command"),
		Handler: a.toolRun,
	})
	s.AddTool(mcp.Tool{
		Name:        "pending_approvals",
		Description: "List held require_cosign calls awaiting a human decision.",
		InputSchema: appObj(nil),
		Handler:     a.toolPending,
	})
	s.AddTool(mcp.Tool{
		Name:        "approve",
		Description: "Approve a held co-sign call for a peer+tool (writes an identity-attributed grant so the call proceeds).",
		InputSchema: appObj(map[string]any{"peer": appStr("caller mesh identity"), "tool": appStr("tool name")}, "peer", "tool"),
		Handler:     a.toolApprove,
	})
	s.AddTool(mcp.Tool{
		Name:        "deny",
		Description: "Deny (clear) a held co-sign call for a peer+tool without granting it.",
		InputSchema: appObj(map[string]any{"peer": appStr("caller mesh identity"), "tool": appStr("tool name")}, "peer", "tool"),
		Handler:     a.toolDeny,
	})
	s.AddTool(mcp.Tool{
		Name:        "audit_verify",
		Description: "Verify the audit ledger's tamper-evident hash chain (optionally signatures with checkpoints+pubkey).",
		InputSchema: appObj(map[string]any{
			"checkpoints": appStr("optional signed-checkpoint file"),
			"pubkey":      appStr("optional expected signer public key (hex)"),
		}),
		Handler: a.toolVerify,
	})
	s.AddTool(mcp.Tool{
		Name:        "drop_file",
		Description: "AirDrop a local file to a peer's drop receiver over the mesh (resumable, audited). target is peer-ip:port.",
		InputSchema: appObj(map[string]any{
			"target": appStr("drop receiver mesh address, e.g. 100.64.0.5:9110"),
			"path":   appStr("local file path to send"),
		}, "target", "path"),
		Handler: a.toolDropFile,
	})
	s.AddTool(mcp.Tool{
		Name:        "air_sessions",
		Description: "List live resumable sessions across the gateway's backends (Air · Steer). Requires --control. Returns backend, session id, caller, age.",
		InputSchema: appObj(nil),
		Handler:     a.toolAirSessions,
	})
	s.AddTool(mcp.Tool{
		Name:        "air_steer",
		Description: "Steer a live session: deliver a server→client MCP notification to the agent driving it (Air · Steer). Requires --control.",
		InputSchema: appObj(map[string]any{
			"backend": appStr("backend name the session belongs to (from air_sessions)"),
			"id":      appStr("session id (from air_sessions)"),
			"method":  appStr("notification method, e.g. notifications/air/steer"),
			"params":  appAnyObj("notification params object (guidance for the agent)"),
		}, "backend", "id", "method"),
		Handler: a.toolAirSteer,
	})
	s.AddTool(mcp.Tool{
		Name:        "air_tasks",
		Description: "List the running/finished async tasks a mesh backend is tracking (Air · Steer). target is peer-ip:port.",
		InputSchema: appObj(map[string]any{"target": appStr("backend mesh address")}, "target"),
		Handler:     a.toolAirTasks,
	})
	s.AddTool(mcp.Tool{
		Name:        "air_task_steer",
		Description: "Augment a running task in-flight with guidance (tasks/steer) — the non-restart counterpart to cancel. target is peer-ip:port.",
		InputSchema: appObj(map[string]any{
			"target":  appStr("backend mesh address"),
			"task_id": appStr("task id (from air_tasks)"),
			"payload": appAnyObj("guidance payload delivered to the task"),
		}, "target", "task_id"),
		Handler: a.toolAirTaskSteer,
	})
	s.AddTool(mcp.Tool{
		Name:        "air_peers",
		Description: "List reachable mesh identities (the 'who can I drop/steer to' view). Each is a WireGuard key + FQDN.",
		InputSchema: appObj(nil),
		Handler:     a.toolAirPeers,
	})
	s.AddTool(mcp.Tool{
		Name:        "air_push",
		Description: "Push a small text payload (clipboard / a task) to a peer's inbox over the resumable mesh channel. target is peer-ip:port.",
		InputSchema: appObj(map[string]any{
			"target": appStr("peer inbox mesh address, e.g. 100.64.0.5:9110"),
			"text":   appStr("the payload text to push"),
			"name":   appStr("optional name for the payload (default clip.txt)"),
		}, "target", "text"),
		Handler: a.toolAirPush,
	})
	s.AddTool(mcp.Tool{
		Name:        "air_fetch",
		Description: "Fetch a blob by sha256 content hash from a peer's content-addressed store, writing it locally. target is peer-ip:port.",
		InputSchema: appObj(map[string]any{
			"target": appStr("peer mesh address hosting the CAS"),
			"hash":   appStr("sha256 hex hash of the blob"),
			"out":    appStr("optional local path to write to (default: the hash)"),
		}, "target", "hash"),
		Handler: a.toolAirFetch,
	})
	s.AddTool(mcp.Tool{
		Name:        "air_launch",
		Description: "Spawn a new agent (its own mesh identity) against a gateway. Disabled unless the app was started with --allow-launch.",
		InputSchema: appObj(map[string]any{
			"role":    appStr("agent role: reader | fetcher | billing | analyst"),
			"gateway": appStr("gateway backend mesh address the agent drives"),
		}, "role", "gateway"),
		Handler: a.toolAirLaunch,
	})
	s.AddTool(mcp.Tool{
		Name:        "show_retrievals",
		Description: "Show retrieval receipts from the audit log: which documents/triples produced answers (provenance), newest first. Answers 'what did the agent read?'.",
		InputSchema: appObj(map[string]any{"limit": appNum("max receipts to show (default 20)")}),
		Handler:     a.toolShowRetrievals,
	})
	s.AddTool(mcp.Tool{
		Name:        "pubsub_publish",
		Description: "Publish an event to a pub/sub broker topic over the mesh (identity-gated, audited). target is broker-ip:port.",
		InputSchema: appObj(map[string]any{
			"target":     appStr("broker mesh address, e.g. 100.64.0.5:9120"),
			"topic":      appStr("topic to publish to, e.g. alerts.prod"),
			"data":       appStr("event payload (wrapped as a JSON string unless json=true)"),
			"json":       appBool("treat data as raw JSON (default false)"),
			"retain":     appBool("store as the topic's retained last-value (default false)"),
			"retain_ttl": appStr("expire the retained value after this duration, e.g. 5m (implies retain)"),
			"unretain":   appBool("clear the topic's retained last-value (tombstone; overrides retain)"),
			"reply_to":   appStr("request/reply: topic a responder should send the reply to"),
			"corr":       appStr("request/reply: correlation id (echo the request's corr when replying)"),
		}, "target", "topic", "data"),
		Handler: a.toolPubsubPublish,
	})
	s.AddTool(mcp.Tool{
		Name:        "pubsub_stats",
		Description: "Query a running pub/sub broker for a live snapshot (subscriptions, sequence, retained, drops). target is broker-ip:port.",
		InputSchema: appObj(map[string]any{"target": appStr("broker mesh address, e.g. 100.64.0.5:9120")}, "target"),
		Handler:     a.toolPubsubStats,
	})
}

// toolPubsubPublish publishes one event to a broker over the mesh.
func (a *meshApp) toolPubsubPublish(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Target, Topic, Data    string
		JSON, Retain, Unretain bool
		RetainTTL              string `json:"retain_ttl"`
		ReplyTo                string `json:"reply_to"`
		Corr                   string `json:"corr"`
	}
	if err := json.Unmarshal(args, &p); err != nil || p.Target == "" || p.Topic == "" {
		return errTxt("target and topic are required"), nil
	}
	if a.mesh == nil {
		return errTxt("not joined to the mesh (set NB_SETUP_KEY)"), nil
	}
	if p.Unretain && (p.Retain || p.RetainTTL != "") {
		return errTxt("unretain (clear) cannot be combined with retain/retain_ttl (set)"), nil
	}
	ttlSec := 0
	if p.RetainTTL != "" {
		d, err := time.ParseDuration(p.RetainTTL)
		if err != nil || d < 0 {
			return errTxt("retain_ttl is not a valid non-negative duration (e.g. 5m)"), nil
		}
		ttlSec = int(d.Seconds())
	}
	var payload json.RawMessage
	if p.JSON {
		if !json.Valid([]byte(p.Data)) {
			return errTxt("json=true but data is not valid JSON"), nil
		}
		payload = json.RawMessage(p.Data)
	} else {
		enc, _ := json.Marshal(p.Data)
		payload = enc
	}
	hello, _ := json.Marshal(helloFrame{Role: "pub"})
	pf, _ := json.Marshal(pubFrame{
		Topic: p.Topic, Retain: p.Retain || ttlSec > 0, RetainTTLSec: ttlSec,
		RetainDelete: p.Unretain, ReplyTo: p.ReplyTo, Corr: p.Corr, Payload: payload,
	})
	preamble := append(append(hello, '\n'), append(pf, '\n')...)

	var mu sync.Mutex
	var ack ackFrame
	var got bool
	stream := &clientStream{out: preamble, done: make(chan struct{})}
	stream.onLine = func(line []byte) {
		mu.Lock()
		defer mu.Unlock()
		if got {
			return
		}
		got = true
		_ = json.Unmarshal(line, &ack)
		stream.finish()
	}
	dial := func(ctx context.Context) (net.Conn, error) { return a.mesh.Dial(ctx, "tcp", p.Target) }
	_ = session.NewClient(dial, nil).Run(ctx, stream)
	mu.Lock()
	g, r := got, ack
	mu.Unlock()
	if !g {
		return errTxt("no acknowledgment from broker %s", p.Target), nil
	}
	if r.Error != "" {
		return errTxt("broker rejected publish: %s", r.Error), nil
	}
	return txt(fmt.Sprintf("published to %q on %s (seq %d)", p.Topic, p.Target, r.Seq)), nil
}

// toolPubsubStats returns a running broker's snapshot.
func (a *meshApp) toolPubsubStats(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct{ Target string }
	if err := json.Unmarshal(args, &p); err != nil || p.Target == "" {
		return errTxt("target is required"), nil
	}
	if a.mesh == nil {
		return errTxt("not joined to the mesh (set NB_SETUP_KEY)"), nil
	}
	hello, _ := json.Marshal(helloFrame{Role: "stats"})
	var mu sync.Mutex
	var line string
	var got bool
	stream := &clientStream{out: append(hello, '\n'), done: make(chan struct{})}
	stream.onLine = func(b []byte) {
		mu.Lock()
		defer mu.Unlock()
		if got {
			return
		}
		got = true
		line = string(b)
		stream.finish()
	}
	dial := func(ctx context.Context) (net.Conn, error) { return a.mesh.Dial(ctx, "tcp", p.Target) }
	_ = session.NewClient(dial, nil).Run(ctx, stream)
	mu.Lock()
	g, resp := got, line
	mu.Unlock()
	if !g {
		return errTxt("no response from broker %s", p.Target), nil
	}
	return txt(resp), nil
}

// toolDropFile streams a local file to a peer's drop receiver over the mesh.
func (a *meshApp) toolDropFile(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct{ Target, Path string }
	if err := json.Unmarshal(args, &p); err != nil || p.Target == "" || p.Path == "" {
		return errTxt("target and path are required"), nil
	}
	if a.mesh == nil {
		return errTxt("not joined to the mesh (set NB_SETUP_KEY)"), nil
	}
	if _, err := os.Stat(p.Path); err != nil {
		return errTxt("cannot send %s: %v", p.Path, err), nil
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(sendFiles(pw, []string{p.Path})) }()
	dial := func(ctx context.Context) (net.Conn, error) { return a.mesh.Dial(ctx, "tcp", p.Target) }
	if err := session.NewClient(dial, nil).Run(ctx, sendStream{r: pr}); err != nil {
		return errTxt("drop to %s failed: %v", p.Target, err), nil
	}
	return txt(fmt.Sprintf("dropped %s to %s", p.Path, p.Target)), nil
}

// toolAirSessions lists live sessions via the gateway control endpoint.
func (a *meshApp) toolAirSessions(ctx context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
	hc, err := a.controlClient()
	if err != nil {
		return errTxt("%v", err), nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://air-control/v1/sessions", nil)
	resp, err := hc.Do(req)
	if err != nil {
		return errTxt("air_sessions: %v", err), nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return errTxt("air_sessions: %s: %s", resp.Status, string(body)), nil
	}
	return txt(string(body)), nil
}

// toolAirSteer steers a live session via the gateway control endpoint.
func (a *meshApp) toolAirSteer(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Backend string          `json:"backend"`
		ID      string          `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if json.Unmarshal(args, &p) != nil || p.Backend == "" || p.ID == "" || p.Method == "" {
		return errTxt("backend, id and method are required"), nil
	}
	hc, err := a.controlClient()
	if err != nil {
		return errTxt("%v", err), nil
	}
	reqBody, _ := json.Marshal(p)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://air-control/v1/steer", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return errTxt("air_steer: %v", err), nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return errTxt("air_steer: %s: %s", resp.Status, string(body)), nil
	}
	return txt(string(body)), nil
}

// toolAirTasks lists the async tasks a backend is tracking.
func (a *meshApp) toolAirTasks(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct{ Target string }
	_ = json.Unmarshal(args, &p)
	c, err := a.client(p.Target)
	if err != nil {
		return errTxt("%v", err), nil
	}
	tasks, err := c.ListTasks(ctx)
	if err != nil {
		a.drop(p.Target)
		return errTxt("air_tasks: %v", err), nil
	}
	return jsonTxt(map[string]any{"tasks": tasks}), nil
}

// toolAirTaskSteer augments a running task in-flight (tasks/steer).
func (a *meshApp) toolAirTaskSteer(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Target  string          `json:"target"`
		TaskID  string          `json:"task_id"`
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(args, &p) != nil || p.Target == "" || p.TaskID == "" {
		return errTxt("target and task_id are required"), nil
	}
	c, err := a.client(p.Target)
	if err != nil {
		return errTxt("%v", err), nil
	}
	payload := p.Payload
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	t, err := c.SteerTask(ctx, p.TaskID, payload)
	if err != nil {
		a.drop(p.Target)
		return errTxt("air_task_steer: %v", err), nil
	}
	return jsonTxt(t), nil
}

// toolAirPeers lists reachable mesh identities.
func (a *meshApp) toolAirPeers(_ context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
	if a.mesh == nil {
		return errTxt("not joined to the mesh (set NB_SETUP_KEY)"), nil
	}
	st, err := a.mesh.Status()
	if err != nil {
		return errTxt("mesh status: %v", err), nil
	}
	type row struct{ Status, IP, FQDN, PubKey string }
	peers := []row{}
	for _, p := range st.Peers {
		connected := strings.EqualFold(fmt.Sprint(p.ConnStatus), "Connected")
		status := "connected"
		if !connected {
			status = strings.ToLower(fmt.Sprint(p.ConnStatus))
		}
		peers = append(peers, row{
			Status: status,
			IP:     strings.SplitN(p.IP, "/", 2)[0],
			FQDN:   p.FQDN,
			PubKey: shortKey(p.PubKey),
		})
	}
	return jsonTxt(map[string]any{"peers": peers}), nil
}

// toolAirPush pushes a small text payload to a peer's inbox over the mesh.
func (a *meshApp) toolAirPush(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct{ Target, Text, Name string }
	if json.Unmarshal(args, &p) != nil || p.Target == "" || p.Text == "" {
		return errTxt("target and text are required"), nil
	}
	if a.mesh == nil {
		return errTxt("not joined to the mesh (set NB_SETUP_KEY)"), nil
	}
	name := p.Name
	if name == "" {
		name = "clip.txt"
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(sendData(pw, name, []byte(p.Text))) }()
	dial := func(ctx context.Context) (net.Conn, error) { return a.mesh.Dial(ctx, "tcp", p.Target) }
	if err := session.NewClient(dial, nil).Run(ctx, sendStream{r: pr}); err != nil {
		return errTxt("push to %s failed: %v", p.Target, err), nil
	}
	return txt(fmt.Sprintf("pushed %d bytes (%q) to %s", len(p.Text), name, p.Target)), nil
}

// toolAirFetch fetches a blob by content hash from a peer's CAS.
func (a *meshApp) toolAirFetch(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct{ Target, Hash, Out string }
	if json.Unmarshal(args, &p) != nil || p.Target == "" || p.Hash == "" {
		return errTxt("target and hash are required"), nil
	}
	hash := strings.ToLower(p.Hash)
	if len(hash) != 64 || !isHex(hash) {
		return errTxt("%q is not a sha256 hash", p.Hash), nil
	}
	if a.mesh == nil {
		return errTxt("not joined to the mesh (set NB_SETUP_KEY)"), nil
	}
	dest := p.Out
	if dest == "" {
		dest = hash
	}
	conn, err := a.mesh.Dial(ctx, "tcp", p.Target)
	if err != nil {
		return errTxt("dial %s: %v", p.Target, err), nil
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(fetchReq{Hash: hash}); err != nil {
		return errTxt("send request: %v", err), nil
	}
	got, err := fetchBlob(conn, hash, dest)
	if err != nil {
		return errTxt("fetch: %v", err), nil
	}
	return txt(fmt.Sprintf("fetched %s (%d bytes) -> %s", hash, got, dest)), nil
}

// toolAirLaunch spawns a new agent — opt-in, since it starts a process.
func (a *meshApp) toolAirLaunch(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	if !a.allowLaunch {
		return errTxt("air_launch is disabled — start `meshmcp mcp` with --allow-launch to permit spawning agents"), nil
	}
	var p struct{ Role, Gateway string }
	if json.Unmarshal(args, &p) != nil || p.Role == "" || p.Gateway == "" {
		return errTxt("role and gateway are required"), nil
	}
	pid, identity, err := spawnAgent(p.Role, "", p.Gateway)
	if err != nil {
		return errTxt("air_launch: %v", err), nil
	}
	return txt(fmt.Sprintf("launched agent role=%s pid=%d identity=%s -> %s", p.Role, pid, identity, p.Gateway)), nil
}

// toolShowRetrievals surfaces provenance receipts from the audit log.
func (a *meshApp) toolShowRetrievals(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	if a.auditPath == "" {
		return errTxt("no --audit configured"), nil
	}
	var p struct{ Limit int }
	_ = json.Unmarshal(args, &p)
	if p.Limit <= 0 {
		p.Limit = 20
	}
	f, err := os.Open(a.auditPath)
	if err != nil {
		return errTxt("open audit log: %v", err), nil
	}
	defer f.Close()

	var receipts []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var r policy.AuditRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue
		}
		if len(r.Provenance) == 0 {
			continue
		}
		receipts = append(receipts, map[string]any{
			"seq": r.Seq, "time": r.Time, "peer": r.Peer, "tool": r.Tool, "retrieved": r.Provenance,
		})
	}
	// Newest first, capped.
	for i, j := 0, len(receipts)-1; i < j; i, j = i+1, j-1 {
		receipts[i], receipts[j] = receipts[j], receipts[i]
	}
	if len(receipts) > p.Limit {
		receipts = receipts[:p.Limit]
	}
	return jsonTxt(map[string]any{"count": len(receipts), "receipts": receipts}), nil
}

func (a *meshApp) toolNetwork(_ context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
	if a.auditPath == "" {
		return errTxt("no --audit configured"), nil
	}
	f, err := os.Open(a.auditPath)
	if err != nil {
		return errTxt("open audit: %v", err), nil
	}
	defer f.Close()
	sum, err := policy.Analyze(f, 30)
	if err != nil {
		return errTxt("analyze: %v", err), nil
	}
	return jsonTxt(map[string]any{
		"totals":     map[string]int{"calls": sum.Records, "allow": sum.Allowed, "deny": sum.Denied, "cosign": sum.Cosign},
		"chain_ok":   sum.Chain.OK,
		"servers":    sum.BackendStats,
		"identities": sum.Peers,
		"recent":     sum.Recent,
	}), nil
}

func (a *meshApp) toolListTools(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct{ Target string }
	_ = json.Unmarshal(args, &p)
	c, err := a.client(p.Target)
	if err != nil {
		return errTxt("%v", err), nil
	}
	out := map[string]any{}
	tools, err := c.ListTools(ctx)
	if err != nil {
		a.drop(p.Target)
		return errTxt("%v", err), nil
	}
	out["tools"] = tools
	if res, err := c.ListResources(ctx); err == nil {
		out["resources"] = res
	}
	if pr, err := c.ListPrompts(ctx); err == nil {
		out["prompts"] = pr
	}
	return jsonTxt(out), nil
}

func (a *meshApp) toolCallTool(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Target    string          `json:"target"`
		Tool      string          `json:"tool"`
		Arguments json.RawMessage `json:"arguments"`
	}
	_ = json.Unmarshal(args, &p)
	c, err := a.client(p.Target)
	if err != nil {
		return errTxt("%v", err), nil
	}
	var toolArgs any = map[string]any{}
	if len(p.Arguments) > 0 {
		toolArgs = p.Arguments
	}
	res, err := c.CallTool(ctx, p.Tool, toolArgs, false)
	if err != nil {
		a.drop(p.Target)
		return errTxt("call %s: %v", p.Tool, err), nil
	}
	return txt(string(res)), nil
}

func (a *meshApp) toolRun(ctx context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct {
		Target  string   `json:"target"`
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	_ = json.Unmarshal(args, &p)
	c, err := a.client(p.Target)
	if err != nil {
		return errTxt("%v", err), nil
	}
	res, err := c.CallTool(ctx, "run_command", map[string]any{"command": p.Command, "args": p.Args}, false)
	if err != nil {
		a.drop(p.Target)
		return errTxt("run: %v", err), nil
	}
	return txt(string(res)), nil
}

func (a *meshApp) pendingStore() *policy.FilePending {
	if a.cosignDir == "" {
		return nil
	}
	return &policy.FilePending{Dir: a.cosignDir}
}

func (a *meshApp) toolPending(_ context.Context, _ json.RawMessage) (mcp.ToolResult, error) {
	ps := a.pendingStore()
	if ps == nil {
		return errTxt("no --cosign-store configured"), nil
	}
	list, err := ps.List()
	if err != nil {
		return errTxt("%v", err), nil
	}
	if list == nil {
		list = []policy.Pending{}
	}
	return jsonTxt(map[string]any{"pending": list}), nil
}

func (a *meshApp) toolApprove(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct{ Peer, Tool string }
	_ = json.Unmarshal(args, &p)
	if a.cosignDir == "" || p.Peer == "" || p.Tool == "" {
		return errTxt("need --cosign-store and {peer, tool}"), nil
	}
	if err := policy.Grant(a.cosignDir, p.Peer, p.Tool, "mcp-app", time.Now()); err != nil {
		return errTxt("%v", err), nil
	}
	_ = a.pendingStore().Clear(p.Peer, p.Tool)
	return txt(fmt.Sprintf("approved: %s may call %q", p.Peer, p.Tool)), nil
}

func (a *meshApp) toolDeny(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	var p struct{ Peer, Tool string }
	_ = json.Unmarshal(args, &p)
	if a.cosignDir == "" || p.Peer == "" || p.Tool == "" {
		return errTxt("need --cosign-store and {peer, tool}"), nil
	}
	_ = a.pendingStore().Clear(p.Peer, p.Tool)
	return txt(fmt.Sprintf("denied (cleared): %s / %q", p.Peer, p.Tool)), nil
}

func (a *meshApp) toolVerify(_ context.Context, args json.RawMessage) (mcp.ToolResult, error) {
	if a.auditPath == "" {
		return errTxt("no --audit configured"), nil
	}
	var p struct{ Checkpoints, Pubkey string }
	_ = json.Unmarshal(args, &p)
	lf, err := os.Open(a.auditPath)
	if err != nil {
		return errTxt("%v", err), nil
	}
	defer lf.Close()
	if p.Checkpoints != "" {
		cf, err := os.Open(p.Checkpoints)
		if err != nil {
			return errTxt("%v", err), nil
		}
		defer cf.Close()
		res, err := policy.VerifySigned(lf, cf, p.Pubkey)
		if err != nil {
			return errTxt("%v", err), nil
		}
		return jsonTxt(res), nil
	}
	res, err := policy.VerifyChain(lf)
	if err != nil {
		return errTxt("%v", err), nil
	}
	return jsonTxt(res), nil
}
