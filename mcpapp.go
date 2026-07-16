package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/embed"

	"meshmcp/mcp"
	"meshmcp/mcpclient"
	"meshmcp/policy"
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
	if err := fs.Parse(args); err != nil {
		return err
	}

	app := &meshApp{auditPath: *auditPath, cosignDir: *cosignDir, pool: map[string]*mcpclient.Client{}}
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
	mesh      *embed.Client
	auditPath string
	cosignDir string

	mu   sync.Mutex
	pool map[string]*mcpclient.Client
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
func appStr(d string) map[string]any { return map[string]any{"type": "string", "description": d} }
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
