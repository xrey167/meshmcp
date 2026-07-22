package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/xrey167/meshmcp/air"
	"github.com/xrey167/meshmcp/mcpclient"
	"github.com/xrey167/meshmcp/policy"
	"github.com/xrey167/meshmcp/session"
)

// multiFlag collects repeatable string flags (e.g. --steer-allow a --steer-allow b).
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error {
	*m = append(*m, s)
	return nil
}

// agentStep is one scripted tool call an agent app makes.
type agentStep struct {
	tool string
	args map[string]any
	note string // what this step is meant to demonstrate
}

// roleScripts maps a demo agent role to the sequence of calls it loops through.
// The sequence is deliberate: an agent holds ONE mesh session, so state that
// accumulates across calls (taint, labels) carries between steps — e.g. the
// fetcher taints itself, then its write is blocked.
var roleScripts = map[string][]agentStep{
	"reader": {
		{tool: "read_file", args: map[string]any{"path": "README.md"}, note: "allowed read"},
		{tool: "list_dir", args: map[string]any{"path": "."}, note: "allowed list"},
		{tool: "write_file", args: map[string]any{"path": "x", "data": "y"}, note: "policy denies writes"},
	},
	"fetcher": {
		{tool: "fetch", args: map[string]any{"url": "https://example.com"}, note: "allowed — taints the session"},
		{tool: "write_file", args: map[string]any{"path": "x", "data": "y"}, note: "blocked: session tainted"},
	},
	"billing": {
		{tool: "charge", args: map[string]any{"amount": 4200, "auth": "Bearer {{secret:stripe_key}}"}, note: "secret injected by the gateway"},
		{tool: "transfer_funds", args: map[string]any{"to": "acct-9", "amount": 500}, note: "held for human co-sign"},
	},
	"analyst": {
		{tool: "read_customer", args: map[string]any{"id": 42}, note: "allowed — tags the session pii"},
		{tool: "post_message", args: map[string]any{"text": "customer 42 …"}, note: "blocked: pii may not egress"},
	},
}

func roleNames() string {
	names := make([]string, 0, len(roleScripts))
	for r := range roleScripts {
		names = append(names, r)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// cmdAgent runs a small MCP client "app" with a fixed role and a persistent
// mesh identity, looping realistic traffic against a backend. Point several of
// them (with distinct --nb-config identities) at a gateway and watch the
// Control Room: each role produces a recognizable pattern of allow / deny /
// co-sign decisions.
func cmdAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	o := meshFlags(fs)
	role := fs.String("role", "", "agent role: "+roleNames())
	interval := fs.Duration("interval", 2*time.Second, "delay between calls")
	count := fs.Int("count", 0, "total calls to make (0 = run until stopped)")
	steerPort := fs.Int("steer-port", 0, "if >0, also listen on this mesh port for steer instructions (Air · Steer, P1)")
	steerAllow := multiFlag{}
	fs.Var(&steerAllow, "steer-allow", "identity permitted to steer this agent (FQDN glob or pubkey:<key>); repeatable; empty = any mesh peer")
	steerAudit := fs.String("steer-audit", "", "JSONL hash-chained audit log recording every delivered steer envelope (with --steer-port)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	steps, ok := roleScripts[*role]
	if !ok {
		return fmt.Errorf("meshmcp agent: --role must be one of: %s", roleNames())
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: meshmcp agent --role <%s> [flags] <peer-ip:port>", roleNames())
	}
	target := fs.Arg(0)

	// Persistent identity: use a per-agent nb-config so the gateway sees a
	// stable WireGuard key for this role (that's how policy distinguishes apps).
	if o.DeviceName == "" {
		o.DeviceName = "agent-" + *role
	}
	logf := func(format string, a ...any) { log.Printf("["+*role+"] "+format, a...) }

	// Steer-enabled agents must also accept inbound mesh connections (the
	// default dialMCP path is outbound-only), so they join the mesh directly.
	if *steerPort > 0 {
		// The steer inbox lets a peer inject tool calls that run under THIS
		// agent's identity (borrowed authority), so it is default-deny like the
		// gateway control endpoint: an empty allow-list is a startup error, not
		// "any mesh peer". Name who may steer with --steer-allow.
		if len(steerAllow) == 0 {
			return fmt.Errorf("meshmcp agent: --steer-port requires at least one --steer-allow identity (the steer inbox runs tool calls under this agent's identity; it is deny-by-default)")
		}
		return runSteerableAgent(o, target, steps, *count, *interval, *steerPort, steerAllow, *steerAudit, logf)
	}

	mc, cleanup, err := dialMCP(o, target)
	if err != nil {
		return err
	}
	defer cleanup()
	return runAgentLoop(context.Background(), mc, steps, *count, *interval, nil, logf)
}

// runSteerableAgent joins the mesh with inbound enabled, dials the backend, and
// runs a steer inbox alongside the scripted loop: instructions arriving on the
// steer port are delivered into the loop's select between steps.
func runSteerableAgent(o *meshOptions, target string, steps []agentStep, count int, interval time.Duration, steerPort int, allow []string, auditPath string, logf func(string, ...any)) error {
	o.BlockInbound = false
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

	// One audit record per delivered steer envelope. A steer runs a tool call
	// under this agent's identity, so it is ALWAYS recorded (to --steer-audit
	// when given, else stderr) — an injected instruction must never be
	// unattributable, regardless of whether a file sink was configured.
	var auditW io.Writer = os.Stderr
	if auditPath != "" {
		f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("open steer audit log %s: %w", auditPath, err)
		}
		defer f.Close()
		auditW = f
	}
	audit := policy.NewAuditLog(auditW, func() string { return time.Now().UTC().Format(time.RFC3339) })

	conn, err := client.Dial(context.Background(), "tcp", target)
	if err != nil {
		return fmt.Errorf("dial %s over mesh: %w", target, err)
	}
	mc := mcpclient.New(conn, func(method string, params json.RawMessage) {
		logf("notify: %s %s", method, string(params))
	})
	if _, err := mc.Initialize(context.Background(), "meshmcp-agent"); err != nil {
		mc.Close()
		return fmt.Errorf("initialize: %w", err)
	}
	defer mc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	steer := make(chan steerEnvelope, 16)
	ln, err := client.ListenTCP(fmt.Sprintf(":%d", steerPort))
	if err != nil {
		return fmt.Errorf("listen on steer port %d: %w", steerPort, err)
	}
	defer ln.Close()
	checker := newACL(allow)
	srv := session.NewServer(newSteerFactory(ctx, steer, audit), 2*time.Minute, log.Printf)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			pubKey, fqdn := peerIdentity(client, c.RemoteAddr())
			if !checker.allows(pubKey, fqdn) {
				logf("steer DENIED from %s (%s)", fqdn, shortKey(pubKey))
				c.Close()
				continue
			}
			go srv.Handle(c, session.Meta{PeerFQDN: fqdn, PeerAddr: c.RemoteAddr().String(), PeerKey: pubKey})
		}
	}()
	logf("steer inbox on mesh port %d", steerPort)

	return runAgentLoop(ctx, mc, steps, count, interval, steer, logf)
}

// toolCaller is the slice of mcpclient.Client the agent loop needs (so the loop
// is unit-testable against an in-process client).
type toolCaller interface {
	CallTool(ctx context.Context, name string, args any, task bool) (json.RawMessage, error)
}

// taskSteerer is the optional slice of mcpclient.Client applySteer uses to
// route a steer addressed to sub-work ("task:<id>") on the agent's backend.
type taskSteerer interface {
	SteerTask(ctx context.Context, taskID string, payload json.RawMessage) (mcpclient.Task, error)
	CancelTask(ctx context.Context, taskID string) (mcpclient.Task, error)
}

// runAgentLoop cycles through steps, issuing each call and logging whether it
// was allowed (a result) or blocked/held (a JSON-RPC error from the gateway).
// When steer is non-nil it also reacts to steer instructions arriving between
// steps: a "task" runs an extra call, a "nudge" updates the guidance the
// following scripted steps carry, and a "cancel" stops the agent. A nil steer
// channel disables that select case (a receive on nil blocks forever), so a
// plain agent is unaffected.
func runAgentLoop(ctx context.Context, mc toolCaller, steps []agentStep, count int, interval time.Duration, steer <-chan steerEnvelope, logf func(string, ...any)) error {
	made := 0
	var guidance string
	for i := 0; count == 0 || made < count; i++ {
		step := steps[i%len(steps)]
		_, err := mc.CallTool(ctx, step.tool, stepArgs(step, guidance), false)
		if err != nil {
			logf("%-16s ✗ %s", step.tool, blockedReason(err))
		} else {
			logf("%-16s ✓ ok", step.tool)
		}
		made++
		if count != 0 && made >= count {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case env := <-steer:
			if stop := applySteer(ctx, mc, env, &guidance, logf); stop {
				return nil
			}
		case <-time.After(interval):
		}
	}
	return nil
}

// stepArgs returns a step's args with the current nudge guidance merged in
// (as a "guidance" argument) — a copy, never a mutation of the shared script.
func stepArgs(step agentStep, guidance string) map[string]any {
	if guidance == "" {
		return step.args
	}
	args := make(map[string]any, len(step.args)+1)
	for k, v := range step.args {
		args[k] = v
	}
	args["guidance"] = guidance
	return args
}

// applySteer handles one steer instruction. It returns true when the agent
// should stop (a "cancel"). A steer carrying a "task:<id>" target is routed to
// that task on the agent's backend (tasks/steer / tasks/cancel) rather than
// applied to the agent loop itself; any other target is refused loudly so a
// mis-addressed steer is never silently acted on.
func applySteer(ctx context.Context, mc toolCaller, env steerEnvelope, guidance *string, logf func(string, ...any)) (stop bool) {
	if env.Target != "" {
		steerTarget(ctx, mc, env, logf)
		return false
	}
	switch env.Type {
	case "cancel":
		logf("steer: cancel — stopping")
		return true
	case "nudge":
		*guidance = env.Text
		if env.Text == "" {
			logf("steer: nudge — guidance cleared")
		} else {
			logf("steer: nudge %q — carried on following steps", env.Text)
		}
	case "task":
		var args any = map[string]any{}
		if len(env.Args) > 0 {
			args = env.Args
		}
		if _, err := mc.CallTool(ctx, env.Tool, args, false); err != nil {
			logf("%-16s ✗ %s (steered)", env.Tool, blockedReason(err))
		} else {
			logf("%-16s ✓ ok (steered)", env.Tool)
		}
	default:
		logf("steer: unknown type %q", env.Type)
	}
	return false
}

// steerTarget forwards a targeted steer to the sub-work it addresses. Only
// "task:<id>" targets are supported; the forwarded call is a governed MCP
// method on the agent's existing backend connection (tasks/cancel or
// tasks/steer), so the gateway firewall still applies.
func steerTarget(ctx context.Context, mc toolCaller, env steerEnvelope, logf func(string, ...any)) {
	tgt, err := env.ParsedTarget()
	if err != nil {
		logf("steer: %v — ignored", err)
		return
	}
	if tgt.Kind != air.TargetTask {
		logf("steer: target %q not supported here — only task:<id> (ignored)", env.Target)
		return
	}
	id := tgt.Value
	ts, ok := mc.(taskSteerer)
	if !ok {
		logf("steer: target %q needs a task-capable client — ignored", env.Target)
		return
	}
	if env.Type == "cancel" {
		if _, err := ts.CancelTask(ctx, id); err != nil {
			logf("steer: cancel task %s ✗ %s", id, blockedReason(err))
		} else {
			logf("steer: cancel task %s ✓", id)
		}
		return
	}
	payload, _ := json.Marshal(env)
	if _, err := ts.SteerTask(ctx, id, payload); err != nil {
		logf("steer: %s task %s ✗ %s", env.Type, id, blockedReason(err))
	} else {
		logf("steer: %s task %s ✓", env.Type, id)
	}
}

// blockedReason trims a JSON-RPC error to its human message for the log.
func blockedReason(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 && strings.HasPrefix(msg, "mcp error") {
		return strings.TrimSpace(msg[i+2:])
	}
	return msg
}
