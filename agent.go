package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"meshmcp/mcpclient"
	"meshmcp/session"
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
		return runSteerableAgent(o, target, steps, *count, *interval, *steerPort, steerAllow, logf)
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
func runSteerableAgent(o *meshOptions, target string, steps []agentStep, count int, interval time.Duration, steerPort int, allow []string, logf func(string, ...any)) error {
	o.BlockInbound = false
	client, err := startMesh(o, os.Stderr)
	if err != nil {
		return err
	}
	defer stopMesh(client)

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
	srv := session.NewServer(newSteerFactory(ctx, steer, nil), 2*time.Minute, log.Printf)
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

// runAgentLoop cycles through steps, issuing each call and logging whether it
// was allowed (a result) or blocked/held (a JSON-RPC error from the gateway).
// runAgentLoop cycles through steps, and — when steer is non-nil — also reacts
// to steer instructions arriving between steps: a "task" runs an extra call, a
// "nudge" logs guidance, and a "cancel" stops the agent. A nil steer channel
// disables that select case (a receive on nil blocks forever), so a plain agent
// is unaffected.
func runAgentLoop(ctx context.Context, mc toolCaller, steps []agentStep, count int, interval time.Duration, steer <-chan steerEnvelope, logf func(string, ...any)) error {
	made := 0
	for i := 0; count == 0 || made < count; i++ {
		step := steps[i%len(steps)]
		_, err := mc.CallTool(ctx, step.tool, step.args, false)
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
			if stop := applySteer(ctx, mc, env, logf); stop {
				return nil
			}
		case <-time.After(interval):
		}
	}
	return nil
}

// applySteer handles one steer instruction. It returns true when the agent
// should stop (a "cancel").
func applySteer(ctx context.Context, mc toolCaller, env steerEnvelope, logf func(string, ...any)) (stop bool) {
	switch env.Type {
	case "cancel":
		logf("steer: cancel — stopping")
		return true
	case "nudge":
		logf("steer: nudge %q", env.Text)
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

// blockedReason trims a JSON-RPC error to its human message for the log.
func blockedReason(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 && strings.HasPrefix(msg, "mcp error") {
		return strings.TrimSpace(msg[i+2:])
	}
	return msg
}
