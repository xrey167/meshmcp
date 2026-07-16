package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

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
	mc, cleanup, err := dialMCP(o, target)
	if err != nil {
		return err
	}
	defer cleanup()

	logf := func(format string, a ...any) { log.Printf("["+*role+"] "+format, a...) }
	return runAgentLoop(context.Background(), mc, steps, *count, *interval, logf)
}

// toolCaller is the slice of mcpclient.Client the agent loop needs (so the loop
// is unit-testable against an in-process client).
type toolCaller interface {
	CallTool(ctx context.Context, name string, args any, task bool) (json.RawMessage, error)
}

// runAgentLoop cycles through steps, issuing each call and logging whether it
// was allowed (a result) or blocked/held (a JSON-RPC error from the gateway).
func runAgentLoop(ctx context.Context, mc toolCaller, steps []agentStep, count int, interval time.Duration, logf func(string, ...any)) error {
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
		case <-time.After(interval):
		}
	}
	return nil
}

// blockedReason trims a JSON-RPC error to its human message for the log.
func blockedReason(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 && strings.HasPrefix(msg, "mcp error") {
		return strings.TrimSpace(msg[i+2:])
	}
	return msg
}
