package gateway

import (
	"context"
	"fmt"
	"strings"

	"github.com/xrey167/meshmcp/gateway/channels"
	"github.com/xrey167/meshmcp/harness"
)

// parseSlash splits a leading "/command args" out of text. ok is false for a
// non-command message.
func parseSlash(text string) (cmd, rest string, ok bool) {
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, "/") {
		return "", "", false
	}
	t = strings.TrimPrefix(t, "/")
	if i := strings.IndexAny(t, " \t"); i >= 0 {
		return strings.ToLower(t[:i]), strings.TrimSpace(t[i+1:]), true
	}
	return strings.ToLower(t), "", true
}

// handleCommand maps openclaw's session slash-commands onto harness/control ops.
func (g *Gateway) handleCommand(ctx context.Context, in channels.Inbound, key, cmd, rest string) channels.Reply {
	switch cmd {
	case "status":
		return g.cmdStatus(key)
	case "new", "reset":
		g.mu.Lock()
		delete(g.sessions, key)
		g.mu.Unlock()
		return channels.Reply{Text: "session reset — starting fresh"}
	case "compact":
		return channels.Reply{Text: "context compacted (continuity preserved in air)"}
	case "think":
		return g.cmdThink(key, rest)
	case "verbose":
		g.setVerbose(key, true)
		return channels.Reply{Text: "verbose on"}
	case "trace":
		return channels.Reply{Text: "trace: this session's actions are on the audit chain — replay with `meshmcp audit replay`"}
	case "usage":
		return g.cmdUsage(key)
	case "stop", "cancel":
		return g.cmdStop(ctx, key)
	case "pair":
		g.Pair(in.Channel, in.User)
		return channels.Reply{Text: "channel paired — I can now act on messages here"}
	case "restart":
		g.mu.Lock()
		delete(g.sessions, key)
		g.mu.Unlock()
		return channels.Reply{Text: "restarted"}
	case "activation":
		return channels.Reply{Text: "activation: send a plain message to open a governed run; /help for commands"}
	case "help":
		return channels.Reply{Text: helpText}
	default:
		return channels.Reply{Text: "unknown command /" + cmd + " — try /help"}
	}
}

func (g *Gateway) cmdStatus(key string) channels.Reply {
	g.mu.Lock()
	sess := g.sessions[key]
	g.mu.Unlock()
	if sess == nil || sess.lastRun == "" {
		return channels.Reply{Text: "no run yet in this session"}
	}
	st, err := g.eng.State(sess.lastRun)
	if err != nil {
		return channels.Reply{Text: "run " + string(sess.lastRun) + ": not resident (may have settled)"}
	}
	return channels.Reply{Text: summarize(st)}
}

func (g *Gateway) cmdThink(key, level string) channels.Reply {
	if level == "" {
		level = "high"
	}
	g.mu.Lock()
	sess := g.sessions[key]
	if sess == nil {
		sess = &chSession{}
		g.sessions[key] = sess
	}
	sess.think = level
	g.mu.Unlock()
	return channels.Reply{Text: "effort set to " + level}
}

func (g *Gateway) cmdUsage(key string) channels.Reply {
	b := harness.DefaultBudget()
	return channels.Reply{Text: fmt.Sprintf("budget — tokens %d, loop rounds %d, fan-out %d", b.Tokens, b.LoopRounds, b.FanOut)}
}

func (g *Gateway) cmdStop(ctx context.Context, key string) channels.Reply {
	g.mu.Lock()
	sess := g.sessions[key]
	g.mu.Unlock()
	if sess == nil || sess.lastRun == "" {
		return channels.Reply{Text: "nothing to stop"}
	}
	if err := g.eng.Cancel(ctx, sess.lastRun, "channel /stop"); err != nil {
		return channels.Reply{Text: "stop: " + err.Error()}
	}
	return channels.Reply{Text: "stopped run " + string(sess.lastRun) + " (audited; will not resume)"}
}

func (g *Gateway) setVerbose(key string, on bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	sess := g.sessions[key]
	if sess == nil {
		sess = &chSession{}
		g.sessions[key] = sess
	}
	sess.verbose = on
}

const helpText = `commands: /status /new /reset /compact /think <level> /verbose /trace /usage /stop /pair /restart /activation /help
send a plain message to open a governed run`
